/* ============================================================================
 * APP LOGO 图标收藏馆 · 在线 CMS 后端（Cloudflare Pages Functions）
 * 路由：/api/cms
 *
 * 让纯静态站点拥有「登录后在线编辑并保存」的能力，不额外购买数据库：
 *   - 管理员登录 → HttpOnly 签名 Cookie（HMAC-SHA256，密钥由 ADMIN_PASSWORD 派生）
 *   - 保存     → 把整份馆藏拆成 manifest.json / index.html 内嵌快照 / 图标文件
 *               → 用 GitHub Git Data API 一次原子提交到 main
 *               → 第 57 轮起每次保存都触发一次 Pages 构建（中间图片批次除外），
 *                 保证线上页面 / 清单 / AI 索引三者永远同版
 *   - 暂存发布 → 前端后台改动只写本机草稿，点「发布到线上」才调用一次保存，
 *               避免每改一处就消耗一次构建额度
 *   - 即时生效 → 前端改从 /api/cms?action=manifest 读 GitHub 上的最新清单，
 *               边缘缓存 15 秒且保存时主动清除，访客刷新即可看到，无需等重建
 *
 * ---- Cloudflare 控制台需要做的两件事（Settings → Environment variables）----
 *   ADMIN_PASSWORD   管理员密码，至少 8 位；不要在前端代码或仓库里出现
 *   GITHUB_TOKEN     Fine-grained PAT，只授权 xxxlira/logo-icon-museum 一个仓库，
 *                   权限 Contents: Read & Write；不要用 classic PAT
 * 两个变量都设置后才会启用在线 CMS；没设置时 /api/cms 返回 cms:false，
 * 前端完全回退到原来的只读静态行为，站点不会受任何影响。
 *
 * ---- 安全边界 ----
 *   - 密码、令牌只在服务端环境变量里，永远不会下发到浏览器
 *   - 写接口校验 Cookie 签名 + 同源 Origin/Referer，Cookie 为 HttpOnly/Secure/SameSite=Strict
 *   - 请求体上限 20 MB；文件名严格白名单 [a-z0-9-] + .webp/.png/.jpg，防路径穿越
 *   - 只写 manifest.json / index.html / icons/* / thumbs/*，不碰仓库其他文件
 *   - 私有字段 activity / suggestions / subscribers 一律不写入公开清单
 *   - security 只有 7 个布尔开关会被白名单过滤后公开，管理员本机状态不外泄
 *   - 不做自动删除旧图片（避免误删）；跑本地 update_site.sh 批量重建时会清理
 *   - 建议另外在 Cloudflare Access 里给 /api/* 加一层访问策略，防密码爆破
 *
 * 任何异常都返回 JSON 而不是抛出，保证即使未配置也不会让站点报错。
 * ========================================================================== */

const REPO = 'xxxlira/logo-icon-museum';
const BRANCH = 'main';
const COOKIE = 'im_cms';
const MAX_BODY = 20 * 1024 * 1024;
/* Cloudflare Workers 免费版每次调用最多 50 个子请求。每写一个图片 blob 就要
   一次 GitHub API，加上读取清单/页面、ref、commit、tree、patch 共约 8 次固定开销，
   因此一次调用最多安全写 30 张图片。图片更多时拆成多次调用，中间批次用
   [CI Skip] 跳过 Pages 构建，最后一批写清单并只触发一次构建。 */
const BATCH_SIZE = 30;
/* 一次「发布到线上」生成唯一 pubId，随每个批次一起提交。
   跨境链路下响应可能在回程丢失，前端重试同一个 pubId：
   - 清单已是本次发布的结果 → 直接返回成功，绝不重复写入、不重复触发构建；
   - 只有图片批已提交 → 重传同名文件是幂等的（内容相同的 blob）。 */
function safePubId(v) {
  const t = String(v == null ? '' : v);
  return /^[A-Za-z0-9_-]{6,80}$/.test(t) ? t : '';
}
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const GH = 'https://api.github.com/repos/' + REPO;
const SNAP_RE = /(<script id="site-db"[^>]*>)[\s\S]*?(<\/script>)/;
const SAFE_NAME = /^[a-z0-9][a-z0-9-]{0,80}\.(webp|png|jpg|jpeg)$/i;

function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extra,
    },
  });
}

function configured(env) {
  return typeof env.ADMIN_PASSWORD === 'string' && env.ADMIN_PASSWORD.length >= 8
      && typeof env.GITHUB_TOKEN === 'string' && env.GITHUB_TOKEN.length > 10;
}

/* ---------------------------------------------------------------- 编码工具 */

function utf8ToB64(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  }
  return btoa(bin);
}

function b64ToUtf8(b64) {
  const bin = atob(String(b64).replace(/\s/g, ''));
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(u);
}

function b64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function mac(payload, env) {
  const k = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode('im-cms|' + env.ADMIN_PASSWORD),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(payload));
  return b64url(new Uint8Array(sig));
}

/* ---------------------------------------------------------------- 会话 */

async function issueCookie(env) {
  const exp = Date.now() + SESSION_MS;
  const body = b64url(new TextEncoder().encode(JSON.stringify({ exp })));
  return COOKIE + '=' + body + '.' + (await mac(body, env))
    + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + Math.round(SESSION_MS / 1000);
}

async function authed(request, env) {
  const raw = (request.headers.get('Cookie') || '');
  const hit = raw.split(';').map(s => s.trim()).find(s => s.startsWith(COOKIE + '='));
  if (!hit) return false;
  const token = hit.slice(COOKIE.length + 1);
  const dot = token.lastIndexOf('.');
  if (dot < 1) return false;
  const body = token.slice(0, dot), sig = token.slice(dot + 1);
  let expected;
  try { expected = await mac(body, env); } catch (e) { return false; }
  // 长度固定，逐字符比较，避免短路带来的时序差
  if (sig.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff) return false;
  try {
    const p = JSON.parse(b64ToUtf8(body.replace(/-/g, '+').replace(/_/g, '/')));
    return !!(p && typeof p.exp === 'number' && p.exp > Date.now());
  } catch (e) { return false; }
}

function sameOrigin(request, url) {
  const o = request.headers.get('Origin') || request.headers.get('Referer') || '';
  if (!o) return false;                       // 同源 fetch 一定会带 Origin/Referer
  try { return new URL(o).host === url.host; } catch (e) { return false; }
}

function logout() {
  return json({ ok: true }, 200, {
    'Set-Cookie': COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
  });
}

/* ---------------------------------------------------------------- GitHub */

const GH_TIMEOUT = 25000;
/* 写操作绝不自动重试（会重复 blob / 重复 commit）；只读失败可重试一次。
   加显式超时，避免 GitHub 挂起时 Worker 一直挂着、前端只能干等到 abort。 */
async function gh(path, env, opt = {}) {
  const headers = {
    'Authorization': 'Bearer ' + env.GITHUB_TOKEN,
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'icon-museum-cms',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (opt.body) headers['Content-Type'] = 'application/json';
  const method = opt.method || 'GET';
  const tries = method === 'GET' ? 2 : 1;
  let last = null;
  for (let i = 0; i < tries; i++) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), GH_TIMEOUT);
    try {
      const r = await fetch('https://api.github.com' + path, {
        method, headers, body: opt.body || undefined, signal: ctl.signal,
      });
      if (!r.ok) {
        const t = (await r.text()).slice(0, 300);
        last = new Error('GitHub ' + r.status + '：' + t);
      } else {
        return await r.json();
      }
    } catch (e) {
      last = e;
    } finally { clearTimeout(timer); }
    /* 明确的 4xx（权限/参数/冲突）重试没有意义，直接抛出；5xx/限流/超时才重试 */
    if (last && /GitHub 4\d\d/.test(String(last.message)) &&
        !/GitHub 403|GitHub 429/.test(String(last.message))) break;
    if (i < tries - 1) await new Promise(r => setTimeout(r, 500 * (i + 1)));
  }
  throw last || new Error('GitHub API 连接超时');
}

async function readRepoFile(path, env) {
  const d = await gh('/repos/' + REPO + '/contents/' + path + '?ref=' + BRANCH, env);
  if (!d || !d.content) throw new Error('读取 ' + path + ' 失败');
  return b64ToUtf8(d.content);
}

/* 边缘缓存：让公开读取不把 GitHub API 额度耗尽；保存时会主动清除 */
function cacheObj() {
  try { return (typeof caches !== 'undefined' && caches.default) ? caches.default : null; }
  catch (e) { return null; }
}
function cacheKey(url) {
  return new Request(new URL('/__cms_manifest__', url.origin).toString());
}
async function cachedManifest(env, url) {
  const c = cacheObj(), k = cacheKey(url);
  if (c) {
    try {
      const hit = await c.match(k);
      if (hit) return { manifest: await hit.json(), cached: true };
    } catch (e) { /* 缓存不可用则直接读源 */ }
  }
  const text = await readRepoFile('manifest.json', env);
  const manifest = JSON.parse(text);
  if (c) {
    try {
      await c.put(k, new Response(JSON.stringify(manifest), {
        headers: { 'Cache-Control': 'public, max-age=15' },
      }));
    } catch (e) { /* 缓存写入失败不影响主流程 */ }
  }
  return { manifest, cached: false };
}

/* ---------------------------------------------------------------- 保存 */

function parseDataURL(v) {
  const m = /^data:([^;,]+)?;base64,([A-Za-z0-9+/=\s]+)$/.exec(String(v));
  if (!m) return null;
  const mime = (m[1] || 'image/webp').toLowerCase();
  const ext = mime.includes('png') ? 'png'
            : (mime.includes('jpeg') || mime.includes('jpg')) ? 'jpg' : 'webp';
  return { ext, b64: m[2].replace(/\s/g, '') };
}

const SEC_DEFAULT = { contextMenu: true, devKeys: true, dragSelect: true,
  consoleBanner: true, devtoolsNotice: true, autoNotice: false, iframeNotice: false };
/* 只公开固定的布尔开关；管理员传什么其它字段都会被丢弃 */
function publicSecurity(src) {
  const s = (src && typeof src === 'object') ? src : {}, o = {};
  for (const k of Object.keys(SEC_DEFAULT)) o[k] = s[k] === undefined ? SEC_DEFAULT[k] : !!s[k];
  return o;
}

function publicPayload(db) {
  const p = Object.assign({}, db, {
    version: 5, generatedAt: new Date().toISOString(),
  });
  ['activity', 'suggestions', 'subscribers', 'colors'].forEach(k => delete p[k]);
  p.security = publicSecurity(db.security);
  if (!Array.isArray(p.apps)) throw new Error('数据格式不正确：缺少 apps');
  if (!Array.isArray(p.designers)) p.designers = [];
  if (!Array.isArray(p.categories)) p.categories = [];
  if (!Array.isArray(p.types)) p.types = [];
  return p;
}

/* 第 65 轮 C · 增量发布合并 -------------------------------------------------
   以线上清单为基线，本机草稿只贡献「新增 + 修改」，线上已有而草稿未触及的
   变体保持不动。这样旧浏览器 / 过期草稿点「发布到线上」不会再把线上刚更新
   的图标回滚成默认图。
   - 应用列表仍以草稿为准（批量删除应用照常生效）
   - 图标按 id 合并：updatedAt（或 date）草稿 >= 线上时用草稿，否则保留线上；
     草稿独有的 id 是新增，线上独有的 id 是别处刚加的变体，必须留下
   - 应用级字段：草稿应用比线上新才整体生效，否则只让上面的图标增量生效
   - kept = 本次被保护的线上变体数，随响应回传，便于核对
   ------------------------------------------------------------------------ */
function mergeIncremental(draft, baseline) {
  const kept0 = { p: draft, kept: 0 };
  if (!baseline || !Array.isArray(baseline.apps) || !Array.isArray(draft.apps)) return kept0;
  const ts = o => {
    const v = Date.parse((o && (o.updatedAt || o.date)) || '');
    return isNaN(v) ? 0 : v;
  };
  const baseBySlug = new Map();
  for (const a of baseline.apps) {
    const s = a && a.app && a.app.slug;
    if (s) baseBySlug.set(s, a);
  }
  let kept = 0;
  const apps = draft.apps.map(d => {
    const slug = d && d.app && d.app.slug;
    const b = slug ? baseBySlug.get(slug) : null;
    if (!b || !Array.isArray(b.icons)) return d;
    const baseIcons = b.icons, draftIcons = Array.isArray(d.icons) ? d.icons : [];
    const byId = new Map();
    for (const ic of baseIcons) if (ic && ic.id) byId.set(ic.id, ic);
    const out = [], used = new Set();
    for (const ic of draftIcons) {
      const id = ic && ic.id, old = id ? byId.get(id) : null;
      if (!old) { out.push(ic); if (id) used.add(id); continue; }
      const pick = ts(ic) > ts(old) ? ic : old;
      if (pick === old) kept++;
      out.push(pick);
      used.add(id);
    }
    /* 线上有、草稿没有的变体：不是被删（图标删除走归档，仍在数组里），
       而是草稿更旧没同步到，原样保留。 */
    for (const ic of baseIcons) if (ic && ic.id && !used.has(ic.id)) out.push(ic);
    return ts(d) >= ts(b) ? { ...d, icons: out } : { ...b, icons: out };
  });
  return { p: Object.assign({}, draft, { apps }), kept };
}

/* 第 59 轮 · 内容短哈希：只采样少量字符做 FNV，避免遍历几十万字符的 base64。
   仅用于「同一路径却装了不同图片」时另起唯一文件名。 */
function shortImageHash(s) {
  const n = s.length;
  const sample = String(n) + '|' + s.slice(0, 48) + '|' +
    s.slice(Math.floor(n / 2), Math.floor(n / 2) + 48) + '|' + s.slice(-48);
  let h = 0x811c9dc5;
  for (let i = 0; i < sample.length; i++) {
    h ^= sample.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(36).padStart(7, '0');
}

/* 把 DB 里的 dataURL 图片拆成独立文件，并把字段改成站内相对路径 */
function extractImages(p) {
  const files = [], seen = new Map(), mapped = [], dupes = [];
  /* 第 59 轮：seen 记录 path → base64。旧版是 Set，同名直接丢弃第二张，
     导致「上传变体图标后显示成第一张」。现在同名不同图必须换名另存。 */
  const push = (path, b64, ref) => {
    const r = Object.assign({}, ref);
    let use = path;
    if (seen.has(use) && seen.get(use) !== b64) {
      const m = use.match(/\.(webp|png|jpe?g)$/i);
      const ext = m ? m[0] : '.webp';
      use = use.slice(0, use.length - ext.length) + '-' + shortImageHash(b64 + use) + ext;
    }
    r.path = use;
    if (!seen.has(use)) { files.push({ path: use, base64: b64, ref: r }); seen.set(use, b64); }
    else mapped.push(r);
    return use;
  };
  for (let ai = 0; ai < p.apps.length; ai++) {
    const a = p.apps[ai];
    /* 本应用内 dataURL 内容 → 已拆出的文件路径，用于复用同一张图 */
    const own = new Map();
    const remember = (b64, path) => { if (!own.has(b64)) own.set(b64, path); };
    const slug = a && a.app && a.app.slug;
    if (!slug || !/^[a-z0-9][a-z0-9-]{0,80}$/.test(slug)) {
      throw new Error('应用 slug 不合法：' + String(slug).slice(0, 60));
    }
    const icons = a.icons || [];
    for (let ii = 0; ii < icons.length; ii++) {
      const ic = icons[ii];
      for (const field of ['url', 'hdUrl']) {
        const v = ic[field];
        if (typeof v !== 'string' || !v.startsWith('data:')) continue;
        const d = parseDataURL(v);
        if (!d) continue;                       // 非图片 dataURL（如内联 SVG）保留原样
        /* 第 59 轮：文件名与 type 无关 —— 首枚非变体保留历史名 <slug>.<ext>，
           其余一律带稳定后缀（图标 id 优先，缺失时用序号），
           两枚 type='default' 也不会再共用同一文件。 */
        const idPart = String(ic.id || '').replace(/[^a-z0-9-]/gi, '').slice(-24);
        const suffix = (ii === 0 && ic.type !== 'variant') ? '' : '-' + (idPart || ('i' + ii));
        const dir = field === 'hdUrl' ? 'icons' : 'thumbs';
        const name = slug + suffix + '.' + d.ext;
        if (!SAFE_NAME.test(name)) throw new Error('图片文件名不合法：' + name);
        const path = push(dir + '/' + name, d.b64, { ai, ii, field });
        remember(d.b64, path);
        ic[field] = path;
      }
    }
    /* 详情页「相关图片」：同样拆成独立文件，避免 dataURL 撑爆 manifest.json */
    const rels = a.app && Array.isArray(a.app.relatedImages) ? a.app.relatedImages : [];
    for (let ri = 0; ri < rels.length; ri++) {
      const r = rels[ri];
      const v = r && r.url;
      if (typeof v !== 'string' || !v.startsWith('data:')) continue;
      const d = parseDataURL(v);
      if (!d) continue;
      const rid = String(r.id || '').replace(/[^a-z0-9-]/gi, '').slice(-24) || 'img';
      const name = slug + '-' + rid + '.' + d.ext;
      if (!SAFE_NAME.test(name)) throw new Error('相关图片文件名不合法：' + name);
      const path = push('related/' + name, d.b64, { ai, ri, field: 'related' });
      remember(d.b64, path);
      r.url = path;
    }
    /* defaultIconUrl 常是图标 url 的同一张 dataURL（旧版本 / App Store 导入），
       过去会整段留在清单与内嵌快照里（60+ 应用约 300KB 冗余），并且每次保存都重传。
       内容相同的直接复用已拆出的文件；内容不同的另存一份，绝不丢图。 */
    const dv = a && a.defaultIconUrl;
    if (typeof dv === 'string' && dv.startsWith('data:image/')) {
      const dd = parseDataURL(dv);
      if (dd) {
        let path = own.get(dd.b64);
        if (!path) {
          const name = slug + '-default.' + dd.ext;
          if (!SAFE_NAME.test(name)) throw new Error('默认图标文件名不合法：' + name);
          path = push('thumbs/' + name, dd.b64, { ai, field: 'defaultIconUrl' });
          remember(dd.b64, path);
        } else {
          mapped.push({ ai, field: 'defaultIconUrl', path });
        }
        a.defaultIconUrl = path;
      }
    }
  }
  /* 第 63 轮：同一次提交里，同一应用的两枚图标若被写入完全相同的字节，
     记一条告警随响应回传，管理员发布后立刻能看到，而不是等访客发现。 */
  const byApp = new Map();
  for (const f of files) {
    const r = f.ref || {};
    if (r.field !== 'url' || typeof r.ii !== 'number') continue;
    if (!byApp.has(r.ai)) byApp.set(r.ai, new Map());
    const seenBytes = byApp.get(r.ai);
    if (seenBytes.has(f.base64)) {
      const app = p.apps[r.ai];
      dupes.push({ slug: (app && app.app && app.app.slug) || '', a: seenBytes.get(f.base64), b: r.ii });
    } else seenBytes.set(f.base64, r.ii);
  }
  return { files, mapped, dupes };
}


/* ---- 第 57 轮 · 数据规范化 / AI 索引 ----------------------------------
 * 与本地 apply_r57_data.py 完全同一套算法，保证 CMS 发布与手工构建结果一致。
 * - 风格表：以飞书「应用清单 / 风格」10 项多选选项为准，顺序与飞书一致；
 *   three-d 合并进 3d；旧链接 ?style=three-d 由前端 applyFilters 兜底。
 * - 配色：按站点 colorFamily() 的色相族分组，每枚图标压到 3-5 色，
 *   减少颜色筛选的误命中（8 色里常混入无关色相族）。
 * - 每次发布同时写 icons.json，索引 version = publishId。
 * ---------------------------------------------------------------------- */
const STYLE_FIX = { flat: '扁平', gradient: '玻璃', line: '线性', text: '文字',
  '3d': '3D/黏土', minimal: '渐变', glass: '拟物', skeuomorphic: '拟人',
  'style-mwa1j4ggya0': '手绘/插画', pixel: '像素' };
const STYLE_MERGE = { 'three-d': '3d', 'hand-drawn': 'style-mwa1j4ggya0',
  'style-mwob8jy4wq2': 'gradient' };
const STYLE_ALIASES = {
  "扁平": ["flat"],
  "玻璃": ["gradient"],
  "玻璃质感": ["gradient"],
  "玻璃风格": ["gradient"],
  "线性": ["line"],
  "线框": ["line"],
  "文字": ["text"],
  "字标": ["text"],
  "3D/黏土": ["3d"],
  "3D": ["3d"],
  "立体": ["3d"],
  "黏土": ["3d"],
  "渐变": ["minimal"],
  "拟物": ["glass"],
  "拟人": ["skeuomorphic"],
  "拟人化": ["skeuomorphic"],
  "卡通角色": ["skeuomorphic"],
  "手绘/插画": ["style-mwa1j4ggya0"],
  "手绘": ["style-mwa1j4ggya0"],
  "插画": ["style-mwa1j4ggya0"],
  "像素": ["pixel"],
  "黑白": ["@monochrome"],
  "单色": ["@monochrome"],
  "无彩色": ["@monochrome"],
  "monochrome": ["@monochrome"],
  "黑白配色": ["@monochrome"]
};
const PALETTE_CAP = 5;

/* 与前端 colorFamily() 逐字一致 */
function colorFamily(hex) {
  const r = parseInt(hex.slice(1, 3), 16), g = parseInt(hex.slice(3, 5), 16), b = parseInt(hex.slice(5, 7), 16);
  const mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn, l = (mx + mn) / 2 / 255;
  if (d < 18) return l < .18 ? 'black' : l < .35 ? 'dark gray' : l < .55 ? 'gray' : l < .8 ? 'light gray' : 'white';
  let h = 0;
  if (mx === r) h = ((g - b) / d) % 6; else if (mx === g) h = (b - r) / d + 2; else h = (r - g) / d + 4;
  h *= 60; if (h < 0) h += 360;
  if (h < 15 || h >= 345) return 'red';
  if (h < 45) return 'orange';
  if (h < 70) return 'yellow';
  if (h < 160) return 'green';
  if (h < 200) return 'teal';
  if (h < 255) return 'blue';
  if (h < 290) return 'purple';
  return 'pink';
}
function palValue(h) {
  return Math.max(parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)) / 255;
}
function compactPalette(pal, cap = PALETTE_CAP) {
  if (!Array.isArray(pal)) return [];
  const uniq = [], seen = new Set();
  for (const c of pal) {
    if (typeof c !== 'string' || !/^#[0-9a-fA-F]{6}$/.test(c)) continue;
    const x = c.toLowerCase();
    if (!seen.has(x)) { seen.add(x); uniq.push(x); }
  }
  if (uniq.length <= cap) return uniq;
  const groups = new Map();
  for (const c of uniq) {
    const f = colorFamily(c);
    if (!groups.has(f)) groups.set(f, []);
    groups.get(f).push(c);
  }
  const order = new Map(uniq.map((c, i) => [c, i]));
  const ranked = [...groups.entries()].sort((a, b) =>
    (b[1].length - a[1].length) || (order.get(a[1][0]) - order.get(b[1][0])));
  let picked;
  if (groups.size > cap) {
    picked = ranked.slice(0, cap).map(e => e[1][0]);
  } else {
    picked = ranked.map(e => e[1][0]);
    for (const [, cs] of ranked) {
      if (picked.length >= cap) break;
      let reps;
      if (cs.length <= 2) reps = cs;
      else { const byV = [...cs].sort((x, y) => palValue(x) - palValue(y)); reps = [byV[0], byV[byV.length - 1]]; }
      for (const c of reps) if (!picked.includes(c) && picked.length < cap) picked.push(c);
    }
  }
  const keep = new Set(picked);
  return uniq.filter(c => keep.has(c));
}
function paletteFeatures(pal) {
  const vals = (pal || []).filter(c => typeof c === 'string' && /^#[0-9a-fA-F]{6}$/.test(c)).map(c => {
    const r = parseInt(c.slice(1, 3), 16) / 255, g = parseInt(c.slice(3, 5), 16) / 255, b = parseInt(c.slice(5, 7), 16) / 255;
    const mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn;
    return { s: mx === 0 ? 0 : d / mx, v: mx };
  });
  if (!vals.length) return { monochrome: false, neutral_ratio: 0, dominant: '' };
  const nr = vals.filter(x => x.s < 0.15).length / vals.length;
  return {
    monochrome: nr >= 0.75 && vals.some(x => x.v > 0.75) && vals.some(x => x.v < 0.30),
    neutral_ratio: Math.round(nr * 100) / 100,
    dominant: (pal && pal[0]) || ''
  };
}
function normalizePayload(p) {
  const styles = Array.isArray(p.styles) ? p.styles
    .filter(s => s && !STYLE_MERGE[s.slug])
    .map(s => {
      const want = STYLE_FIX[s.slug];
      return (want && (s.name !== want || s.zh !== want)) ? { ...s, name: want, zh: want } : s;
    }) : p.styles;
  const apps = (Array.isArray(p.apps) ? p.apps : []).map(a => {
    if (!a || !Array.isArray(a.icons)) return a;
    const icons = a.icons.map(ic => {
      const pal = compactPalette(Array.isArray(ic.palette) ? ic.palette : []);
      const raw = Array.isArray(ic.styles) ? ic.styles : (ic.style ? [ic.style] : []);
      const sl = [...new Set(raw.map(x => STYLE_MERGE[x] || x).filter(x => typeof x === 'string' && x))];
      const style = sl[0] || null;
      return { ...ic, palette: pal, styles: sl, style };
    });
    return { ...a, icons };
  });
  return { ...p, styles, apps };
}
function absUrl(rel) {
  if (!rel) return '';
  if (/^https?:\/\//.test(rel)) return rel;
  return 'https://logoicon.cn/' + String(rel).replace(/^\.\//, '');
}
function buildIconsIndex(p) {
  p = normalizePayload(p);
  const labels = {};
  (p.styles || []).forEach(s => { if (s && s.slug) labels[s.slug] = s.zh || s.name || s.slug; });
  const icons = [];
  for (const a of p.apps || []) {
    const app = a.app || {}, slug = app.slug || '';
    const cats = (app.categories || []).map(c => c && (c.name || c.zh)).filter(Boolean);
    for (const ic of a.icons || []) {
      const pal = ic.palette || [], f = paletteFeatures(pal);
      const sl = (ic.styles || []).filter(x => typeof x === 'string');
      icons.push({
        id: ic.id || '', app: app.name || '', slug,
        url: 'https://logoicon.cn/apps/' + slug,
        thumb: absUrl(ic.url), hd: absUrl(ic.hdUrl),
        categories: cats, styles: sl, styleLabels: sl.map(x => labels[x] || x),
        palette: pal, monochrome: f.monochrome, neutral_ratio: f.neutral_ratio,
        dominant: f.dominant, designer: (ic.designer && ic.designer.name) || '',
        platform: ic.platform || '', date: ic.date || '', updatedAt: ic.updatedAt || a.updatedAt || ''
      });
    }
  }
  return {
    site: 'logoicon.cn', version: p.publishId || '', generatedAt: p.generatedAt || '',
    appCount: (p.apps || []).length, iconCount: icons.length,
    palettePolicy: '3-5 colors per icon, grouped by colorFamily',
    styleAliases: STYLE_ALIASES,
    styles: (p.styles || []).map(s => ({ slug: s.slug, name: s.name, zh: s.zh })),
    icons
  };
}

function buildManifest(p) {
  p = normalizePayload(p);
  const m = {
    generatedAt: p.generatedAt,
    apps: p.apps,
    designers: p.designers,
    categories: p.categories,
  };
  if (p.styles) m.styles = p.styles;
  if (p.types) m.types = p.types;
  if (p.about) m.about = p.about;
  if (p.settings) m.settings = p.settings;
  /* 关键：安全策略必须写进 manifest.json。访客端 loadSiteManifest() 会用清单
     覆盖内嵌快照，若此处漏掉，管理员发布的开关会在刷新后被 publicSecurity(undefined)
     重置为默认值 —— 这正是「后台改了不生效」的根因。 */
  m.security = publicSecurity(p.security);
  if (p.publishId) m.publishId = p.publishId;
  return m;
}

async function buildIndexHTML(p, env) {
  p = normalizePayload(p);
  const html = await readRepoFile('index.html', env);
  if (!SNAP_RE.test(html)) throw new Error('index.html 里找不到 #site-db 快照节点');
  const snapshot = JSON.stringify({
    generatedAt: p.generatedAt, apps: p.apps, designers: p.designers,
    categories: p.categories, styles: p.styles, types: p.types, about: p.about,
    settings: p.settings, security: p.security, version: 5,
    ...(p.publishId ? { publishId: p.publishId } : {}),
  }).replace(/</g, '\\u003c');
  return html.replace(SNAP_RE, (all, open, close) => open + snapshot + close);
}

/* 清单里仍被引用到的站内图片路径（icons / thumbs / related） */
function referencedImagePaths(m) {
  const set = new Set();
  const SITE_IMG = /^(\.\/)?(icons|thumbs|related)\//;
  for (const a of (m && Array.isArray(m.apps) ? m.apps : [])) {
    for (const ic of (a.icons || [])) {
      for (const f of ['url', 'hdUrl']) {
        const v = ic[f];
        if (typeof v === 'string' && SITE_IMG.test(v)) set.add(v.replace(/^\.\//, ''));
      }
    }
    const du = a && a.defaultIconUrl;
    if (typeof du === 'string' && SITE_IMG.test(du)) set.add(du.replace(/^\.\//, ''));
    for (const ri of ((a.app && a.app.relatedImages) || [])) {
      const v = ri && ri.url;
      if (typeof v === 'string' && SITE_IMG.test(v)) set.add(v.replace(/^\.\//, ''));
    }
  }
  return set;
}

/* 批量删除应用后，找出新清单已不再引用、但仓库里还存在的图片文件。
   只做「旧引用 - 新引用」差集，因此不会误删仍被其它应用共用的图片。 */
async function orphanedImagePaths(p, env) {
  let old;
  try { old = JSON.parse(await readRepoFile('manifest.json', env)); }
  catch (e) { return []; }   /* 首次发布 / 旧清单读不到时不做猜测 */
  const before = referencedImagePaths(old), after = referencedImagePaths(p);
  return [...before].filter(x => !after.has(x)).slice(0, 500);
}

/* 用 Git Data API 一次性提交多个文件，避免产生多次无谓的 Pages 构建 */
async function atomicCommit(items, env, message) {
  const ref = await gh('/repos/' + REPO + '/git/ref/heads/' + BRANCH, env);
  const baseSha = ref.object.sha;
  const baseCommit = await gh('/repos/' + REPO + '/git/commits/' + baseSha, env);
  const entries = [];
  // 串行创建 blob，避免并发触发 GitHub 的二级限流
  for (const it of items) {
    /* sha:null 是 GitHub Git Trees API 的删除语义，用于回收已删应用的孤儿图片 */
    if (it.remove) { entries.push({ path: it.path, mode: '100644', type: 'blob', sha: null }); continue; }
    const blob = await gh('/repos/' + REPO + '/git/blobs', env, {
      method: 'POST',
      body: JSON.stringify({ content: it.base64, encoding: 'base64' }),
    });
    entries.push({ path: it.path, mode: '100644', type: 'blob', sha: blob.sha });
  }
  const tree = await gh('/repos/' + REPO + '/git/trees', env, {
    method: 'POST',
    body: JSON.stringify({ base_tree: baseCommit.tree.sha, tree: entries }),
  });
  const commit = await gh('/repos/' + REPO + '/git/commits', env, {
    method: 'POST',
    body: JSON.stringify({ message, tree: tree.sha, parents: [baseSha] }),
  });
  await gh('/repos/' + REPO + '/git/refs/heads/' + BRANCH, env, {
    method: 'PATCH', body: JSON.stringify({ sha: commit.sha }),
  });
  return commit.sha;
}

/* ---------------------------------------------------------------- 路由 */

async function handleGet(ctx) {
  const { request, env } = ctx;
  const url = new URL(request.url);
  const action = url.searchParams.get('action') || 'session';

  if (!configured(env)) return json({ cms: false, reason: '未配置 ADMIN_PASSWORD / GITHUB_TOKEN' });

  if (action === 'session') {
    return json({ cms: true, configured: true, authed: await authed(request, env) });
  }
  if (action === 'manifest') {
    const { manifest, cached } = await cachedManifest(env, url);
    return json(manifest, 200, { 'X-CMS-Cache': cached ? 'hit' : 'miss' });
  }
  /* 断连核对：直接读仓库清单（不走 15s 缓存），只回几十字节 */
  if (action === 'verify') {
    const want = safePubId(url.searchParams.get('pubId'));
    if (!want) return json({ published: false, reason: '缺少 pubId' });
    try {
      const m = JSON.parse(await readRepoFile('manifest.json', env));
      return json({ published: m.publishId === want, generatedAt: m.generatedAt || '',
        apps: Array.isArray(m.apps) ? m.apps.length : 0 });
    } catch (e) { return json({ published: false, reason: '线上清单暂不可读' }); }
  }
  return json({ error: '未知操作' }, 400);
}

async function handlePost(ctx) {
  const { request, env } = ctx;
  const url = new URL(request.url);
  if (!configured(env)) return json({ error: '在线 CMS 尚未配置' }, 503);
  if (!sameOrigin(request, url)) return json({ error: '请求来源不合法（403）：请始终用 https://logoicon.cn/admin 打开后台，不要混用 www、pages.dev 或镜像域名' }, 403);

  const len = Number(request.headers.get('Content-Length') || 0);
  if (len > MAX_BODY) return json({ error: '请求体过大' }, 413);
  const text = await request.text();
  if (text.length > MAX_BODY) return json({ error: '请求体过大' }, 413);
  let body;
  try { body = JSON.parse(text); } catch (e) { return json({ error: 'JSON 解析失败' }, 400); }

  if (body.action === 'login') {
    const pass = String(body.password || '');
    // 固定小延迟，降低在线爆破速度
    await new Promise(r => setTimeout(r, 350));
    if (pass !== env.ADMIN_PASSWORD) return json({ error: '密码不正确' }, 401);
    return json({ ok: true, authed: true }, 200, { 'Set-Cookie': await issueCookie(env) });
  }
  if (body.action === 'logout') return logout();

  if (!await authed(request, env)) return json({ error: '登录已失效（401）：请重新打开 https://logoicon.cn/admin 并输入管理员密码。草稿仍在本机，不会丢失。' }, 401);

  if (body.action === 'save') {
    const saveT0 = Date.now();   /* 第 45 轮：把服务端耗时回传，便于区分链路慢 / GitHub 慢 */
    let p = publicPayload(body.db || {});
    const pubId = safePubId(body.pubId);
    p.publishId = pubId;
    /* 新版前端每批只带「还没上传」的 dataURL，offset 表示已累计上传数量。
       老版前端不带 incremental，仍按原来的 offset 切片逻辑工作，完全兼容。 */
    const incremental = body.incremental === true;
    /* 防止另一台设备 / 过期草稿把整馆数据整包覆盖：
       一次发布若把应用数砍掉一半以上且减少 >= 20 个，直接拒绝。
       正常的分批删除不受影响；确需整批清理可分批进行。 */
    let oldM = null, oldCount = 0;
    try {
      oldM = JSON.parse(await readRepoFile('manifest.json', env));
      oldCount = Array.isArray(oldM.apps) ? oldM.apps.length : 0;
    } catch (e) { /* 读不到旧清单时不做猜测，放行 */ }
    const newCount = Array.isArray(p.apps) ? p.apps.length : 0;
    /* 断连后重试：线上清单已是本次发布的结果，直接返回成功。
       必须放在「旧草稿覆盖」护栏之前，否则重试会被误判并拒绝。 */
    if (pubId && oldM && oldM.publishId === pubId) {
      return json({ ok: true, already: true, sha: '', generatedAt: oldM.generatedAt,
        skippedBuild: true, total: 0, chunks: 0, refs: [], mapped: [],
        serverMs: Date.now() - saveT0 });
    }
    if (oldCount >= 20 && newCount < oldCount * 0.5 && oldCount - newCount >= 20) {
      return json({
        error: '已拦截一次疑似旧草稿覆盖（409）：线上现有 ' + oldCount + ' 个应用，'
             + '本机草稿只有 ' + newCount + ' 个。这是本机草稿过旧，不是网络问题，'
             + '反复点发布只会一直失败。请先把云端最新馆藏同步回本机再发布；'
             + '若确实要批量删除，请分批操作。草稿已保留，没有丢失。'
      }, 409);
    }
    /* 第 65 轮 C：以线上清单为基线做增量合并，草稿只带新增与修改，
       线上较新的变体原样保留，避免旧草稿整包覆盖。 */
    const merge = mergeIncremental(p, oldM);
    p = merge.p;
    /* extractImages 同时把 p 里的 dataURL 改写成站内相对路径 */
    const { files: images, mapped, dupes } = extractImages(p);
    const remaining = images.length;
    const offset = Math.max(0, Number(body.offset) || 0);
    /* 进度条用的总数：增量模式下要加上前面批次已上传的数量 */
    const totalForUI = incremental ? Math.max(remaining + offset, Number(body.total) || 0) : remaining;

    /* 图片超出单次调用预算时，只写这一批图片；前端会带着 next 再发一次请求。
       每个批次是一次独立的 Worker 调用，因此子请求数始终 <= 约 36 次。 */
    const needChunk = remaining > BATCH_SIZE && (incremental || offset < remaining);
    if (needChunk) {
      const slice = incremental ? images.slice(0, BATCH_SIZE) : images.slice(offset, offset + BATCH_SIZE);
      const next = incremental ? offset + slice.length : Math.min(offset + BATCH_SIZE, remaining);
      const sha = await atomicCommit(slice, env,
        '[CI Skip] 站内编辑：上传图片 ' + next + '/' + totalForUI);
      const paths = new Set(slice.map(f => f.path));
      return json({ ok: true, chunk: true, total: totalForUI, written: slice.length, next,
        sha, skippedBuild: true, generatedAt: p.generatedAt,
        refs: slice.map(f => f.ref).filter(Boolean),
        mapped: mapped.filter(r => paths.has(r.path)), dupes,
        serverMs: Date.now() - saveT0 });
    }

    /* 最后一批（或图片不多时的一次性提交）：写清单、页面，并回收孤儿图片。
       旧清单已在护栏阶段读过，这里直接复用，省一次 GitHub 请求。 */
    let orphans = [];
    if (oldM) {
      try {
        const after = referencedImagePaths(p);
        orphans = [...referencedImagePaths(oldM)].filter(x => !after.has(x)).slice(0, 500);
      } catch (e) { /* 差集失败时不做删除，避免误删 */ }
    }
    const removals = orphans.map(path => ({ path, remove: true }));
    /* 图片未超过一批时，图片文件必须在本批一起写入（否则清单里已是相对路径、
       仓库里却没有对应文件，图标会 404）；超过一批时图片由前面的批次写完，
       这里只负责清单、页面与孤儿删除。 */
    const items = (remaining > BATCH_SIZE ? [] : images).concat(removals).concat([
      { path: 'manifest.json', base64: utf8ToB64(JSON.stringify(buildManifest(p))) },
      { path: 'index.html', base64: utf8ToB64(await buildIndexHTML(p, env)) },
      { path: 'icons.json', base64: utf8ToB64(JSON.stringify(buildIconsIndex(p))) },
    ]);
    /* 第 57 轮 R02：纯文字保存不再加 [CI Skip]。
       Cloudflare Pages 会 omit that deployment，导致线上 HTML 落后仓库一次编辑；
       用户已确认接受因此增加的构建次数。中间图片批次仍用 [CI Skip]。 */
    const skippedBuild = false;
    const message = '站内编辑：' + p.apps.length + ' 个应用 · ' + new Date().toISOString();
    const sha = await atomicCommit(items, env, message);
    const c = cacheObj();
    if (c) { try { await c.delete(cacheKey(url)); } catch (e) { /* ignore */ } }
    return json({ ok: true, sha, files: items.length, generatedAt: p.generatedAt,
      skippedBuild, total: totalForUI, protectedIcons: merge.kept || 0,
      refs: images.map(f => f.ref).filter(Boolean), mapped, dupes,
      chunks: remaining > BATCH_SIZE ? Math.ceil(remaining / BATCH_SIZE) : 0,
      serverMs: Date.now() - saveT0 });
  }
  return json({ error: '未知操作' }, 400);
}

/* 把 GitHub / 网络的英文异常翻成管理员能直接照做的中文结论 */
function friendlyError(e) {
  const s = String((e && e.message) || e);
  if (/GitHub 401/.test(s)) return 'GitHub 令牌无效或已过期（401）：请在 Cloudflare → 项目设置 → 环境变量更新 GITHUB_TOKEN（Fine-grained PAT，Contents: Read & Write），保存后重新部署一次。';
  if (/GitHub 403|GitHub 429/.test(s)) return 'GitHub API 限流或权限不足（403/429）：请等 1 分钟再点「重试发布」，并检查 GITHUB_TOKEN 是否过期。';
  if (/GitHub 404/.test(s)) return 'GitHub 仓库或文件读取失败（404）：请确认令牌已授权 xxxlira/logo-icon-museum，且 main 分支存在。';
  if (/GitHub 409|GitHub 422/.test(s)) return 'GitHub 提交冲突（409/422）：可能有另一个发布正在写入，请等 10 秒后点「重试发布」，系统会自动核对，不会重复提交。';
  if (/GitHub 5\d\d/.test(s)) return 'GitHub 服务暂时不可用（5xx）：请稍后点「重试发布」。';
  if (/fetch failed|failed to fetch|networkerror|network error|load failed|ENOTFOUND|EAI_AGAIN/i.test(s)) return '连接 GitHub 失败（跨境链路抖动）：请直接点「重试发布」，系统会自动核对线上是否其实已写入成功。草稿仍保留在本机。';
  if (/abort|timed out|timeout|连接超时/i.test(s)) return '连接 GitHub 超时：跨境链路抖动，请直接点「重试发布」，系统会自动核对线上是否其实已写入成功。';
  return s;
}

export async function onRequest(ctx) {
  try {
    const m = ctx.request.method;
    if (m === 'GET') return await handleGet(ctx);
    if (m === 'POST') return await handlePost(ctx);
    if (m === 'DELETE') return logout();
    return json({ error: '不支持的请求方法' }, 405);
  } catch (e) {
    return json({ error: friendlyError(e) }, 500);
  }
}
