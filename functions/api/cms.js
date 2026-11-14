/* ============================================================================
 * APP LOGO 图标收藏馆 · 在线 CMS 后端（Cloudflare Pages Functions）
 * 路由：/api/cms
 *
 * 让纯静态站点拥有「登录后在线编辑并保存」的能力，不额外购买数据库：
 *   - 管理员登录 → HttpOnly 签名 Cookie（HMAC-SHA256，密钥由 ADMIN_PASSWORD 派生）
 *   - 保存     → 把整份馆藏拆成 manifest.json / index.html 内嵌快照 / 图标文件
 *               → 用 GitHub Git Data API 一次原子提交到 main
 *               → 纯文字改动在提交信息加 [CI Skip] 跳过 Pages 构建；
 *                 含新图片时才触发一次构建，把文件铺到 CDN（1-2 分钟）
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

/* ---- 访客投稿 ------------------------------------------------------------
 * 投稿存仓库 data/submissions.json（一个 JSON 数组），复用现有 GitHub 链路
 * 读写，不需要 Cloudflare KV/D1 绑定，也不需要改动任何部署配置。
 * 不写入 manifest.json / #site-db，访客端不会加载；内容仅含待公开的产品信息。
 * 每次写入带 [CI Skip]，避免一条投稿触发一次 Pages 构建。 */
const SUB_PATH = 'data/submissions.json';
const SUB_MAX_BODY = 1600000;      /* 单条投稿（含压缩后 logo）请求体上限 */
const SUB_MAX_PENDING = 120;       /* 待审核堆积上限，防匿名刷提交 */
const SUB_MAX_RECORDS = 300;       /* 记录总数上限 */
const SUB_RATE = new Map();        /* 轻量限流：单 IP 每分钟 3 条 */

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

/* 把 DB 里的 dataURL 图片拆成独立文件，并把字段改成站内相对路径 */
function extractImages(p) {
  const files = [], seen = new Set(), mapped = [];
  /* ref 用数组下标定位，前端拿到后把本机 DB 里对应的 dataURL 换成站内相对路径，
     下一批请求就只带「还没上传」的图片，不再反复重传整馆（第 38 轮）。 */
  const push = (path, b64, ref) => {
    if (!seen.has(path)) { files.push({ path, base64: b64, ref }); seen.add(path); }
    else mapped.push(ref);
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
        const suffix = ic.type === 'variant' ? '-' + String(ic.id || '').replace(/[^a-z0-9-]/gi, '').slice(-24) : '';
        const dir = field === 'hdUrl' ? 'icons' : 'thumbs';
        const name = slug + suffix + '.' + d.ext;
        if (!SAFE_NAME.test(name)) throw new Error('图片文件名不合法：' + name);
        const path = dir + '/' + name;
        push(path, d.b64, { ai, ii, field, path });
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
      const path = 'related/' + name;
      push(path, d.b64, { ai, ri, field: 'related', path });
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
          path = 'thumbs/' + name;
          push(path, dd.b64, { ai, field: 'defaultIconUrl', path });
          remember(dd.b64, path);
        } else {
          mapped.push({ ai, field: 'defaultIconUrl', path });
        }
        a.defaultIconUrl = path;
      }
    }
  }
  return { files, mapped };
}

function buildManifest(p) {
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

/* ------------------------------------------------------------ 访客投稿 */

function subStr(v, max) {
  return (typeof v === 'string' ? v.trim() : '').slice(0, max);
}
function subUrl(v) {
  const s = subStr(v, 500);
  if (!s) return '';
  try {
    const u = new URL(s);
    return (u.protocol === 'https:' || u.protocol === 'http:') ? u.toString().slice(0, 500) : '';
  } catch (e) { return ''; }
}
/* 只接受前端 canvas 压缩后的位图 dataURL；拒绝 svg（可含脚本）与任意外链 */
function subLogo(v) {
  const s = typeof v === 'string' ? v : '';
  if (!/^data:image\/(webp|png|jpeg);base64,[A-Za-z0-9+/=]+$/.test(s)) return '';
  return s.length <= 900000 ? s : '';
}
function subRateLimited(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const now = Date.now();
  const hits = (SUB_RATE.get(ip) || []).filter(t => now - t < 60000);
  if (hits.length >= 3) { SUB_RATE.set(ip, hits); return true; }
  hits.push(now); SUB_RATE.set(ip, hits);
  if (SUB_RATE.size > 2000) for (const [k, arr] of SUB_RATE)
    if (!arr.length || now - arr[arr.length - 1] > 60000) SUB_RATE.delete(k);
  return false;
}
async function readSubmissions(env) {
  try {
    const d = JSON.parse(await readRepoFile(SUB_PATH, env));
    return Array.isArray(d) ? d : [];
  } catch (e) { return []; }   /* 首次投稿时文件还不存在 */
}
/* 读 → 改 → 写 整体重试：两个投稿并发时后者会 ref 冲突，重读后合并再写。
   atomicCommit 每次都重新取 main 的 ref，所以重试是安全的。 */
async function mutateSubmissions(env, message, fn) {
  let last = null;
  for (let i = 0; i < 3; i++) {
    const cur = await readSubmissions(env);
    const res = fn(cur);
    if (res && res.error) return { ok: false, error: res.error, list: cur };
    const list = (res && res.list) || (Array.isArray(res) ? res : cur);
    try {
      await atomicCommit([{ path: SUB_PATH, base64: utf8ToB64(JSON.stringify(list)) }],
        env, '[CI Skip] ' + message);
      return { ok: true, list };
    } catch (e) {
      last = e;
      if (!/GitHub (409|422)/.test(String(e && e.message))) throw e;
      await new Promise(r => setTimeout(r, 400 * (i + 1)));
    }
  }
  throw last || new Error('投稿写入冲突，请稍后重试');
}
function subId() {
  try { return crypto.randomUUID(); }
  catch (e) { return 'sub-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10); }
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
  /* 管理员读取投稿列表（匿名不可读） */
  if (action === 'submissions') {
    if (!await authed(request, env)) return json({ error: '登录已失效（401）' }, 401);
    try { return json({ ok: true, submissions: await readSubmissions(env) }); }
    catch (e) { return json({ error: '投稿列表读取失败' }, 500); }
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

  /* 访客投稿：匿名，必须放在 authed() 闸门之前 */
  if (body.action === 'submit') {
    if (text.length > SUB_MAX_BODY) return json({ error: '投稿内容过大，请换一张小一点的 Logo 图片' }, 413);
    if (subStr(body._hp, 50)) return json({ ok: true, id: '' });   /* 蜜罐：机器人填了就假装成功 */
    const kind = body.kind === 'unlisted' ? 'unlisted' : 'listed';
    const rec = {
      id: subId(), kind,
      storeUrl: subUrl(body.storeUrl),
      name: subStr(body.name, 80),
      author: subStr(body.author, 80),
      note: subStr(body.note, 500),
      contact: subStr(body.contact, 120),
      logo: subLogo(body.logo),
      logoHd: subLogo(body.logoHd),
      status: 'pending',
      createdAt: new Date().toISOString(),
      reviewedAt: null,
    };
    if (kind === 'listed' && !rec.storeUrl)
      return json({ error: '请填写有效的应用市场链接（https://…）' }, 400);
    if (kind === 'unlisted' && (!rec.name || !rec.author || !rec.logo))
      return json({ error: '请填写产品名称、作者并上传 Logo 图片' }, 400);
    /* 限流放在字段校验之后：填错被拒的正常用户不应消耗额度 */
    if (subRateLimited(request)) return json({ error: '提交太频繁，请稍后再试' }, 429);
    const key = kind === 'listed' ? rec.storeUrl : (rec.name + '|' + rec.author).toLowerCase();
    let out;
    try {
      out = await mutateSubmissions(env, '访客投稿：' + (rec.name || rec.storeUrl).slice(0, 40), cur => {
        const pending = cur.filter(x => x.status === 'pending');
        if (pending.length >= SUB_MAX_PENDING) return { error: '投稿队列已满，请稍后再试' };
        const dup = pending.some(x => {
          const k = x.kind === 'listed' ? x.storeUrl : ((x.name || '') + '|' + (x.author || '')).toLowerCase();
          return k && k === key;
        });
        if (dup) return { error: '这条投稿已在待审核队列中，请勿重复提交' };
        return [rec, ...cur].slice(0, SUB_MAX_RECORDS);
      });
    } catch (e) { return json({ error: friendlyError(e) }, 500); }
    if (!out.ok) return json({ error: out.error }, 429);
    return json({ ok: true, id: rec.id });
  }

  if (!await authed(request, env)) return json({ error: '登录已失效（401）：请重新打开 https://logoicon.cn/admin 并输入管理员密码。草稿仍在本机，不会丢失。' }, 401);

  /* 管理员审核投稿 */
  if (body.action === 'moderate') {
    const id = subStr(body.id, 80), status = subStr(body.status, 20);
    if (!id || !['approved', 'rejected', 'pending', 'deleted'].includes(status))
      return json({ error: '审核参数不正确' }, 400);
    let out;
    try {
      out = await mutateSubmissions(env, '审核投稿：' + status + ' ' + id.slice(0, 12), cur => {
        const i = cur.findIndex(x => x.id === id);
        if (i < 0) return { error: '找不到这条投稿，可能已被处理' };
        const next = cur.slice();
        if (status === 'deleted') next.splice(i, 1);
        else {
          next[i] = Object.assign({}, next[i], { status, reviewedAt: new Date().toISOString() });
          /* 审核后释放图片与联系信息，既避免 submissions.json 膨胀，
             也降低旧记录被静态托管时泄露投稿者隐私的风险。
             前端「通过并收录」时已把图片写进本机应用草稿。 */
          if (status === 'approved' || status === 'rejected') {
            delete next[i].logo; delete next[i].logoHd;
            delete next[i].contact; delete next[i].note;
          }
        }
        return next;
      });
    } catch (e) { return json({ error: friendlyError(e) }, 500); }
    if (!out.ok) return json({ error: out.error }, 400);
    return json({ ok: true, submissions: out.list });
  }

  if (body.action === 'save') {
    const saveT0 = Date.now();   /* 第 45 轮：把服务端耗时回传，便于区分链路慢 / GitHub 慢 */
    const p = publicPayload(body.db || {});
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
    /* extractImages 同时把 p 里的 dataURL 改写成站内相对路径 */
    const { files: images, mapped } = extractImages(p);
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
        mapped: mapped.filter(r => paths.has(r.path)),
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
    ]);
    /* 纯文字改动跳过构建；含新图片或删除应用时正常构建一次（前面各批都 [CI Skip]） */
    /* 增量模式下前面批次都用 [CI Skip] 提交，最后一批必须触发一次构建，
       否则新图片文件不会出现在 Cloudflare CDN 上（会 404）。 */
    const skippedBuild = remaining === 0 && removals.length === 0 && offset === 0;
    const message = (skippedBuild ? '[CI Skip] ' : '')
      + '站内编辑：' + p.apps.length + ' 个应用 · ' + new Date().toISOString();
    const sha = await atomicCommit(items, env, message);
    const c = cacheObj();
    if (c) { try { await c.delete(cacheKey(url)); } catch (e) { /* ignore */ } }
    return json({ ok: true, sha, files: items.length, generatedAt: p.generatedAt,
      skippedBuild, total: totalForUI,
      refs: images.map(f => f.ref).filter(Boolean), mapped,
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
