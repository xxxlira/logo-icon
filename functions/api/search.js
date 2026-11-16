/* ============================================================================
 * APP LOGO 图标收藏馆 · 只读检索 API（第 57 轮 · 站外 AI 可查）
 * 路由：GET /api/search
 *
 * 数据源是同一次构建产出的 /icons.json（version = publishId），
 * 因此 REST、llms.txt、页面三者永远同版；不额外读 GitHub、不需要鉴权。
 *
 * 示例：
 *   /api/search?q=黑白配色
 *   /api/search?q=拟人风格&limit=10
 *   /api/search?style=skeuomorphic&monochrome=1
 *   /api/search?q=Cubox
 *   /api/search?category=效率工具&limit=20
 * ========================================================================== */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

function reply(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'public, max-age=300, s-maxage=600',
      'X-Content-Type-Options': 'nosniff',
      ...CORS,
    },
  });
}

function norm(v) {
  return String(v == null ? '' : v).trim().toLowerCase();
}

/* 自然语言短语 → 结构化条件。命中 styleAliases 时把别名从余下文本里剥掉，
   剩余部分仍可作为应用名 / 分类的附加过滤；若剥完为空就只用别名。 */
function resolveNatural(q, aliases) {
  const s = String(q || '').trim();
  if (!s) return null;
  let best = null;
  for (const [alias, targets] of Object.entries(aliases || {})) {
    if (s === alias || (alias.length >= 2 && s.includes(alias))) {
      if (!best || alias.length > best.alias.length) best = { alias, targets };
    }
  }
  if (!best) return null;
  const rest = s.replace(best.alias, '')
    .replace(/的|风格|图标|图片|logo|app|应用|找|一些|配色|设计|参考|给我|看看|里|中|的|有|哪些/gi, '')
    .trim();
  return { ...best, rest: rest.length >= 2 ? rest : '' };
}

function textMatch(icon, needle) {
  const n = norm(needle);
  if (!n) return true;
  const hay = [icon.app, icon.slug, (icon.categories || []).join(' '),
    (icon.styleLabels || []).join(' '), icon.designer, (icon.palette || []).join(' ')]
    .join(' ').toLowerCase();
  return hay.includes(n);
}

export async function onRequest(ctx) {
  const req = ctx.request;
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (req.method !== 'GET') return reply({ error: '仅支持 GET，详见 /openapi.json' }, 405);
  const url = new URL(req.url);
  const p = url.searchParams;
  try {
    const res = await fetch(new URL('/icons.json', url.origin));
    if (!res.ok) throw new Error('索引读取失败 HTTP ' + res.status);
    const idx = await res.json();
    let list = Array.isArray(idx.icons) ? idx.icons : [];

    const q = String(p.get('q') || '').trim();
    const style = String(p.get('style') || '').trim();
    const category = String(p.get('category') || '').trim();
    const mono = String(p.get('monochrome') || '').trim();
    const natural = resolveNatural(q, idx.styleAliases);
    const applied = [];

    if (natural) {
      const wantsMono = (natural.targets || []).includes('@monochrome');
      const styles = (natural.targets || []).filter(x => x !== '@monochrome');
      const before = list;
      if (wantsMono) {
        list = list.filter(i => i.monochrome === true);
        applied.push('monochrome=true');
      }
      if (styles.length) {
        list = list.filter(i => (i.styles || []).some(s => styles.includes(s)));
        applied.push('style in [' + styles.join(',') + ']');
      }
      if (natural.rest) {
        const narrowed = list.filter(i => textMatch(i, natural.rest));
        if (narrowed.length) {
          list = narrowed;
          applied.push('text contains "' + natural.rest + '"');
        }
      }
      applied.unshift('alias "' + natural.alias + '"');
      if (!list.length) list = before.filter(i => wantsMono ? i.monochrome === true : true);
    } else if (q) {
      list = list.filter(i => textMatch(i, q));
      applied.push('text contains "' + q + '"');
    }
    if (style) {
      list = list.filter(i => (i.styles || []).includes(style));
      applied.push('style=' + style);
    }
    if (mono === '1' || mono === 'true') {
      list = list.filter(i => i.monochrome === true);
      applied.push('monochrome=1');
    }
    if (category) {
      const c = norm(category);
      list = list.filter(i => (i.categories || []).some(x => norm(x).includes(c)));
      applied.push('category=' + category);
    }

    const total = list.length;
    const limit = Math.min(100, Math.max(1, parseInt(p.get('limit') || '20', 10) || 20));
    const offset = Math.max(0, parseInt(p.get('offset') || '0', 10) || 0);
    const items = list.slice(offset, offset + limit);
    return reply({
      site: 'logoicon.cn',
      version: idx.version || '',
      total,
      limit, offset,
      query: { q, style, category, monochrome: mono },
      applied,
      hints: {
        styles: (idx.styles || []).map(s => ({ slug: s.slug, name: s.name, zh: s.zh })),
        palettePolicy: idx.palettePolicy || '',
        docs: 'https://logoicon.cn/llms.txt',
        openapi: 'https://logoicon.cn/openapi.json',
      },
      items,
    });
  } catch (e) {
    return reply({ error: '检索服务暂时不可用：' + String(e && e.message || e),
      docs: 'https://logoicon.cn/llms.txt' }, 500);
  }
}
