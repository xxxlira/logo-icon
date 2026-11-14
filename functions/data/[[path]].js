/* 投稿数据目录：data/submissions.json 只允许 /api/cms 通过 GitHub API 读写，
   绝不能作为静态资源被匿名访客直接 GET（里面可能有投稿者留的联系方式）。
   _routes.json 把 /data/* 指到 Functions，这里对所有方法与路径统一返回 404。 */
export async function onRequest() {
  return new Response('Not Found', {
    status: 404,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}
