/* 内部数据目录不对外暴露：/data/* 下的文件一律不作为静态资源提供，
   防止误放的配置文件或含个人信息的数据被匿名访客直接 GET。
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
