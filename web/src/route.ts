export type Route = { name: 'home' } | { name: 'report'; id: string } | { name: 'not-found' }

/** / is the home page; /r/<id> is a report. Anything else is not found. */
export function parseRoute(pathname: string): Route {
  if (pathname === '/') return { name: 'home' }
  const report = /^\/r\/([a-z0-9]{1,32})\/?$/.exec(pathname)
  return report ? { name: 'report', id: report[1] } : { name: 'not-found' }
}
