export type Route = { name: 'home' } | { name: 'report'; id: string } | { name: 'dashboard' } | { name: 'not-found' }

/** / is the home page; /r/<id> is a report; /dashboard is the live view. Anything else is not found. */
export function parseRoute(pathname: string): Route {
  if (pathname === '/') return { name: 'home' }
  if (pathname === '/dashboard' || pathname === '/dashboard/') return { name: 'dashboard' }
  const report = /^\/r\/([a-z0-9]{1,32})\/?$/.exec(pathname)
  return report ? { name: 'report', id: report[1] } : { name: 'not-found' }
}
