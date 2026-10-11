export type Route =
  | { name: 'home' }
  | { name: 'report'; id: string }
  | { name: 'card'; id: string }
  | { name: 'card-gallery' }
  | { name: 'dashboard' }
  | { name: 'not-found' }

/**
 * / is the home page; /r/<id> is a report and /r/<id>/card its compact card; /dashboard is the live
 * view; /card-gallery shows the card's five states. Anything else is not found.
 */
export function parseRoute(pathname: string): Route {
  if (pathname === '/') return { name: 'home' }
  if (pathname === '/dashboard' || pathname === '/dashboard/') return { name: 'dashboard' }
  if (pathname === '/card-gallery' || pathname === '/card-gallery/') return { name: 'card-gallery' }
  const card = /^\/r\/([a-z0-9]{1,32})\/card\/?$/.exec(pathname)
  if (card) return { name: 'card', id: card[1] }
  const report = /^\/r\/([a-z0-9]{1,32})\/?$/.exec(pathname)
  return report ? { name: 'report', id: report[1] } : { name: 'not-found' }
}
