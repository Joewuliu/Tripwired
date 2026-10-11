/** The logo and wordmark, on a glass plate so they read over the wallpaper. Links home. */
export function Brand({ name = 'Phish Finder' }: { name?: string }) {
  return (
    <a className="brand" href="/" aria-label={`${name} home`}>
      <span className="brand-logo" aria-hidden="true" />
      <span className="wordmark">{name}</span>
    </a>
  )
}
