/** The logo and wordmark, on a glass plate so they read over the wallpaper. Links home. */
export function Brand() {
  return (
    <a className="brand" href="/" aria-label="Tripwire home">
      <span className="brand-logo" aria-hidden="true" />
      <span className="wordmark">Tripwire</span>
    </a>
  )
}
