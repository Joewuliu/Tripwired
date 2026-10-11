// Which link-preview tags a page carries. Kept apart from the code that writes them into the page,
// so it can be tested without a browser.

export interface ShareTags {
  title: string
  description: string
  image: string // a path on this host
  path: string // the page's own path
}

/** The tags as [attribute, name, content]: Open Graph for most previews, and the large-image card. */
export function shareTags(tags: ShareTags, origin: string): ['property' | 'name', string, string][] {
  const image = new URL(tags.image, origin).href
  return [
    ['property', 'og:site_name', 'Phish Finder'],
    ['property', 'og:type', 'article'],
    ['property', 'og:title', tags.title],
    ['property', 'og:description', tags.description],
    ['property', 'og:url', new URL(tags.path, origin).href],
    ['property', 'og:image', image],
    ['property', 'og:image:width', '1200'],
    ['property', 'og:image:height', '630'],
    ['name', 'twitter:card', 'summary_large_image'],
    ['name', 'twitter:title', tags.title],
    ['name', 'twitter:description', tags.description],
    ['name', 'twitter:image', image],
  ]
}
