// Link-preview tags for the page being shown. Programs that build previews do not run scripts, so
// the tags they read come from the server (the analyzer's /share/<id> page, which Caddy gives them
// in place of this app). These keep the open page's own tags in step, for a browser's share sheet.

import { shareTags } from './shareTags.ts'
import type { ShareTags } from './shareTags.ts'

function setMeta(key: 'property' | 'name', name: string, content: string): void {
  let tag = document.head.querySelector<HTMLMetaElement>(`meta[${key}="${name}"]`)
  if (!tag) {
    tag = document.createElement('meta')
    tag.setAttribute(key, name)
    document.head.appendChild(tag)
  }
  tag.content = content
}

export function setShareTags(tags: ShareTags): void {
  for (const [key, name, content] of shareTags(tags, window.location.origin)) setMeta(key, name, content)
}
