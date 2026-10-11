import assert from 'node:assert/strict'
import { test } from 'node:test'
import { shareTags } from './shareTags.ts'

test('the preview tags name the product, the verdict, and the picture as a full address', () => {
  const tags = shareTags(
    { title: 'Phish Finder: Dangerous', description: 'It looks like a scam.', image: '/og/5a3c0de1f2b4.png', path: '/r/5a3c0de1f2b4' },
    'https://phish.example',
  )
  const get = (name: string) => tags.find(([, key]) => key === name)?.[2]
  assert.equal(get('og:title'), 'Phish Finder: Dangerous')
  assert.equal(get('og:image'), 'https://phish.example/og/5a3c0de1f2b4.png')
  assert.equal(get('og:url'), 'https://phish.example/r/5a3c0de1f2b4')
  assert.equal(get('og:image:width'), '1200')
  assert.equal(get('og:image:height'), '630')
  assert.equal(get('twitter:card'), 'summary_large_image')
  assert.equal(get('og:site_name'), 'Phish Finder')
})
