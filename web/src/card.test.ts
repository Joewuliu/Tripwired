import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { ACTION, BADGE, CARD_STATES, MAX_LINK_CHARS, cardFor, scanningCard, truncateMiddle } from './card.ts'
import type { CardModel } from './card.ts'
import { SAMPLE_REPORTS } from './sample/cards.ts'

const cards: CardModel[] = [scanningCard('5a3c0de1f2b4'), ...Object.values(SAMPLE_REPORTS).map((report) => cardFor(report))]
const everyWord = (card: CardModel) => [card.badge, card.headline, ...card.reasons, card.link ?? '', card.action].join(' ')

test('there are five states, each with a badge in words and a line of what to do', () => {
  assert.deepEqual([...CARD_STATES].sort(), cards.map((c) => c.state).sort())
  for (const state of CARD_STATES) {
    assert.ok(BADGE[state].length > 0 && ACTION[state].length > 0, state)
  }
  assert.equal(BADGE.no_red_flags, 'No red flags found')
  assert.equal(BADGE.scanning, 'Checking…')
})

test('the action lines are the agreed ones', () => {
  assert.equal(ACTION.dangerous, "Don't tap it or enter anything.")
  assert.equal(ACTION.suspicious, "Don't type anything in; check with the sender another way.")
  assert.equal(ACTION.no_red_flags, "Still go to the company's own website yourself.")
  assert.equal(ACTION.couldnt_check, "Don't type anything until you've checked another way.")
})

test('no state says "safe", in any of its words', () => {
  for (const card of cards) assert.doesNotMatch(everyWord(card), /\bsafe(ly|r|st|ty)?\b/i, card.state)
})

test('no card carries a live link: the address is defanged text, or absent', () => {
  for (const card of cards) assert.doesNotMatch(everyWord(card), /https?:\/\//i, card.state)
  const live = cardFor({ ...SAMPLE_REPORTS.dangerous, url_defanged: 'https://evil.example/login' })
  assert.equal(live.link, null) // an address that is not defanged is not shown at all
})

test('the whole card opens the full report, and nothing else', () => {
  assert.equal(cardFor(SAMPLE_REPORTS.dangerous).href, '/r/5a3c0de1f2b4')
  assert.equal(cardFor(SAMPLE_REPORTS.dangerous, 'sample').href, '/r/sample')
  assert.equal(scanningCard('5a3c0de1f2b4').href, '/r/5a3c0de1f2b4')
})

test('the badge says the verdict, so the headline does not repeat the verdict word', () => {
  const card = cardFor(SAMPLE_REPORTS.dangerous)
  assert.equal(card.badge, 'Dangerous')
  assert.equal(card.headline, "The web address uses the name E-ZPass, but it isn't their real website.")
  assert.ok(!card.reasons.includes(card.headline), 'and its reason is not said twice')
})

test('at most three reasons, most important first', () => {
  const card = cardFor(SAMPLE_REPORTS.dangerous)
  assert.deepEqual(card.reasons, [
    'This website was only created 2 days ago.',
    'The page asks for card details.',
    "It isn't on any list of known scam websites.",
  ])
  const many = cardFor({ ...SAMPLE_REPORTS.suspicious, observations: ['a', 'b', 'c', 'd', 'e'] })
  assert.deepEqual(many.reasons, ['a', 'b', 'c'])
})

test("a couldn't-check leads its reasons with why", () => {
  const card = cardFor(SAMPLE_REPORTS.couldnt_check)
  assert.equal(card.state, 'couldnt_check')
  assert.equal(card.reasons[0], "That web address doesn't exist, or no longer works.")
  assert.equal(card.screenshotUrl, null)
})

test('a clean card is not a promise: its words say so', () => {
  const card = cardFor(SAMPLE_REPORTS.no_red_flags)
  assert.match(card.headline, /not a guarantee/i)
  assert.match(card.action, /company's own website/)
})

test('a scanning card has no verdict, no reasons and no link yet', () => {
  const card = scanningCard('5a3c0de1f2b4')
  assert.deepEqual([card.state, card.reasons, card.link, card.screenshotUrl], ['scanning', [], null, null])
})

test('a long address is cut in the middle, keeping its start and its end', () => {
  const long = SAMPLE_REPORTS.suspicious.url_defanged
  const cut = cardFor(SAMPLE_REPORTS.suspicious).link!
  assert.ok(long.length > MAX_LINK_CHARS)
  assert.equal(cut.length, MAX_LINK_CHARS)
  assert.ok(cut.startsWith('hxxps://parcel-redeliver') &&cut.endsWith('confirm-address') && cut.includes('…'))
  assert.equal(truncateMiddle('hxxps://example[.]com/'), 'hxxps://example[.]com/')
})

test('only our own screenshot path becomes an image', () => {
  assert.equal(cardFor(SAMPLE_REPORTS.dangerous).screenshotUrl, '/sample/shot.png')
  assert.equal(cardFor({ ...SAMPLE_REPORTS.dangerous, screenshot_url: 'https://evil.example/x.png' }).screenshotUrl, null)
})

// --- colour contrast: every text colour on the card against the card's surface -------------------

function tokens(css: string): Record<string, string> {
  const found: Record<string, string> = {}
  for (const match of css.matchAll(/(--card[\w-]*):\s*(#[0-9a-fA-F]{6})\b/g)) found[match[1]] = match[2]
  return found
}

function luminance(hex: string): number {
  const channel = (i: number) => {
    const v = parseInt(hex.slice(i, i + 2), 16) / 255
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4
  }
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5)
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

/** The surface is slightly see-through: mix in the worst backdrop it could sit on. */
function over(surface: string, backdrop: string, alpha: number): string {
  const mix = (i: number) =>
    Math.round(parseInt(surface.slice(i, i + 2), 16) * alpha + parseInt(backdrop.slice(i, i + 2), 16) * (1 - alpha))
      .toString(16)
      .padStart(2, '0')
  return `#${mix(1)}${mix(3)}${mix(5)}`
}

test('every text colour on the card has at least 4.5:1 contrast, in light and in dark', () => {
  const t = tokens(readFileSync(new URL('./theme.css', import.meta.url), 'utf8'))
  const alpha = 0.94 // --card-alpha in theme.css
  assert.match(readFileSync(new URL('./theme.css', import.meta.url), 'utf8'), /--card-alpha:\s*0\.94/)
  for (const scheme of ['', '-dark']) {
    const surface = t[`--card${scheme}-surface`]
    assert.ok(surface, `--card${scheme}-surface is defined`)
    // worst case behind the glass: black under a light card, white under a dark one
    const worst = over(surface, scheme ? '#ffffff' : '#000000', alpha)
    for (const text of ['ink', 'muted', 'link']) {
      const ratio = contrast(t[`--card${scheme}-${text}`], worst)
      assert.ok(ratio >= 4.5, `${scheme || 'light'} ${text}: ${ratio.toFixed(2)}`)
    }
    for (const verdict of ['dangerous', 'suspicious', 'clear', 'unknown']) {
      const ratio = contrast(t[`--card${scheme}-${verdict}`], t[`--card${scheme}-${verdict}-fill`])
      assert.ok(ratio >= 4.5, `${scheme || 'light'} ${verdict} badge: ${ratio.toFixed(2)}`)
      // the action line is the verdict colour on the card surface
      const onSurface = contrast(t[`--card${scheme}-${verdict}`], worst)
      assert.ok(onSurface >= 4.5, `${scheme || 'light'} ${verdict} on the card: ${onSurface.toFixed(2)}`)
    }
  }
})

test('the clean verdict is never green', () => {
  const t = tokens(readFileSync(new URL('./theme.css', import.meta.url), 'utf8'))
  for (const name of ['--card-clear', '--card-clear-fill', '--card-dark-clear', '--card-dark-clear-fill']) {
    const [r, g, b] = [1, 3, 5].map((i) => parseInt(t[name].slice(i, i + 2), 16))
    assert.ok(b >= g || b > r + 40, `${name} ${t[name]} reads as blue or aqua, not green`)
    assert.ok(!(g > r + 30 && g > b + 30), `${name} ${t[name]} is not a green`)
  }
})
