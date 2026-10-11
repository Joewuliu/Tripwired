// The verdict card: a compact view of one report, for a link preview or a chat bubble. This file is
// what the card says in each of its five states; pages/Card.tsx only draws it.

import type { Report, Verdict } from './contract.ts'
import { VERDICT_LABEL } from './verdict.ts'

/** The four verdicts, plus "scanning" for a report that is not ready yet. */
export type CardState = Verdict | 'scanning'

export const CARD_STATES: readonly CardState[] = ['scanning', 'dangerous', 'suspicious', 'no_red_flags', 'couldnt_check']

export interface CardModel {
  state: CardState
  badge: string // the verdict in words: the colour never carries it alone
  headline: string
  reasons: string[] // up to three plain lines, most important first
  link: string | null // defanged, shortened in the middle; shown as text, never a link
  action: string // what to do, one line
  screenshotUrl: string | null
  href: string // the full report the whole card opens
}

export const BADGE: Record<CardState, string> = { ...VERDICT_LABEL, scanning: 'Checking…' }

/** One line of what to do. None of them says a link is safe. */
export const ACTION: Record<CardState, string> = {
  scanning: "Hold on. Don't tap the link until this finishes.",
  dangerous: "Don't tap it or enter anything.",
  suspicious: "Don't type anything in; check with the sender another way.",
  no_red_flags: "Still go to the company's own website yourself.",
  couldnt_check: "Don't type anything until you've checked another way.",
}

const SCANNING_HEADLINE = 'Checking this link for you'
const MAX_REASONS = 3
export const MAX_LINK_CHARS = 40

/** Keep both ends of a long address: where it starts and how it ends are the telling parts. */
export function truncateMiddle(text: string, max = MAX_LINK_CHARS): string {
  if (text.length <= max) return text
  const keep = max - 1
  const head = Math.ceil(keep * 0.6)
  return `${text.slice(0, head)}…${text.slice(text.length - (keep - head))}`
}

/** Only our own screenshot paths become an image. */
function ownScreenshot(path: string | null): string | null {
  return path && /^\/(shots|sample)\/[\w-]+\.png$/.test(path) ? path : null
}

/** A defanged address is safe to show as text; anything else is not shown at all. */
function defangedOnly(url: string): string | null {
  return /https?:\/\//i.test(url) ? null : url
}

/** The card for a report that is not ready (or not found yet): the scanning state. */
export function scanningCard(id: string): CardModel {
  return {
    state: 'scanning', badge: BADGE.scanning, headline: SCANNING_HEADLINE, reasons: [], link: null,
    action: ACTION.scanning, screenshotUrl: null, href: `/r/${id}`,
  }
}

export function cardFor(report: Report, id: string = report.id): CardModel {
  const state = report.verdict
  // The badge already says "Dangerous": the headline keeps only what follows the verdict word.
  const headline = report.headline.replace(/^(Dangerous|Suspicious):\s*/i, '').trim() || BADGE[state]
  const lines = report.observations.map((line) => line.trim()).filter(Boolean)
  // A couldn't-check leads with its reason (the analyzer puts it first); elsewhere the headline has
  // already said the top reason, so it is not repeated underneath.
  const reasons = (state === 'couldnt_check' ? lines : lines.filter((line) => line !== headline)).slice(0, MAX_REASONS)
  const shown = defangedOnly(report.url_defanged)
  return {
    state,
    badge: BADGE[state],
    headline,
    reasons,
    link: shown ? truncateMiddle(shown) : null,
    action: ACTION[state],
    screenshotUrl: ownScreenshot(report.screenshot_url),
    href: `/r/${id}`,
  }
}
