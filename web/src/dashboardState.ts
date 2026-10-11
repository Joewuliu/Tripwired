// What the live dashboard knows, built only from the event stream. Pure functions: an event goes
// in, the next state comes out, so the whole picture can be tested without a browser.

import type { Verdict } from './contract.ts'
import type { Outcome, ScanEvent } from './events.ts'

export const MAX_VISIBLE = 7 // bubbles in the sky at once; also the number of lanes across it
export const MAX_KEPT = 200 // scans remembered for the list; the oldest are dropped first
const MAX_HIDDEN = 500 // removed ids remembered, newest kept
const DEPARTING = 3 // bubbles still drawn while they float away
export const CHECKS_PER_SCAN = 6

const VERDICTS: readonly string[] = ['dangerous', 'suspicious', 'no_red_flags', 'couldnt_check']
const OUTCOMES: readonly string[] = ['flagged', 'clear', 'unavailable']

export interface CheckLine {
  check: string
  outcome: Outcome
  detail: string
}

export interface ScanView {
  id: string
  url: string | null // defanged
  source: 'imessage' | 'web' | null
  sender: string | null // a mask such as •••-4412
  checks: CheckLine[]
  screenshotUrl: string | null
  verdict: Verdict | null
  score: number | null
  headline: string | null
  reportPath: string | null
  explainedBy: 'gemini' | 'template' | null
  replied: boolean
  guardians: string[] // masks of the guardians family mode alerted about this scan
  failed: boolean
  startedAt: number | null // ms, from the event's own time
  lane: number // 0..MAX_VISIBLE-1: where across the sky the bubble sits
  leaving: boolean // pushed out of the sky by newer scans; still in the list
  lastEventId: number
}

export interface DashState {
  scans: ScanView[] // oldest first; includes scans the viewer removed (see `hidden`)
  hidden: string[] // ids the viewer removed from this dashboard, oldest first
  lastEventId: number
}

export const EMPTY: DashState = { scans: [], hidden: [], lastEventId: 0 }

export type Action = ScanEvent | { type: 'reset' } | { type: 'hide'; id: string } | { type: 'unhide'; id: string }

function text(value: unknown, max = 300): string | null {
  return typeof value === 'string' && value.length > 0 ? value.slice(0, max) : null
}

/** Only our own screenshot and report paths become an image source or a link. */
function screenshotPath(value: unknown): string | null {
  return typeof value === 'string' && /^\/(shots|sample)\/[\w-]+\.png$/.test(value) ? value : null
}

function reportPath(value: unknown): string | null {
  return typeof value === 'string' && /^\/r\/[a-f0-9]{12}$/.test(value) ? value : null
}

function newScan(event: ScanEvent, lane: number): ScanView {
  return {
    id: event.scan, url: null, source: null, sender: event.sender, checks: [], screenshotUrl: null, verdict: null,
    score: null, headline: null, reportPath: null, explainedBy: null, replied: false, guardians: [], failed: false, startedAt: null,
    lane, leaving: false, lastEventId: event.id,
  }
}

export function isDone(scan: ScanView): boolean {
  return scan.verdict !== null || scan.failed
}

/** The scans that hold a place in the sky: not pushed out, and not removed by the viewer. */
function inSky(scans: ScanView[], hidden: readonly string[]): ScanView[] {
  return scans.filter((s) => !s.leaving && !hidden.includes(s.id))
}

/** Make room for one more bubble: the oldest finished scan leaves first, else the oldest. */
function makeRoom(scans: ScanView[], hidden: readonly string[]): ScanView[] {
  const sky = inSky(scans, hidden)
  if (sky.length < MAX_VISIBLE) return scans
  const goes = sky.find(isDone) ?? sky[0]
  return scans.map((s) => (s.id === goes.id ? { ...s, leaving: true } : s))
}

// Lanes are filled from the middle outwards, so two or three bubbles spread across the sky
// instead of crowding one side.
const LANE_ORDER = [3, 1, 5, 0, 6, 2, 4]

function freeLane(scans: ScanView[], hidden: readonly string[]): number {
  const taken = new Set(inSky(scans, hidden).map((s) => s.lane))
  return LANE_ORDER.find((lane) => !taken.has(lane)) ?? LANE_ORDER[0]
}

function apply(scan: ScanView, event: ScanEvent): ScanView {
  const data = event.data
  const next = { ...scan, lastEventId: event.id, sender: event.sender ?? scan.sender }
  switch (event.kind) {
    case 'scan_started':
      return {
        ...next,
        url: text(data.url),
        source: data.source === 'imessage' || data.source === 'web' ? data.source : null,
        startedAt: Date.parse(event.at) || null,
      }
    case 'check_done': {
      const check = text(data.check, 40)
      const outcome = typeof data.outcome === 'string' && OUTCOMES.includes(data.outcome) ? (data.outcome as Outcome) : null
      if (!check || !outcome || scan.checks.some((c) => c.check === check)) return next
      return { ...next, checks: [...scan.checks, { check, outcome, detail: text(data.detail) ?? '' }] }
    }
    case 'screenshot_ready':
      return { ...next, screenshotUrl: screenshotPath(data.screenshot_url) }
    case 'verdict': {
      if (typeof data.verdict !== 'string' || !VERDICTS.includes(data.verdict)) return next
      return {
        ...next,
        verdict: data.verdict as Verdict,
        score: typeof data.score === 'number' ? data.score : null,
        headline: text(data.headline),
        reportPath: reportPath(data.report_path),
        explainedBy: data.explained_by === 'gemini' ? 'gemini' : 'template',
      }
    }
    case 'reply_sent':
      return { ...next, replied: true }
    case 'guardian_alerted': {
      const guardian = typeof data.guardian === 'string' && /^•••(-[0-9]{4})?$/.test(data.guardian) ? data.guardian : null
      if (!guardian || scan.guardians.includes(guardian)) return next
      return { ...next, guardians: [...scan.guardians, guardian] }
    }
    case 'scan_failed':
      return { ...next, failed: true }
  }
}

function onEvent(state: DashState, event: ScanEvent): DashState {
  if (event.id <= state.lastEventId) return state // a reconnect replays some: seen once is enough
  let scans = state.scans
  if (!scans.some((s) => s.id === event.scan)) {
    // A scan the viewer removed is still tracked (so it stays removed), but takes no room in the sky.
    const removed = state.hidden.includes(event.scan)
    if (!removed) scans = makeRoom(scans, state.hidden)
    scans = [...scans, newScan(event, removed ? 0 : freeLane(scans, state.hidden))].slice(-MAX_KEPT)
  }
  return { ...state, scans: scans.map((s) => (s.id === event.scan ? apply(s, event) : s)), lastEventId: event.id }
}

/** Bring a removed scan back. If the sky filled up meanwhile, it gets a place like a new one would. */
function unhide(state: DashState, id: string): DashState {
  const hidden = state.hidden.filter((h) => h !== id)
  const scan = state.scans.find((s) => s.id === id)
  if (!scan || scan.leaving) return { ...state, hidden }
  const others = makeRoom(state.scans.filter((s) => s.id !== id), hidden)
  const lane = freeLane(others, hidden)
  return { ...state, hidden, scans: state.scans.map((s) => (s.id === id ? { ...scan, lane } : (others.find((o) => o.id === s.id) ?? s))) }
}

/** One step: an event from the stream, or something the viewer did. */
export function reduce(state: DashState, action: Action): DashState {
  if (!('type' in action)) return onEvent(state, action)
  switch (action.type) {
    case 'reset':
      return { ...EMPTY, hidden: state.hidden } // a replay starting over; what was removed stays removed
    case 'hide':
      return state.hidden.includes(action.id) ? state : { ...state, hidden: [...state.hidden, action.id].slice(-MAX_HIDDEN) }
    case 'unhide':
      return unhide(state, action.id)
  }
}

/** Every scan the viewer has not removed, oldest first. Both views and the stats are built from this. */
export function shown(state: DashState): ScanView[] {
  return state.scans.filter((s) => !state.hidden.includes(s.id))
}

/** The bubbles to draw: those in the sky, plus the last few on their way out. */
export function bubbles(state: DashState): ScanView[] {
  const all = shown(state)
  const departing = all.filter((s) => s.leaving).slice(-DEPARTING)
  return all.filter((s) => !s.leaving || departing.includes(s))
}

/** The scan Report Summary shows: the one the viewer picked, or else the one that moved last. */
export function focused(state: DashState, pinned: string | null): ScanView | null {
  const all = shown(state)
  const picked = pinned ? all.find((s) => s.id === pinned) : undefined
  if (picked) return picked
  return all.reduce<ScanView | null>((best, s) => (!best || s.lastEventId > best.lastEventId ? s : best), null)
}

export interface Tally {
  total: number
  dangerous: number
  suspicious: number
  no_red_flags: number
  couldnt_check: number
}

/** The counts on the left: only what is shown, so removing a scan takes it out of them too. */
export function tally(state: DashState): Tally {
  const counts: Tally = { total: 0, dangerous: 0, suspicious: 0, no_red_flags: 0, couldnt_check: 0 }
  for (const scan of shown(state)) {
    counts.total += 1
    if (scan.verdict) counts[scan.verdict] += 1
  }
  return counts
}

function hash(id: string): number {
  let h = 0
  for (const ch of id) h = (h * 31 + ch.charCodeAt(0)) >>> 0
  return h
}

/**
 * Where a bubble is, in percent of the sky: `left` from its lane, `bottom` from how far along it is.
 * It leaves the grass, climbs a step with each finished check, settles high once judged, and goes
 * off the top when newer scans push it out. The left edge of the sky is kept for the counts.
 */
export function position(scan: ScanView): { left: number; bottom: number } {
  const jitter = (hash(scan.id) % 7) - 3
  const left = 25 + scan.lane * (66 / (MAX_VISIBLE - 1)) + jitter * 0.5
  if (scan.leaving) return { left, bottom: 118 }
  if (scan.failed && !scan.verdict) return { left, bottom: 26 }
  if (scan.verdict) return { left, bottom: 48 + (scan.lane % 3) * 12 } // neighbours rest at different heights
  return { left, bottom: 6 + Math.min(scan.checks.length, CHECKS_PER_SCAN) * 7 }
}

/** The short name shown inside a bubble: the host of the defanged address. */
export function shortHost(url: string | null): string {
  if (!url) return 'link'
  const host = url.replace(/^hxxps?:\/\//i, '').split(/[/?#]/)[0]
  return host.length > 26 ? `${host.slice(0, 25)}…` : host
}

// --- what the viewer removed, remembered in this browser ---------------------------------------

const HIDDEN_KEY = 'tripwire.dashboard.hidden'
type Store = Pick<Storage, 'getItem' | 'setItem'>

function browserStore(): Store | null {
  try {
    return globalThis.localStorage ?? null
  } catch {
    return null // storage can be blocked; the dashboard works without it
  }
}

export function loadHidden(store: Store | null = browserStore()): string[] {
  try {
    const parsed: unknown = JSON.parse(store?.getItem(HIDDEN_KEY) ?? '[]')
    if (!Array.isArray(parsed)) return []
    return parsed.filter((id): id is string => typeof id === 'string' && /^[a-f0-9]{12}$/.test(id)).slice(-MAX_HIDDEN)
  } catch {
    return []
  }
}

export function saveHidden(hidden: readonly string[], store: Store | null = browserStore()): void {
  try {
    store?.setItem(HIDDEN_KEY, JSON.stringify(hidden))
  } catch {
    // full or blocked: the removal still holds until the page is reloaded
  }
}
