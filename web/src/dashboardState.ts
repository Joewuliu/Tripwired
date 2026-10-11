// What the live dashboard knows, built only from the event stream. Pure functions: an event goes
// in, the next state comes out, so the whole picture can be tested without a browser.

import type { Verdict } from './contract.ts'
import type { Outcome, ScanEvent } from './events.ts'

export const MAX_VISIBLE = 7 // bubbles in the sky at once; also the number of lanes across it
const MAX_LEAVING = 3 // bubbles kept a little longer while they float away
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
  failed: boolean
  startedAt: number | null // ms, from the event's own time
  lane: number // 0..MAX_VISIBLE-1: where across the sky the bubble sits
  leaving: boolean // pushed out by newer scans; floats away, then is dropped
  lastEventId: number
}

export interface Stats {
  total: number
  dangerous: number
  suspicious: number
  no_red_flags: number
  couldnt_check: number
  failed: number
  timedScans: number
  totalMs: number // scan_started to verdict, summed over timedScans
}

export interface DashState {
  scans: ScanView[] // oldest first
  stats: Stats
  lastEventId: number
}

export const EMPTY: DashState = {
  scans: [],
  stats: { total: 0, dangerous: 0, suspicious: 0, no_red_flags: 0, couldnt_check: 0, failed: 0, timedScans: 0, totalMs: 0 },
  lastEventId: 0,
}

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
    score: null, headline: null, reportPath: null, explainedBy: null, replied: false, failed: false, startedAt: null,
    lane, leaving: false, lastEventId: event.id,
  }
}

export function isDone(scan: ScanView): boolean {
  return scan.verdict !== null || scan.failed
}

/** Make room for one more bubble: the oldest finished scan leaves first, else the oldest. */
function makeRoom(scans: ScanView[]): ScanView[] {
  const visible = scans.filter((s) => !s.leaving)
  if (visible.length < MAX_VISIBLE) return scans
  const goes = visible.find(isDone) ?? visible[0]
  const marked = scans.map((s) => (s.id === goes.id ? { ...s, leaving: true } : s))
  const leaving = marked.filter((s) => s.leaving)
  const dropped = new Set(leaving.slice(0, Math.max(0, leaving.length - MAX_LEAVING)).map((s) => s.id))
  return marked.filter((s) => !dropped.has(s.id))
}

// Lanes are filled from the middle outwards, so two or three bubbles spread across the sky
// instead of crowding one side.
const LANE_ORDER = [3, 1, 5, 0, 6, 2, 4]

function freeLane(scans: ScanView[]): number {
  const taken = new Set(scans.filter((s) => !s.leaving).map((s) => s.lane))
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
    case 'scan_failed':
      return { ...next, failed: true }
  }
}

function count(stats: Stats, before: ScanView | undefined, after: ScanView, event: ScanEvent): Stats {
  const next = { ...stats }
  if (!before) next.total += 1
  if (after.verdict && !before?.verdict) {
    next[after.verdict] += 1
    const ended = Date.parse(event.at)
    if (after.startedAt && ended >= after.startedAt) {
      next.timedScans += 1
      next.totalMs += ended - after.startedAt
    }
  }
  if (after.failed && !before?.failed) next.failed += 1
  return next
}

/** One event in, the next picture out. An event already seen (a reconnect replays some) changes nothing. */
export function reduce(state: DashState, event: ScanEvent): DashState {
  if (event.id <= state.lastEventId) return state
  const before = state.scans.find((s) => s.id === event.scan)
  let scans = state.scans
  if (!before) {
    scans = makeRoom(scans)
    scans = [...scans, newScan(event, freeLane(scans))]
  }
  const after = apply(scans.find((s) => s.id === event.scan)!, event)
  return {
    scans: scans.map((s) => (s.id === event.scan ? after : s)),
    stats: count(state.stats, before, after, event),
    lastEventId: event.id,
  }
}

/** The scan the side panel shows: the one the viewer picked, or else the one that moved last. */
export function focused(state: DashState, pinned: string | null): ScanView | null {
  const picked = pinned ? state.scans.find((s) => s.id === pinned && !s.leaving) : undefined
  if (picked) return picked
  const live = state.scans.filter((s) => !s.leaving)
  return live.reduce<ScanView | null>((best, s) => (!best || s.lastEventId > best.lastEventId ? s : best), null)
}

export function inProgress(state: DashState): number {
  return state.scans.filter((s) => !s.leaving && !isDone(s)).length
}

/** Average seconds from the start of a scan to its verdict, or null before the first one. */
export function averageSeconds(stats: Stats): number | null {
  return stats.timedScans > 0 ? Math.round(stats.totalMs / stats.timedScans / 100) / 10 : null
}

function hash(id: string): number {
  let h = 0
  for (const ch of id) h = (h * 31 + ch.charCodeAt(0)) >>> 0
  return h
}

/**
 * Where a bubble is, in percent of the sky: `left` from its lane, `bottom` from how far along it is.
 * It leaves the grass, climbs a step with each finished check, settles high once judged, and goes
 * off the top when newer scans push it out.
 */
export function position(scan: ScanView): { left: number; bottom: number } {
  const jitter = (hash(scan.id) % 7) - 3
  const left = 9 + scan.lane * (82 / (MAX_VISIBLE - 1)) + jitter * 0.6
  if (scan.leaving) return { left, bottom: 118 }
  if (scan.failed && !scan.verdict) return { left, bottom: 26 }
  if (scan.verdict) return { left, bottom: 50 + (scan.lane % 3) * 11 } // neighbours rest at different heights
  return { left, bottom: 6 + Math.min(scan.checks.length, CHECKS_PER_SCAN) * 7 }
}

/** The short name shown inside a bubble: the host of the defanged address. */
export function shortHost(url: string | null): string {
  if (!url) return 'link'
  const host = url.replace(/^hxxps?:\/\//i, '').split(/[/?#]/)[0]
  return host.length > 26 ? `${host.slice(0, 25)}…` : host
}
