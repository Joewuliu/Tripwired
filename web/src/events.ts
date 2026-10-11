// The live event stream (GET /events, Server-Sent Events) and a recorded replay of it, so the
// dashboard can be designed with no scan running. Mirrors analyzer/events.py; both are checked
// against ./sample/events.sample.json.

export const EVENT_KINDS = [
  'scan_started', 'check_done', 'screenshot_ready', 'verdict', 'reply_sent', 'guardian_alerted', 'scan_failed',
] as const
export type EventKind = (typeof EVENT_KINDS)[number]

/** Whether a finished check found something, found nothing, or could not look. */
export type Outcome = 'flagged' | 'clear' | 'unavailable'

export interface ScanEvent {
  id: number // increases by one per event; also the SSE id (the browser resends it as Last-Event-ID)
  at: string // ISO 8601, UTC
  scan: string // the 12-hex scan id every event of one scan shares; the report is at /r/<scan>
  kind: EventKind
  sender: string | null // a mask such as •••-4412, or null for a scan started from the website
  data: Record<string, unknown>
}

// What `data` holds, by kind (all text is already defanged):
//   scan_started      { url, source: 'imessage' | 'web' }
//   check_done        { check, outcome, detail }  check: page_opened | threat_feeds | domain_age |
//                                                         brand_match | sensitive_form | platform_warning
//   screenshot_ready  { screenshot_url }          fetch it from the same host
//   verdict           { verdict, score, headline, explained_by, report_path }
//   reply_sent        { delivered }
//   guardian_alerted  { guardian }                family mode told a guardian (a mask, like sender)
//   scan_failed       { detail }

export class EventError extends Error {}

function fail(path: string, expected: string): never {
  throw new EventError(`${path}: expected ${expected}`)
}

export function parseEvent(value: unknown): ScanEvent {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return fail('event', 'an object')
  const o = value as Record<string, unknown>
  if (typeof o.id !== 'number' || !Number.isInteger(o.id)) fail('id', 'an integer')
  if (typeof o.at !== 'string') fail('at', 'a string')
  if (typeof o.scan !== 'string' || !/^[a-f0-9]{12}$/.test(o.scan)) fail('scan', '12 hex characters')
  if (typeof o.kind !== 'string' || !(EVENT_KINDS as readonly string[]).includes(o.kind)) fail('kind', EVENT_KINDS.join(', '))
  if (o.sender !== null && typeof o.sender !== 'string') fail('sender', 'a mask or null')
  if (typeof o.data !== 'object' || o.data === null || Array.isArray(o.data)) fail('data', 'an object')
  return o as unknown as ScanEvent
}

export interface ReplayItem {
  t_ms: number
  event: ScanEvent
}

/** The recorded file: events with the time (ms after the start) each one arrived. */
export function parseReplay(value: unknown): ReplayItem[] {
  const o = value as { events?: unknown }
  if (!o || !Array.isArray(o.events)) return fail('events', 'a list')
  return o.events.map((item, i) => {
    const r = item as { t_ms?: unknown; event?: unknown }
    if (typeof r?.t_ms !== 'number') fail(`events[${i}].t_ms`, 'a number')
    return { t_ms: r.t_ms, event: parseEvent(r.event) }
  })
}

type Timer = (callback: () => void, ms: number) => unknown

/**
 * Feed a recording to `onEvent` as if it were live. `speed` 2 plays twice as fast. Returns a
 * function that stops it. Replace `setTimer` to drive it from a test.
 */
export function replay(
  items: ReplayItem[],
  onEvent: (event: ScanEvent) => void,
  options: { speed?: number; setTimer?: Timer; clearTimer?: (handle: unknown) => void } = {},
): () => void {
  const { speed = 1, setTimer = setTimeout as Timer, clearTimer = (h) => clearTimeout(h as number) } = options
  const handles = items.map((item) => setTimer(() => onEvent(item.event), item.t_ms / speed))
  return () => handles.forEach(clearTimer)
}

export const EVENTS_PATH = '/events'

/**
 * Listen to the real stream. The browser reconnects by itself and resends the last id, so a
 * dropped connection loses nothing. Returns a function that closes it.
 */
export function connect(
  onEvent: (event: ScanEvent) => void,
  onStatus: (open: boolean) => void = () => {},
  Source: typeof EventSource = EventSource,
): () => void {
  const source = new Source(EVENTS_PATH)
  source.onopen = () => onStatus(true)
  source.onerror = () => onStatus(false)
  for (const kind of EVENT_KINDS) {
    source.addEventListener(kind, (message) => {
      try {
        onEvent(parseEvent(JSON.parse(String((message as MessageEvent).data))))
      } catch {
        // an event this page does not understand is skipped, never fatal
      }
    })
  }
  return () => source.close()
}
