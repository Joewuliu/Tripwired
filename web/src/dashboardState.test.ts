import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  EMPTY, MAX_KEPT, MAX_VISIBLE, bubbles, focused, loadHidden, position, reduce, saveHidden, shortHost, shown, tally,
} from './dashboardState.ts'
import type { Action, DashState } from './dashboardState.ts'
import { parseReplay } from './events.ts'
import type { EventKind, ScanEvent } from './events.ts'
import sample from './sample/events.sample.json' with { type: 'json' }

const recording = parseReplay(sample).map((item) => item.event)
const play = (actions: Action[], from: DashState = EMPTY) => actions.reduce(reduce, from)

let nextId = 1000
function event(scan: string, kind: EventKind, data: Record<string, unknown> = {}, at = '2026-10-10T18:30:00.000Z'): ScanEvent {
  return { id: nextId++, at, scan, kind, sender: null, data }
}
const scanId = (n: number) => n.toString(16).padStart(12, '0')
const started = (n: number) => event(scanId(n), 'scan_started', { url: `hxxps://s${n}[.]example`, source: 'web' })
const judged = (n: number, verdict = 'suspicious') => event(scanId(n), 'verdict', { verdict, score: 40 })

test('the recording becomes four scans with their checks, verdicts and reply', () => {
  const state = play(recording)
  assert.equal(state.scans.length, 4)
  const [toll, clean, gone, broken] = state.scans
  assert.equal(toll.verdict, 'dangerous')
  assert.equal(toll.checks.length, 6)
  assert.equal(toll.sender, '•••-4412')
  assert.equal(toll.replied, true)
  assert.equal(toll.screenshotUrl, '/sample/shot.png')
  assert.equal(toll.reportPath, '/r/5a3c0de1f2b4')
  assert.equal(clean.verdict, 'no_red_flags')
  assert.equal(clean.source, 'web')
  assert.equal(clean.replied, false)
  assert.equal(gone.verdict, 'couldnt_check')
  assert.equal(gone.screenshotUrl, null)
  assert.equal(gone.checks[0].outcome, 'unavailable')
  assert.equal(broken.failed, true)
  assert.equal(broken.verdict, null)
})

test('the counts cover what is shown', () => {
  assert.deepEqual(tally(play(recording)), { total: 4, dangerous: 1, suspicious: 0, no_red_flags: 1, couldnt_check: 1 })
  assert.deepEqual(tally(EMPTY), { total: 0, dangerous: 0, suspicious: 0, no_red_flags: 0, couldnt_check: 0 })
})

test('events seen twice (a reconnect replays some) change nothing', () => {
  const once = play(recording)
  assert.deepEqual(play(recording, once), once)
  assert.equal(play(recording.slice(0, 10), once), once)
})

test('a scan climbs with each finished check and settles high once judged', () => {
  const id = scanId(1)
  let state = play([started(1)])
  const start = position(state.scans[0]).bottom
  state = play([event(id, 'check_done', { check: 'page_opened', outcome: 'clear', detail: 'ok' })], state)
  const one = position(state.scans[0]).bottom
  state = play([event(id, 'check_done', { check: 'domain_age', outcome: 'flagged', detail: 'new' })], state)
  const two = position(state.scans[0]).bottom
  assert.ok(start < one && one < two)
  state = play([judged(1)], state)
  assert.ok(position(state.scans[0]).bottom > two + 10)
})

test('the same check reported twice is one line, and nonsense is ignored', () => {
  const id = scanId(2)
  const state = play([
    event(id, 'scan_started', { url: 'hxxps://a[.]example', source: 'carrier pigeon' }),
    event(id, 'check_done', { check: 'page_opened', outcome: 'clear', detail: 'ok' }),
    event(id, 'check_done', { check: 'page_opened', outcome: 'clear', detail: 'ok again' }),
    event(id, 'check_done', { check: 'domain_age', outcome: 'sparkly', detail: 'x' }),
    event(id, 'verdict', { verdict: 'safe', score: 0 }),
    event(id, 'screenshot_ready', { screenshot_url: 'https://evil.example/x.png' }),
  ])
  const scan = state.scans[0]
  assert.equal(scan.checks.length, 1)
  assert.equal(scan.source, null)
  assert.equal(scan.verdict, null) // "safe" is not a verdict
  assert.equal(scan.screenshotUrl, null) // only our own /shots path becomes an image
})

test('a report link is only ever our own /r/<id> path', () => {
  const bad = play([event(scanId(3), 'verdict', { verdict: 'dangerous', report_path: '//evil.example/r/abc' })])
  assert.equal(bad.scans[0].reportPath, null)
})

test('when the sky is full the oldest finished bubble leaves it, and its lane is reused', () => {
  let state = EMPTY
  for (let n = 1; n <= MAX_VISIBLE; n++) state = play([started(n)], state)
  assert.deepEqual(state.scans.map((s) => s.lane).sort(), [0, 1, 2, 3, 4, 5, 6])
  state = play([judged(3, 'no_red_flags')], state)
  const laneOfThree = state.scans.find((s) => s.id === scanId(3))!.lane
  state = play([started(99)], state)
  const three = state.scans.find((s) => s.id === scanId(3))!
  assert.equal(three.leaving, true) // finished, so it goes before the older ones still scanning
  assert.ok(position(three).bottom > 100)
  assert.equal(state.scans.find((s) => s.id === scanId(99))!.lane, laneOfThree)
  assert.equal(bubbles(state).filter((s) => !s.leaving).length, MAX_VISIBLE)
})

test('scans that left the sky stay in the list and the counts; only a few are still drawn leaving', () => {
  let state = EMPTY
  for (let n = 1; n <= 30; n++) state = play([started(n), judged(n)], state)
  assert.equal(shown(state).length, 30)
  assert.equal(tally(state).suspicious, 30)
  assert.equal(bubbles(state).filter((s) => !s.leaving).length, MAX_VISIBLE)
  assert.equal(bubbles(state).filter((s) => s.leaving).length, 3)
})

test('the list has a ceiling', () => {
  let state = EMPTY
  for (let n = 1; n <= MAX_KEPT + 20; n++) state = play([started(n)], state)
  assert.equal(state.scans.length, MAX_KEPT)
  assert.equal(state.scans.at(-1)!.id, scanId(MAX_KEPT + 20))
})

test('a removed scan is gone from both views and the counts, and stays gone when its events come again', () => {
  const state = play([...recording, { type: 'hide', id: '5a3c0de1f2b4' }])
  assert.equal(shown(state).some((s) => s.id === '5a3c0de1f2b4'), false)
  assert.equal(bubbles(state).some((s) => s.id === '5a3c0de1f2b4'), false)
  assert.deepEqual(tally(state), { total: 3, dangerous: 0, suspicious: 0, no_red_flags: 1, couldnt_check: 1 })
  // A reload: the remembered ids are there first, then the stream replays its backlog.
  const reloaded = play(recording, { ...EMPTY, hidden: ['5a3c0de1f2b4'] })
  assert.equal(shown(reloaded).length, 3)
  // A replay starting over keeps what was removed.
  assert.deepEqual(play([{ type: 'reset' }], state).hidden, ['5a3c0de1f2b4'])
})

test('a removed scan takes no room in the sky, so it never pushes another bubble out', () => {
  let state = play([{ type: 'hide', id: scanId(1) }])
  for (let n = 1; n <= MAX_VISIBLE + 1; n++) state = play([started(n), judged(n)], state)
  assert.equal(state.scans.filter((s) => s.leaving).length, 0) // 8 scans, one of them removed: 7 fit
  assert.equal(bubbles(state).length, MAX_VISIBLE)
})

test('undo brings a scan back, with a lane of its own', () => {
  let state = EMPTY
  for (let n = 1; n <= 3; n++) state = play([started(n)], state)
  const before = state
  state = play([{ type: 'hide', id: scanId(2) }, started(4), { type: 'unhide', id: scanId(2) }], state)
  assert.equal(shown(state).length, 4)
  const lanes = bubbles(state).map((s) => s.lane)
  assert.equal(new Set(lanes).size, lanes.length)
  assert.deepEqual(play([{ type: 'hide', id: scanId(2) }, { type: 'unhide', id: scanId(2) }], before).hidden, [])
})

test('the summary follows the scan that moved last, unless the viewer picked one that is still shown', () => {
  const state = play(recording)
  const last = recording.at(-1)!.scan
  assert.equal(focused(state, null)!.id, last)
  assert.equal(focused(state, '5a3c0de1f2b4')!.id, '5a3c0de1f2b4')
  assert.equal(focused(state, 'ffffffffffff')!.id, last)
  assert.equal(focused(play([{ type: 'hide', id: '5a3c0de1f2b4' }], state), '5a3c0de1f2b4')!.id, last)
  assert.equal(focused(play([{ type: 'hide', id: last }], state), null)!.id !== last, true)
  assert.equal(focused(EMPTY, null), null)
})

test('a bubble is named by the host of its defanged address', () => {
  assert.equal(shortHost('hxxps://ezpass-pay[.]top/pay?x=1'), 'ezpass-pay[.]top')
  assert.equal(shortHost(null), 'link')
  assert.ok(shortHost(`hxxps://${'a'.repeat(60)}[.]example`).endsWith('…'))
})

test('removed ids are remembered in the browser, and junk there is ignored', () => {
  const data: Record<string, string> = {}
  const store = { getItem: (k: string) => data[k] ?? null, setItem: (k: string, v: string) => void (data[k] = v) }
  saveHidden(['5a3c0de1f2b4'], store)
  assert.deepEqual(loadHidden(store), ['5a3c0de1f2b4'])
  data['tripwire.dashboard.hidden'] = '["5a3c0de1f2b4", "<script>", 7, "../x"]'
  assert.deepEqual(loadHidden(store), ['5a3c0de1f2b4'])
  data['tripwire.dashboard.hidden'] = '{broken'
  assert.deepEqual(loadHidden(store), [])
  assert.deepEqual(loadHidden(null), [])
  saveHidden(['5a3c0de1f2b4'], null) // must not throw
})

test('a guardian alert is kept as a mask, once, and anything that is not a mask is ignored', () => {
  const toll = play(recording).scans[0]
  assert.deepEqual(toll.guardians, ['•••-8820'])
  const id = scanId(7)
  const state = play([
    started(7),
    event(id, 'guardian_alerted', { guardian: '•••-4412' }),
    event(id, 'guardian_alerted', { guardian: '•••-4412' }),
    event(id, 'guardian_alerted', { guardian: '+19195554412' }),
    event(id, 'guardian_alerted', { guardian: 7 }),
  ])
  assert.deepEqual(state.scans[0].guardians, ['•••-4412'])
})
