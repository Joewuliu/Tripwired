import assert from 'node:assert/strict'
import { test } from 'node:test'
import { EMPTY, MAX_VISIBLE, averageSeconds, focused, inProgress, position, reduce, shortHost } from './dashboardState.ts'
import type { DashState } from './dashboardState.ts'
import { parseReplay } from './events.ts'
import type { EventKind, ScanEvent } from './events.ts'
import sample from './sample/events.sample.json' with { type: 'json' }

const recording = parseReplay(sample).map((item) => item.event)
const play = (events: ScanEvent[], from: DashState = EMPTY) => events.reduce(reduce, from)

let nextId = 1000
function event(scan: string, kind: EventKind, data: Record<string, unknown> = {}, at = '2026-10-10T18:30:00.000Z'): ScanEvent {
  return { id: nextId++, at, scan, kind, sender: null, data }
}
const scanId = (n: number) => n.toString(16).padStart(12, '0')

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

test('the running stats add up, and the average is start-to-verdict', () => {
  const { stats } = play(recording)
  assert.deepEqual(
    { total: stats.total, dangerous: stats.dangerous, suspicious: stats.suspicious, clear: stats.no_red_flags, unknown: stats.couldnt_check, failed: stats.failed },
    { total: 4, dangerous: 1, suspicious: 0, clear: 1, unknown: 1, failed: 1 },
  )
  assert.equal(stats.timedScans, 3)
  assert.equal(averageSeconds(stats), 9.1) // each recorded scan takes 9.1 s to its verdict
  assert.equal(averageSeconds(EMPTY.stats), null)
})

test('events seen twice (a reconnect replays some) change nothing', () => {
  const once = play(recording)
  assert.deepEqual(play(recording, once), once)
  assert.equal(play(recording.slice(0, 10), once), once)
})

test('a scan climbs with each finished check and settles high once judged', () => {
  const id = scanId(1)
  let state = play([event(id, 'scan_started', { url: 'hxxps://a[.]example', source: 'web' })])
  const start = position(state.scans[0]).bottom
  state = play([event(id, 'check_done', { check: 'page_opened', outcome: 'clear', detail: 'ok' })], state)
  const one = position(state.scans[0]).bottom
  state = play([event(id, 'check_done', { check: 'domain_age', outcome: 'flagged', detail: 'new' })], state)
  const two = position(state.scans[0]).bottom
  assert.ok(start < one && one < two)
  state = play([event(id, 'verdict', { verdict: 'suspicious', score: 30, headline: 'Suspicious: new', report_path: `/r/${id}` })], state)
  assert.ok(position(state.scans[0]).bottom > two + 10)
  assert.equal(inProgress(state), 0)
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
  assert.equal(state.stats.total, 1)
})

test('a report link is only ever our own /r/<id> path', () => {
  const id = scanId(3)
  const bad = play([event(id, 'verdict', { verdict: 'dangerous', report_path: '//evil.example/r/abc' })])
  assert.equal(bad.scans[0].reportPath, null)
})

test('when the sky is full the oldest finished bubble leaves, and its lane is reused', () => {
  let state = EMPTY
  for (let n = 1; n <= MAX_VISIBLE; n++) {
    state = play([event(scanId(n), 'scan_started', { url: `hxxps://s${n}[.]example`, source: 'web' })], state)
  }
  assert.deepEqual(state.scans.map((s) => s.lane).sort(), [0, 1, 2, 3, 4, 5, 6])
  state = play([event(scanId(3), 'verdict', { verdict: 'no_red_flags', score: 0 })], state)
  const laneOfThree = state.scans.find((s) => s.id === scanId(3))!.lane
  state = play([event(scanId(99), 'scan_started', { url: 'hxxps://new[.]example', source: 'web' })], state)
  const three = state.scans.find((s) => s.id === scanId(3))!
  assert.equal(three.leaving, true) // finished, so it goes before the older ones still scanning
  assert.equal(position(three).bottom > 100, true)
  assert.equal(state.scans.find((s) => s.id === scanId(99))!.lane, laneOfThree)
  assert.equal(state.scans.filter((s) => !s.leaving).length, MAX_VISIBLE)
})

test('bubbles that left are forgotten after a few more, but the stats remember', () => {
  let state = EMPTY
  for (let n = 1; n <= 30; n++) {
    state = play([event(scanId(n), 'scan_started', {}), event(scanId(n), 'verdict', { verdict: 'suspicious', score: 40 })], state)
  }
  assert.ok(state.scans.length <= MAX_VISIBLE + 3)
  assert.equal(state.stats.total, 30)
  assert.equal(state.stats.suspicious, 30)
})

test('the panel follows the scan that moved last, unless the viewer picked one still in the sky', () => {
  const state = play(recording)
  assert.equal(focused(state, null)!.id, recording.at(-1)!.scan)
  assert.equal(focused(state, '5a3c0de1f2b4')!.id, '5a3c0de1f2b4')
  assert.equal(focused(state, 'ffffffffffff')!.id, recording.at(-1)!.scan)
  assert.equal(focused(EMPTY, null), null)
})

test('a bubble is named by the host of its defanged address', () => {
  assert.equal(shortHost('hxxps://ezpass-pay[.]top/pay?x=1'), 'ezpass-pay[.]top')
  assert.equal(shortHost(null), 'link')
  assert.ok(shortHost(`hxxps://${'a'.repeat(60)}[.]example`).endsWith('…'))
})
