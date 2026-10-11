import assert from 'node:assert/strict'
import { test } from 'node:test'
import { EVENT_KINDS, EventError, parseEvent, parseReplay, replay } from './events.ts'
import sample from './sample/events.sample.json' with { type: 'json' }

test('the recording is valid and covers every kind of event', () => {
  const items = parseReplay(sample)
  assert.ok(items.length >= 20)
  const kinds = new Set(items.map((item) => item.event.kind))
  assert.deepEqual([...kinds].sort(), [...EVENT_KINDS].sort())
})

test('events are in id order, times never go backwards, and each scan starts before it ends', () => {
  const items = parseReplay(sample)
  items.forEach((item, i) => {
    assert.equal(item.event.id, i + 1)
    if (i > 0) assert.ok(item.t_ms >= items[i - 1].t_ms)
  })
  for (const scan of new Set(items.map((i) => i.event.scan))) {
    const kinds = items.filter((i) => i.event.scan === scan).map((i) => i.event.kind)
    assert.equal(kinds[0], 'scan_started', scan)
    assert.ok(['verdict', 'scan_failed'].includes(kinds.find((k) => k === 'verdict' || k === 'scan_failed')!), scan)
  }
})

test('the stream carries no number, no hash and no live link', () => {
  const text = JSON.stringify(sample)
  assert.doesNotMatch(text, /https?:\/\//)
  assert.doesNotMatch(text, /"(hash|last4)"/)
  for (const { event } of parseReplay(sample)) {
    assert.ok(event.sender === null || /^•••(-\d{4})?$/.test(event.sender), String(event.sender))
  }
})

test('every scan\'s check events name a known check and a known outcome', () => {
  const checks = new Set(['page_opened', 'threat_feeds', 'domain_age', 'brand_match', 'sensitive_form', 'platform_warning'])
  for (const { event } of parseReplay(sample)) {
    if (event.kind !== 'check_done') continue
    assert.ok(checks.has(String(event.data.check)))
    assert.ok(['flagged', 'clear', 'unavailable'].includes(String(event.data.outcome)))
    assert.equal(typeof event.data.detail, 'string')
  }
})

test('a verdict event never says safe', () => {
  for (const { event } of parseReplay(sample)) {
    if (event.kind === 'verdict') assert.doesNotMatch(String(event.data.headline), /\bsafe\b/i)
  }
})

test('a malformed event is rejected with the field named', () => {
  const good = parseReplay(sample)[0].event
  assert.throws(() => parseEvent({ ...good, kind: 'mystery' }), EventError)
  assert.throws(() => parseEvent({ ...good, scan: 'nope' }), EventError)
  assert.throws(() => parseEvent({ ...good, sender: 4412 }), EventError)
  assert.throws(() => parseEvent(null), EventError)
})

test('replay delivers each event at its time, scaled by speed, and can be stopped', () => {
  const items = parseReplay(sample).slice(0, 3)
  const scheduled: { ms: number; run: () => void; cancelled: boolean }[] = []
  const setTimer = (run: () => void, ms: number) => {
    const entry = { ms, run, cancelled: false }
    scheduled.push(entry)
    return entry
  }
  const clearTimer = (handle: unknown) => {
    ;(handle as { cancelled: boolean }).cancelled = true
  }
  const got: number[] = []
  const stop = replay(items, (e) => got.push(e.id), { speed: 2, setTimer, clearTimer })
  assert.deepEqual(scheduled.map((s) => s.ms), items.map((i) => i.t_ms / 2))
  scheduled[0].run()
  stop()
  assert.deepEqual(got, [1])
  assert.ok(scheduled.every((s) => s.cancelled))
})
