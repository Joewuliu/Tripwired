import assert from 'node:assert/strict'
import { test } from 'node:test'
import { parseReport } from './contract.ts'
import { readHistory, remember } from './history.ts'
import sample from './sample/report.sample.json' with { type: 'json' }

function memory(initial: Record<string, string> = {}) {
  const data = { ...initial }
  return {
    getItem: (key: string) => data[key] ?? null,
    setItem: (key: string, value: string) => {
      data[key] = value
    },
  }
}

test('a viewed report is remembered once, newest first', () => {
  const storage = memory()
  const report = parseReport(sample)
  remember(report, storage)
  remember({ ...report, id: 'aaaaaaaaaaaa' }, storage)
  remember(report, storage) // seen again: moves to the top, no duplicate
  assert.deepEqual(readHistory(storage).map((e) => e.id), [report.id, 'aaaaaaaaaaaa'])
})

test('only the latest eight are kept', () => {
  const storage = memory()
  const report = parseReport(sample)
  for (let i = 0; i < 12; i++) remember({ ...report, id: i.toString(16).padStart(12, '0') }, storage)
  assert.equal(readHistory(storage).length, 8)
})

test('garbage in storage is ignored, and missing storage is fine', () => {
  assert.deepEqual(readHistory(memory({ 'tripwire.history': '{not json' })), [])
  assert.deepEqual(readHistory(memory({ 'tripwire.history': '[{"id":"x","url":1}]' })), [])
  assert.deepEqual(readHistory(null), [])
  remember(parseReport(sample), null) // must not throw
})
