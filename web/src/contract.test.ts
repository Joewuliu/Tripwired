import assert from 'node:assert/strict'
import { test } from 'node:test'
import { ContractError, parseReport } from './contract.ts'
import sample from './sample/report.sample.json' with { type: 'json' }

test('the shared sample is a valid report, field for field', () => {
  assert.deepEqual(parseReport(sample), sample)
})

test('a report with nulls where the sample has values is still valid', () => {
  const bare = { ...sample, brand_match: null, screenshot_url: null, title: null, final_status: null, final_url_defanged: null }
  assert.equal(parseReport(bare).brand_match, null)
})

test('the score is always a number', () => {
  assert.throws(() => parseReport({ ...sample, score: null }), ContractError)
  assert.throws(() => parseReport({ ...sample, score: '90' }), ContractError)
})

test('the placeholder verdict from before scoring existed is gone', () => {
  assert.throws(() => parseReport({ ...sample, verdict: 'unscored' }), ContractError)
})

test('the sample adds up: its score is the sum of its evidence', () => {
  assert.equal(sample.score, sample.evidence.reduce((total, item) => total + item.points, 0))
})

test('every evidence id is unique, because the report keys its rows on it', () => {
  const ids = sample.evidence.map((item) => item.id)
  assert.equal(new Set(ids).size, ids.length)
})

test('a missing field is named in the error', () => {
  const { headline: _headline, ...without } = sample
  assert.throws(() => parseReport(without), (e: unknown) => e instanceof ContractError && /headline/.test(e.message))
})

test('an unknown verdict is rejected, including "safe"', () => {
  assert.throws(() => parseReport({ ...sample, verdict: 'safe' }), ContractError)
})

test('wrong types deep inside are rejected with their path', () => {
  const broken = { ...sample, evidence: [{ ...sample.evidence[0], points: 'many' }] }
  assert.throws(() => parseReport(broken), (e: unknown) => e instanceof ContractError && /evidence\[0\]\.points/.test(e.message))
})

test('something that is not an object is rejected', () => {
  assert.throws(() => parseReport(null), ContractError)
  assert.throws(() => parseReport('{}'), ContractError)
})

test('the sample follows the house rules: defanged urls only, never "safe"', () => {
  const blob = JSON.stringify(sample)
  assert.ok(!blob.includes('http://') && !blob.includes('https://'))
  assert.notEqual(sample.verdict, 'safe')
})
