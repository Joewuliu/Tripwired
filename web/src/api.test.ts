import assert from 'node:assert/strict'
import { test } from 'node:test'
import { fetchReport, submitLink } from './api.ts'
import sample from './sample/report.sample.json' with { type: 'json' }

function reply(status: number, body: unknown, headers: Record<string, string> = {}): typeof fetch {
  return async () =>
    new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers })
}

const ID = '5a3c0de1f2b4'

test('a stored report is fetched from this host and checked against the contract', async () => {
  let asked = ''
  const doFetch: typeof fetch = async (input) => {
    asked = String(input)
    return new Response(JSON.stringify(sample), { status: 200 })
  }
  const result = await fetchReport(ID, doFetch)
  assert.equal(asked, `/api/report/${ID}`)
  assert.ok(result.kind === 'ok' && result.report.verdict === sample.verdict)
})

test('an id that is not 12 hex characters is missing without asking the server', async () => {
  const doFetch: typeof fetch = async () => assert.fail('must not fetch')
  for (const id of ['', 'sample', '../../etc', 'ABCDEF123456', 'abc']) {
    assert.deepEqual(await fetchReport(id, doFetch), { kind: 'missing' }, id)
  }
})

test('404 is missing; other failures and bad shapes are errors, never an empty report', async () => {
  assert.deepEqual(await fetchReport(ID, reply(404, { detail: 'Not Found' })), { kind: 'missing' })
  assert.equal((await fetchReport(ID, reply(500, 'oops'))).kind, 'error')
  assert.equal((await fetchReport(ID, reply(200, { ...sample, verdict: 'safe' }))).kind, 'error')
  assert.equal((await fetchReport(ID, reply(200, 'not json'))).kind, 'error')
  const down: typeof fetch = async () => {
    throw new TypeError('network')
  }
  assert.equal((await fetchReport(ID, down)).kind, 'error')
})

test('a pasted link comes back as the report id', async () => {
  let sent: unknown
  const doFetch: typeof fetch = async (_input, init) => {
    sent = JSON.parse(String(init?.body))
    return new Response(JSON.stringify({ id: ID }), { status: 200 })
  }
  assert.deepEqual(await submitLink('example.com/x', doFetch), { kind: 'ok', id: ID })
  assert.deepEqual(sent, { url: 'example.com/x' })
})

test('the check route answers are told apart', async () => {
  assert.deepEqual(await submitLink('x', reply(422, {})), { kind: 'invalid' })
  assert.deepEqual(await submitLink('x', reply(429, {}, { 'retry-after': '1500' })), { kind: 'limited', retryMinutes: 25 })
  assert.deepEqual(await submitLink('x', reply(429, {})), { kind: 'limited', retryMinutes: 1 })
  assert.deepEqual(await submitLink('x', reply(502, 'bad gateway')), { kind: 'error' })
  assert.deepEqual(await submitLink('x', reply(200, { id: '../x' })), { kind: 'error' }) // never navigate to a made-up id
})
