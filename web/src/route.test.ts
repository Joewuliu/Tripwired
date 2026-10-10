import assert from 'node:assert/strict'
import { test } from 'node:test'
import { parseRoute } from './route.ts'

test('/ is home', () => {
  assert.deepEqual(parseRoute('/'), { name: 'home' })
})

test('/r/<id> is a report, with or without a trailing slash', () => {
  assert.deepEqual(parseRoute('/r/sample'), { name: 'report', id: 'sample' })
  assert.deepEqual(parseRoute('/r/5a3c0de1f2b4/'), { name: 'report', id: '5a3c0de1f2b4' })
})

test('anything else is not found', () => {
  for (const path of ['/r', '/r/', '/r/Bad_Id', '/r/a/b', '/r/' + 'a'.repeat(33), '/analyze', '/shots/x.png']) {
    assert.deepEqual(parseRoute(path), { name: 'not-found' }, path)
  }
})
