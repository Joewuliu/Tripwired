import assert from 'node:assert/strict'
import { test } from 'node:test'
import { guidance } from './actions.ts'
import type { Verdict } from './contract.ts'

const VERDICTS: Verdict[] = ['dangerous', 'suspicious', 'no_red_flags', 'couldnt_check']

test('every verdict has steps to follow', () => {
  for (const verdict of VERDICTS) assert.ok(guidance(verdict).steps.length >= 2, verdict)
})

test('nothing a person reads says "safe"', () => {
  for (const verdict of VERDICTS) {
    const { steps, reportButtons } = guidance(verdict, 'paypal[.]com')
    const text = [...steps, ...reportButtons.map((b) => b.label)].join(' ')
    assert.doesNotMatch(text, /\bsafe(ly)?\b/i, verdict)
  }
})

test('report buttons go only to https services or the SMS short code, never to the scanned page', () => {
  for (const verdict of VERDICTS) {
    for (const { href } of guidance(verdict, 'paypal[.]com').reportButtons) {
      assert.match(href, /^(https:\/\/[a-z.]+(\/|$)|sms:7726$)/, href)
    }
  }
})

test('the official site is named defanged, and is left out when there is no brand match', () => {
  const named = guidance('dangerous', 'paypal[.]com').steps.join(' ')
  assert.match(named, /paypal\[\.\]com/)
  assert.doesNotMatch(guidance('dangerous', null).steps.join(' '), /\[\.\]/)
})

test('a clean verdict offers no report buttons; a dangerous one offers three', () => {
  assert.equal(guidance('no_red_flags').reportButtons.length, 0)
  assert.equal(guidance('dangerous').reportButtons.length, 3)
})
