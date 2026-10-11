import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCommand, parsePhone } from "./commands";

test("phone numbers are read the ways people type them", () => {
  for (const typed of ["+1 919 555 0142", "(919) 555-0142", "919.555.0142", "19195550142", "+19195550142", " 919-555-0142 "]) {
    assert.equal(parsePhone(typed), "19195550142", typed);
  }
  assert.equal(parsePhone("+44 20 7946 0958"), "442079460958");
});

test("what is not a phone number is refused, not guessed at", () => {
  for (const typed of ["", "grandma", "555-0142", "919 555 01422 9", "+1", "919555014a", "https://example.com", "12345678901234567890"]) {
    assert.equal(parsePhone(typed), null, typed);
  }
});

test("the commands, in any case, with the punctuation people add", () => {
  assert.deepEqual(parseCommand("protect +1 919 555 0142"), { kind: "protect", number: "19195550142" });
  assert.deepEqual(parseCommand("Protect: (919) 555-0142"), { kind: "protect", number: "19195550142" });
  assert.deepEqual(parseCommand("UNPROTECT 9195550142"), { kind: "unprotect", number: "19195550142" });
  assert.deepEqual(parseCommand(" yes "), { kind: "yes" });
  assert.deepEqual(parseCommand("YES!"), { kind: "yes" });
  assert.deepEqual(parseCommand("Stop."), { kind: "stop" });
  assert.deepEqual(parseCommand("family"), { kind: "family" });
});

test("protect with no usable number is still the command, so the person gets told how", () => {
  assert.deepEqual(parseCommand("protect"), { kind: "protect", number: null });
  assert.deepEqual(parseCommand("protect my grandma"), { kind: "protect", number: null });
});

test("ordinary messages are not commands", () => {
  for (const text of ["yes I got this text https://ezpass-pay.top/x", "is this real?", "stop sending me this https://a.example", "protection", "my family got this", "https://example.com", "yesterday"]) {
    assert.equal(parseCommand(text), null, text);
  }
});
