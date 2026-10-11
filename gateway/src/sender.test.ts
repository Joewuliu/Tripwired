import assert from "node:assert/strict";
import { test } from "node:test";
import { createHasher, label, mask, redact } from "./sender";

const SALT = "a-long-enough-test-salt-0123456789";
const quiet = () => {};

test("the same number gives the same hash, however it is written", () => {
  const h = createHasher(SALT, quiet);
  const a = h.identify("+1 (919) 555-4412");
  assert.deepEqual(h.identify("19195554412"), a);
  assert.deepEqual(h.identify("+19195554412"), a);
  assert.notEqual(h.identify("+19195554413").hash, a.hash);
});

test("the hash does not contain the number and depends on the salt", () => {
  const a = createHasher(SALT, quiet).identify("+19195554412");
  const b = createHasher(`${SALT}-other`, quiet).identify("+19195554412");
  assert.match(a.hash, /^[0-9a-f]{16}$/);
  assert.ok(!a.hash.includes("5554412"));
  assert.notEqual(a.hash, b.hash);
});

test("only the last four digits are kept, and they make the mask", () => {
  const sender = createHasher(SALT, quiet).identify("+1 919 555 4412");
  assert.equal(sender.last4, "4412");
  assert.equal(mask(sender), "•••-4412");
  assert.ok(!JSON.stringify(sender).includes("919"));
  assert.ok(!label(sender).includes("919555"));
});

test("an email sender is hashed too, with nothing to mask", () => {
  const h = createHasher(SALT, quiet);
  const sender = h.identify("Someone@Example.com");
  assert.equal(sender.last4, null);
  assert.equal(mask(sender), "•••");
  assert.deepEqual(h.identify("someone@example.com"), sender);
});

test("with no salt a random one is used and the operator is told; a short salt is flagged", () => {
  const warnings: string[] = [];
  const a = createHasher(undefined, (line) => warnings.push(line)).identify("+19195554412");
  const b = createHasher("  ", (line) => warnings.push(line)).identify("+19195554412");
  assert.equal(warnings.length, 2);
  assert.notEqual(a.hash, b.hash); // a different random salt each run
  createHasher("short", (line) => warnings.push(line));
  assert.match(warnings[2], /short/);
});

test("redact removes phone numbers and emails from text", () => {
  const text = redact("failed for +1 (919) 555-4412 and a@b.example, id 12");
  assert.ok(!/555|919|a@b/.test(text));
  assert.match(text, /\[number\]/);
  assert.match(text, /\[email\]/);
  assert.match(text, /id 12/); // short numbers are left alone
});
