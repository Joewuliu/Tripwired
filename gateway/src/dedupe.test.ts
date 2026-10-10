import assert from "node:assert/strict";
import { test } from "node:test";
import { createSeenSet } from "./dedupe";

test("the first sighting is new, the second is a repeat", () => {
  const seen = createSeenSet();
  assert.equal(seen("a"), false);
  assert.equal(seen("a"), true);
  assert.equal(seen("b"), false);
});

test("only the most recent ids are remembered", () => {
  const seen = createSeenSet(2);
  seen("a");
  seen("b");
  seen("c"); // pushes "a" out
  assert.equal(seen("c"), true);
  assert.equal(seen("a"), false);
});
