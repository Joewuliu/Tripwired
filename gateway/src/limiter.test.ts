import assert from "node:assert/strict";
import { test } from "node:test";
import { RateLimiter, limitFromEnv } from "./limiter";

const HOUR = 60 * 60 * 1000;

test("ten checks an hour, then a wait that ends when the oldest check ages out", () => {
  const limiter = new RateLimiter(10, HOUR);
  for (let i = 0; i < 10; i++) assert.equal(limiter.take("a", i * 1000), null);
  assert.equal(limiter.take("a", 10_000), HOUR - 10_000); // the oldest check was at 0
  assert.equal(limiter.take("a", HOUR), null); // it has aged out, so one more is allowed
  assert.equal(limiter.take("a", HOUR + 1), 1000); // the next waits for the one at 1000 (999 ms; a wait is never under a second)
});

test("each sender has their own allowance", () => {
  const limiter = new RateLimiter(1, HOUR);
  assert.equal(limiter.take("a", 0), null);
  assert.notEqual(limiter.take("a", 1), null);
  assert.equal(limiter.take("b", 2), null);
});

test("a refused check does not extend the wait", () => {
  const limiter = new RateLimiter(1, HOUR);
  limiter.take("a", 0);
  const first = limiter.take("a", 10);
  limiter.take("a", 20);
  limiter.take("a", 30);
  assert.equal(limiter.take("a", 40), first! - 30);
});

test("memory is bounded: the least recently active senders are forgotten", () => {
  const limiter = new RateLimiter(1, HOUR, 3);
  for (const key of ["a", "b", "c", "d"]) limiter.take(key, 0);
  assert.equal(limiter.take("a", 1), null); // "a" was dropped, so it starts fresh
  assert.notEqual(limiter.take("d", 1), null);
});

test("the hourly limit can be set, within sense", () => {
  assert.equal(limitFromEnv(undefined), 10);
  assert.equal(limitFromEnv("25"), 25);
  for (const bad of ["", "0", "-3", "abc", "5000"]) assert.equal(limitFromEnv(bad), 10, bad);
});
