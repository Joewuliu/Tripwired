import assert from "node:assert/strict";
import { test } from "node:test";
import { extractUrls, refang } from "./urls";

test("finds a full link inside a message", () => {
  assert.deepEqual(extractUrls("Your toll is overdue: https://ezpass-pay.top/pay?id=9 act now"), [
    "https://ezpass-pay.top/pay?id=9",
  ]);
});

test("adds https:// to a link typed without a scheme", () => {
  assert.deepEqual(extractUrls("USPS: update your address at usps-track.top/redeliver"), [
    "https://usps-track.top/redeliver",
  ]);
});

test("keeps http:// links as http", () => {
  assert.deepEqual(extractUrls("see http://old-site.example/a"), ["http://old-site.example/a"]);
});

test("does not swallow trailing punctuation", () => {
  assert.deepEqual(extractUrls("Go to https://example.com/a."), ["https://example.com/a"]);
});

test("returns links in order, without duplicates", () => {
  assert.deepEqual(extractUrls("https://a.example/x then https://b.example/y and https://a.example/x again"), [
    "https://a.example/x",
    "https://b.example/y",
  ]);
});

test("ignores email addresses and non-web schemes", () => {
  assert.deepEqual(extractUrls("mail help@example.com or ftp://files.example.com/x"), []);
});

test("finds nothing in ordinary text", () => {
  assert.deepEqual(extractUrls("hi grandma, call me when you can. Mr. Smith says hello."), []);
});

test("recognises a defanged link that was pasted back", () => {
  assert.equal(refang("hxxps://ezpass-pay[.]top/pay"), "https://ezpass-pay.top/pay");
  assert.deepEqual(extractUrls("is this ok? hxxps://ezpass-pay[.]top/pay"), ["https://ezpass-pay.top/pay"]);
});
