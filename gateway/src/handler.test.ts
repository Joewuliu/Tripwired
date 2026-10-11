import assert from "node:assert/strict";
import { test } from "node:test";
import { type Analyzer, AnalyzerUnreachable } from "./analyzer";
import { RateLimiter } from "./limiter";
import { createHasher, label } from "./sender";
import { type Outbox, handleInbound } from "./handler";
import {
  ANALYZER_DOWN,
  NO_LINK_IN_PICTURE,
  NO_URL,
  ONE_AT_A_TIME,
  OPENING,
  PICTURE_UNAVAILABLE,
  READING_PICTURE,
  type AnalysisResult,
  foundInPicture,
  rateLimited,
} from "./reply";

const RESULT: AnalysisResult = {
  id: "abc123abc123",
  verdict: "no_red_flags",
  headline: "No red flags found. That is not a guarantee.",
  observations: ["Not listed by Google Safe Browsing, URLhaus or OpenPhish"],
  url_defanged: "hxxps://example[.]com",
  final_url_defanged: "hxxps://example[.]com/",
  loaded: true,
  screenshot_url: "/shots/abc123abc123.png",
};

function recorder(): { out: Outbox; sent: string[] } {
  const sent: string[] = [];
  return {
    sent,
    out: {
      sendText: async (text) => void sent.push(`text:${text}`),
      sendImage: async (bytes, name, mime) => void sent.push(`image:${name}:${mime}:${bytes.length}`),
    },
  };
}

function fakeAnalyzer(
  overrides: Partial<Analyzer> = {},
): Analyzer & { asked: string[]; senders: unknown[]; replies: unknown[]; alerts: unknown[] } {
  const asked: string[] = [];
  const senders: unknown[] = [];
  const replies: unknown[] = [];
  const alerts: unknown[] = [];
  return {
    asked,
    senders,
    replies,
    alerts,
    guardianAlerted: async (scan, guardian, sender) => void alerts.push({ scan, guardian, sender }),
    analyze: async (url, sender) => {
      asked.push(url);
      senders.push(sender);
      return RESULT;
    },
    replySent: async (scan, sender) => void replies.push({ scan, sender }),
    fetchScreenshot: async () => Buffer.from([1, 2, 3, 4]),
    readImage: async () => ({ status: "ok", urls: [] }),
    ...overrides,
  };
}

test("acknowledgment first, then the screenshot, then the verdict", async () => {
  const { out, sent } = recorder();
  const analyzer = fakeAnalyzer();
  await handleInbound({ kind: "text", text: "pay now https://ezpass-pay.top/x" }, out, analyzer);

  assert.deepEqual(analyzer.asked, ["https://ezpass-pay.top/x"]);
  assert.equal(sent.length, 3);
  assert.equal(sent[0], `text:${OPENING}`);
  assert.equal(sent[1], "image:abc123abc123.png:image/png:4");
  assert.ok(sent[2].startsWith("text:Phish Finder: NO RED FLAGS"));
  assert.ok(!sent[2].includes("https://"));
});

test("the verdict message ends with the report link when PUBLIC_URL is given", async () => {
  const { out, sent } = recorder();
  await handleInbound({ kind: "text", text: "https://example.com" }, out, fakeAnalyzer(), "https://host.example");
  assert.ok(sent.at(-1)!.endsWith("\n\nFull report: https://host.example/r/abc123abc123"));
});

test("there is no report line, and nothing breaks, without PUBLIC_URL", async () => {
  const { out, sent } = recorder();
  await handleInbound({ kind: "text", text: "https://example.com" }, out, fakeAnalyzer(), undefined);
  assert.equal(sent.length, 3);
  assert.ok(!sent.at(-1)!.includes("Full report"));
});

test("a message with no link gets the how-to reply and nothing is analyzed", async () => {
  const { out, sent } = recorder();
  const analyzer = fakeAnalyzer();
  await handleInbound({ kind: "text", text: "hello?" }, out, analyzer);
  assert.deepEqual(sent, [`text:${NO_URL}`]);
  assert.deepEqual(analyzer.asked, []);
});

function picture(bytes = [9, 9, 9], size?: number, mimeType = "image/png") {
  return { mimeType, size, read: async () => Buffer.from(bytes) };
}

test("a picture with a link in it: the link is read, shown defanged, then scanned like any other", async () => {
  const { out, sent } = recorder();
  const read: [number, string][] = [];
  const analyzer = fakeAnalyzer({
    readImage: async (bytes, mime) => {
      read.push([bytes.length, mime]);
      return { status: "ok", urls: ["https://usps-track.top/x"] };
    },
  });
  await handleInbound({ kind: "image", pictures: [picture([1, 2, 3, 4, 5])] }, out, analyzer);
  assert.deepEqual(read, [[5, "image/png"]]);
  assert.deepEqual(analyzer.asked, ["https://usps-track.top/x"]);
  assert.equal(sent[0], `text:${READING_PICTURE}`);
  assert.equal(sent[1], `text:${foundInPicture("https://usps-track.top/x")}`);
  assert.ok(!sent[1].includes("https://"));
  assert.ok(sent.at(-1)!.startsWith("text:Phish Finder:"));
});

test("a QR photo sent with words but no link is read too", async () => {
  const { out } = recorder();
  const analyzer = fakeAnalyzer({ readImage: async () => ({ status: "ok", urls: ["https://parking-pay.top/q"] }) });
  await handleInbound({ kind: "text", text: "is this real?", hasImage: true, pictures: [picture()] }, out, analyzer);
  assert.deepEqual(analyzer.asked, ["https://parking-pay.top/q"]);
});

test("a link in the words wins: the picture is not read", async () => {
  const { out } = recorder();
  let read = 0;
  const analyzer = fakeAnalyzer({
    readImage: async () => {
      read++;
      return { status: "ok", urls: ["https://other.example"] };
    },
  });
  await handleInbound({ kind: "text", text: "https://a.example", hasImage: true, pictures: [picture()] }, out, analyzer);
  assert.equal(read, 0);
  assert.deepEqual(analyzer.asked, ["https://a.example"]);
});

test("a picture with no link says so and scans nothing", async () => {
  const { out, sent } = recorder();
  const analyzer = fakeAnalyzer();
  await handleInbound({ kind: "image", pictures: [picture()] }, out, analyzer);
  assert.deepEqual(sent, [`text:${READING_PICTURE}`, `text:${NO_LINK_IN_PICTURE}`]);
  assert.deepEqual(analyzer.asked, []);
});

test("when pictures cannot be read (no key, Gemini down) the reply says so and nothing is scanned", async () => {
  const { out, sent } = recorder();
  const analyzer = fakeAnalyzer({ readImage: async () => ({ status: "unavailable", urls: [] }) });
  await handleInbound({ kind: "image", pictures: [picture()] }, out, analyzer);
  assert.deepEqual(sent, [`text:${READING_PICTURE}`, `text:${PICTURE_UNAVAILABLE}`]);
  assert.deepEqual(analyzer.asked, []);
});

test("a picture whose bytes cannot be had, or are too large, is never sent for reading", async () => {
  const { out, sent } = recorder();
  let read = 0;
  const analyzer = fakeAnalyzer({
    readImage: async () => {
      read++;
      return { status: "ok", urls: [] };
    },
  });
  const huge = picture([1], 50 * 1024 * 1024);
  const broken = { mimeType: "image/png", read: async () => Promise.reject(new Error("gone")) };
  await handleInbound({ kind: "image", pictures: [huge, broken] }, out, analyzer);
  assert.equal(read, 0);
  assert.deepEqual(sent, [`text:${READING_PICTURE}`, `text:${PICTURE_UNAVAILABLE}`]);
});

test("an image the platform gave us no way to read is the plain unavailable reply", async () => {
  const { out, sent } = recorder();
  await handleInbound({ kind: "image" }, out, fakeAnalyzer());
  assert.deepEqual(sent, [`text:${PICTURE_UNAVAILABLE}`]);
});

test("the analyzer being down while reading a picture is the honest down message", async () => {
  const { out, sent } = recorder();
  const analyzer = fakeAnalyzer({
    readImage: async () => {
      throw new AnalyzerUnreachable("http://127.0.0.1:8001", "unreachable");
    },
  });
  await handleInbound({ kind: "image", pictures: [picture()] }, out, analyzer);
  assert.deepEqual(sent, [`text:${READING_PICTURE}`, `text:${ANALYZER_DOWN}`]);
});

test("ignored content sends nothing", async () => {
  const { out, sent } = recorder();
  await handleInbound({ kind: "ignore" }, out, fakeAnalyzer());
  assert.deepEqual(sent, []);
});

test("analyzer down: acknowledgment, then one honest message, no verdict", async () => {
  const { out, sent } = recorder();
  const analyzer = fakeAnalyzer({
    analyze: async () => {
      throw new AnalyzerUnreachable("http://127.0.0.1:8001", "unreachable");
    },
  });
  await handleInbound({ kind: "text", text: "https://example.com" }, out, analyzer);
  assert.deepEqual(sent, [`text:${OPENING}`, `text:${ANALYZER_DOWN}`]);
});

test("a screenshot that cannot be fetched does not stop the verdict", async () => {
  const { out, sent } = recorder();
  const analyzer = fakeAnalyzer({
    fetchScreenshot: async () => {
      throw new Error("screenshot returned 404");
    },
  });
  await handleInbound({ kind: "text", text: "https://example.com" }, out, analyzer);
  assert.equal(sent.length, 2);
  assert.ok(sent[1].startsWith("text:Phish Finder:"));
});

test("no screenshot to send when the analyzer has none", async () => {
  const { out, sent } = recorder();
  const analyzer = fakeAnalyzer({ analyze: async () => ({ ...RESULT, screenshot_url: null, loaded: false, verdict: "couldnt_check" }) });
  await handleInbound({ kind: "text", text: "https://example.com" }, out, analyzer);
  assert.equal(sent.length, 2);
  assert.ok(sent[1].includes("COULDN'T CHECK"));
});

test("with several links, the first is checked and the user is told", async () => {
  const { out, sent } = recorder();
  const analyzer = fakeAnalyzer();
  await handleInbound({ kind: "text", text: "https://a.example/x and https://b.example/y" }, out, analyzer);
  assert.deepEqual(analyzer.asked, ["https://a.example/x"]);
  assert.equal(sent.at(-1), `text:${ONE_AT_A_TIME}`);
});

// --- Rate limit and sender privacy --------------------------------------------------------------

const NUMBER = "+1 (919) 555-4412";

function policyFor(raw: string, limiter: RateLimiter) {
  const sender = createHasher("a-long-enough-test-salt-0123456789", () => {}).identify(raw);
  return { sender, label: label(sender), limit: limiter.limit, take: () => limiter.take(sender.hash) };
}

test("the eleventh check in an hour gets the friendly reply and no scan", async () => {
  const limiter = new RateLimiter(10);
  const analyzer = fakeAnalyzer();
  const policy = policyFor(NUMBER, limiter);
  for (let i = 0; i < 10; i++) await handleInbound({ kind: "text", text: "https://example.com" }, recorder().out, analyzer, undefined, policy);
  assert.equal(analyzer.asked.length, 10);

  const { out, sent } = recorder();
  await handleInbound({ kind: "text", text: "https://example.com" }, out, analyzer, undefined, policy);
  assert.equal(analyzer.asked.length, 10); // nothing more was scanned
  assert.equal(sent.length, 1);
  assert.match(sent[0], /^text:You.ve used your 10 checks for this hour./);
  assert.match(sent[0], /about \d+ minutes?/);
  assert.ok(!/safe/i.test(sent[0].replace("Phish Finder", "")));
});

test("pictures count too, and so does the second sender separately", async () => {
  const limiter = new RateLimiter(1);
  const analyzer = fakeAnalyzer({ readImage: async () => ({ status: "ok", urls: [] }) });
  const mine = policyFor(NUMBER, limiter);
  const other = policyFor("+1 919 555 0000", limiter);
  const pic = { mimeType: "image/png", read: async () => Buffer.from([1]) };
  await handleInbound({ kind: "image", pictures: [pic] }, recorder().out, analyzer, undefined, mine);
  const { out, sent } = recorder();
  await handleInbound({ kind: "image", pictures: [pic] }, out, analyzer, undefined, mine);
  assert.match(sent[0], /used your 1 checks/);
  const second = recorder();
  await handleInbound({ kind: "image", pictures: [pic] }, second.out, analyzer, undefined, other);
  assert.equal(second.sent[0], `text:${READING_PICTURE}`);
});

test("messages that start no check (how-to, ignored) are not counted", async () => {
  const limiter = new RateLimiter(1);
  const policy = policyFor(NUMBER, limiter);
  const analyzer = fakeAnalyzer();
  await handleInbound({ kind: "text", text: "hello" }, recorder().out, analyzer, undefined, policy);
  await handleInbound({ kind: "ignore" }, recorder().out, analyzer, undefined, policy);
  const { sent } = recorder();
  await handleInbound({ kind: "text", text: "https://example.com" }, recorder().out, analyzer, undefined, policy);
  assert.equal(analyzer.asked.length, 1);
  assert.equal(sent.length, 0);
});

test("the wait is stated in whole minutes, at least one", () => {
  assert.match(rateLimited(10, 90_000), /about 2 minutes/);
  assert.match(rateLimited(10, 5_000), /about 1 minute\./);
});

test("no raw number reaches a log line, even when the analyzer fails with it in the message", async () => {
  const lines: string[] = [];
  const originals = { log: console.log, error: console.error, warn: console.warn };
  console.log = (...a: unknown[]) => void lines.push(a.map(String).join(" "));
  console.error = (...a: unknown[]) => void lines.push(a.map(String).join(" "));
  try {
    const limiter = new RateLimiter(1);
    const policy = policyFor(NUMBER, limiter);
    const analyzer = fakeAnalyzer({
      fetchScreenshot: async () => {
        throw new Error("could not deliver to +1 (919) 555-4412 / me@example.com");
      },
    });
    await handleInbound({ kind: "text", text: "https://example.com" }, recorder().out, analyzer, undefined, policy);
    await handleInbound({ kind: "text", text: "https://example.com" }, recorder().out, analyzer, undefined, policy); // limited
  } finally {
    Object.assign(console, originals);
  }
  const joined = lines.join("\n");
  assert.match(joined, /rate limited [0-9a-f]{8} •••-4412/);
  assert.match(joined, /checking hxxps:\/\/example\[\.\]com for [0-9a-f]{8} •••-4412/);
  assert.ok(!/919|555-4412|5554412|me@example/.test(joined), joined);
});

test("the analyzer is given the hash and last four digits, and told when the reply went out", async () => {
  const analyzer = fakeAnalyzer();
  const policy = policyFor(NUMBER, new RateLimiter(10));
  const { out, sent } = recorder();
  const order: string[] = [];
  const spied = { ...analyzer, replySent: async (scan: string, sender?: unknown) => {
    order.push(`replySent after ${sent.length} messages`);
    await analyzer.replySent(scan, sender as never);
  } };
  await handleInbound({ kind: "text", text: "https://example.com" }, out, spied, undefined, policy);
  assert.deepEqual(analyzer.senders, [policy.sender]);
  assert.deepEqual(Object.keys(policy.sender).sort(), ["hash", "last4"]);
  assert.equal(policy.sender.last4, "4412");
  assert.ok(!JSON.stringify(analyzer.senders).includes("555"));
  assert.deepEqual(analyzer.replies, [{ scan: "abc123abc123", sender: policy.sender }]);
  assert.deepEqual(order, ["replySent after 3 messages"]); // acknowledgment, screenshot, verdict: then the event
});

test("a link read from a picture also carries the sender and reports its reply", async () => {
  const analyzer = fakeAnalyzer({ readImage: async () => ({ status: "ok", urls: ["https://usps-track.top/x"] }) });
  const policy = policyFor(NUMBER, new RateLimiter(10));
  await handleInbound({ kind: "image", pictures: [picture()] }, recorder().out, analyzer, undefined, policy);
  assert.deepEqual(analyzer.senders, [policy.sender]);
  assert.equal(analyzer.replies.length, 1);
});

test("a limited message produces no scan and no reply event", async () => {
  const analyzer = fakeAnalyzer();
  const policy = policyFor(NUMBER, new RateLimiter(1));
  await handleInbound({ kind: "text", text: "https://a.example" }, recorder().out, analyzer, undefined, policy);
  await handleInbound({ kind: "text", text: "https://b.example" }, recorder().out, analyzer, undefined, policy);
  assert.equal(analyzer.asked.length, 1);
  assert.equal(analyzer.replies.length, 1);
});
