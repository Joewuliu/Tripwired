import assert from "node:assert/strict";
import { test } from "node:test";
import { type Analyzer, AnalyzerUnreachable } from "./analyzer";
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

function fakeAnalyzer(overrides: Partial<Analyzer> = {}): Analyzer & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    analyze: async (url) => {
      asked.push(url);
      return RESULT;
    },
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
  assert.ok(sent[2].startsWith("text:Tripwire: NO RED FLAGS"));
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
  assert.ok(sent.at(-1)!.startsWith("text:Tripwire:"));
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
  assert.ok(sent[1].startsWith("text:Tripwire:"));
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
