import assert from "node:assert/strict";
import { test } from "node:test";
import { type Analyzer, AnalyzerUnreachable } from "./analyzer";
import { type Outbox, handleInbound } from "./handler";
import { ANALYZER_DOWN, IMAGE_SOON, NO_URL, ONE_AT_A_TIME, OPENING, type AnalysisResult } from "./reply";

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
  assert.ok(sent.at(-1)!.endsWith("\n\nFull report: https://host.example/api/report/abc123abc123"));
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

test("text with a picture but no link says image checking is coming soon", async () => {
  const { out, sent } = recorder();
  await handleInbound({ kind: "text", text: "is this real?", hasImage: true }, out, fakeAnalyzer());
  assert.deepEqual(sent, [`text:${IMAGE_SOON}`]);
});

test("an image says it is coming soon", async () => {
  const { out, sent } = recorder();
  await handleInbound({ kind: "image" }, out, fakeAnalyzer());
  assert.deepEqual(sent, [`text:${IMAGE_SOON}`]);
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
