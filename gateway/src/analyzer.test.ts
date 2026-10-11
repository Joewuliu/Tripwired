import assert from "node:assert/strict";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, test } from "node:test";
import { AnalyzerUnreachable, createAnalyzer } from "./analyzer";

const GOOD = {
  id: "abc123abc123",
  verdict: "suspicious",
  headline: "Suspicious: Registered 2 days ago, from RDAP",
  observations: ["Registered 2 days ago, from RDAP"],
  url_defanged: "hxxps://example[.]com",
  final_url_defanged: "hxxps://example[.]com/",
  loaded: true,
  screenshot_url: "/shots/abc123abc123.png",
};

let server: Server | undefined;
afterEach(() => server?.close());

async function start(handler: Parameters<typeof createServer>[1]): Promise<string> {
  server = createServer(handler);
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

test("analyze posts the url and parses the result", async () => {
  let seen = "";
  const base = await start((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      seen = `${req.method} ${req.url} ${body}`;
      res.setHeader("content-type", "application/json").end(JSON.stringify(GOOD));
    });
  });
  const result = await createAnalyzer(base).analyze("https://example.com");
  assert.equal(seen, 'POST /analyze {"urls":["https://example.com"]}');
  assert.equal(result.verdict, "suspicious");
  assert.equal(result.screenshot_url, "/shots/abc123abc123.png");
});

test("a response missing required fields is rejected", async () => {
  const base = await start((_req, res) => void res.setHeader("content-type", "application/json").end("{}"));
  await assert.rejects(createAnalyzer(base).analyze("https://example.com"), /unexpected analyzer response/);
});

test("a non-200 reply is an error", async () => {
  const base = await start((_req, res) => void res.writeHead(500).end());
  await assert.rejects(createAnalyzer(base).analyze("https://example.com"), /analyzer returned 500/);
});

test("nobody listening is AnalyzerUnreachable", async () => {
  const base = await start((_req, res) => void res.end());
  await new Promise((resolve) => server!.close(resolve)); // the port is now free and closed
  await assert.rejects(createAnalyzer(base).analyze("https://example.com"), AnalyzerUnreachable);
});

test("fetchScreenshot returns the bytes", async () => {
  const base = await start((_req, res) => void res.end(Buffer.from([1, 2, 3])));
  const bytes = await createAnalyzer(base).fetchScreenshot("/shots/abc123abc123.png");
  assert.deepEqual([...bytes], [1, 2, 3]);
});

test("fetchScreenshot refuses an address on another host", async () => {
  await assert.rejects(
    createAnalyzer("http://127.0.0.1:8001").fetchScreenshot("http://169.254.169.254/x.png"),
    /not on the analyzer/,
  );
});

test("readImage posts the picture as base64 and returns what was found", async () => {
  let seen: { mime_type?: string; data_base64?: string; url?: string } = {};
  const base = await start((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      seen = { ...JSON.parse(body), url: req.url };
      res.setHeader("content-type", "application/json").end(JSON.stringify({ status: "ok", urls: ["https://a.example/x", 7] }));
    });
  });
  const reading = await createAnalyzer(base).readImage(Buffer.from([1, 2, 3]), "image/jpeg");
  assert.equal(seen.url, "/read-image");
  assert.equal(seen.mime_type, "image/jpeg");
  assert.equal(seen.data_base64, "AQID");
  assert.deepEqual(reading, { status: "ok", urls: ["https://a.example/x"] });
});

test("readImage: an unexpected status is treated as unavailable", async () => {
  const base = await start((_req, res) => void res.setHeader("content-type", "application/json").end(JSON.stringify({ status: "weird", urls: [] })));
  assert.deepEqual(await createAnalyzer(base).readImage(Buffer.from([1]), "image/png"), { status: "unavailable", urls: [] });
});

test("analyze sends the sender as hash and last four digits only", async () => {
  let body = "";
  const base = await start((req, res) => {
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => res.setHeader("content-type", "application/json").end(JSON.stringify(GOOD)));
  });
  await createAnalyzer(base).analyze("https://example.com", { hash: "3f9a1c2e7b4d5a60", last4: "4412" });
  assert.deepEqual(JSON.parse(body), {
    urls: ["https://example.com"],
    sender: { hash: "3f9a1c2e7b4d5a60", last4: "4412" },
  });
});

test("replySent posts the scan id and sender to the internal route, and never throws", async () => {
  let seen = "";
  const base = await start((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      seen = `${req.method} ${req.url} ${body}`;
      res.writeHead(204).end();
    });
  });
  await createAnalyzer(base).replySent("abc123abc123", { hash: "3f9a1c2e7b4d5a60", last4: null });
  assert.equal(seen, `POST /internal/reply-sent {"scan":"abc123abc123","sender":{"hash":"3f9a1c2e7b4d5a60","last4":null}}`);
  await new Promise((resolve) => server!.close(resolve));
  await createAnalyzer(base).replySent("abc123abc123"); // nobody is listening: still fine
});
