import assert from "node:assert/strict";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, test } from "node:test";
import { AnalyzerUnreachable, createAnalyzer } from "./analyzer";

const GOOD = {
  id: "abc123abc123",
  verdict: "unscored",
  headline: "Opened in the sandbox.",
  observations: ["one"],
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
  assert.equal(result.verdict, "unscored");
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
