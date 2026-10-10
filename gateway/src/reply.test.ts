import assert from "node:assert/strict";
import { test } from "node:test";
import { type AnalysisResult, defangText, formatReply } from "./reply";

function result(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    id: "abc123abc123",
    verdict: "dangerous",
    headline: "Dangerous: Listed as phishing by OpenPhish",
    observations: ["Listed as phishing by OpenPhish", "Registered 2 days ago, from RDAP", "Asks for a password"],
    url_defanged: "hxxps://short[.]example/x",
    final_url_defanged: "hxxps://ezpass-pay[.]top/pay",
    loaded: true,
    screenshot_url: "/shots/abc123abc123.png",
    ...overrides,
  };
}

test("defangText defangs schemes and link-looking text", () => {
  assert.equal(defangText("go to https://evil.example.com/a now"), "go to hxxps://evil[.]example[.]com/a now");
  assert.equal(defangText("or evil.example.com/login"), "or evil[.]example[.]com/login");
});

test("defangText leaves ordinary sentences and already-defanged links alone", () => {
  assert.equal(defangText("Mr. Smith said hello."), "Mr. Smith said hello.");
  assert.equal(defangText("hxxps://ezpass-pay[.]top/pay"), "hxxps://ezpass-pay[.]top/pay");
});

test("a dangerous reply has a label, headline, up to three bullets, an action and the link", () => {
  const reply = formatReply(result());
  const lines = reply.split("\n");
  assert.equal(lines[0], "Tripwire: DANGEROUS");
  assert.equal(lines[1], "Dangerous: Listed as phishing by OpenPhish");
  assert.ok(!reply.includes("- Listed as phishing by OpenPhish"), "headline's reason is not repeated");
  assert.ok(reply.includes("- Registered 2 days ago, from RDAP"));
  assert.ok(reply.includes("Don't enter anything, and don't tap the link."));
  assert.equal(lines.at(-1), "Link opened: hxxps://ezpass-pay[.]top/pay");
});

test("at most three observations are shown", () => {
  const many = Array.from({ length: 6 }, (_, i) => `Observation number ${i}`);
  const bullets = formatReply(result({ headline: "Suspicious: x", verdict: "suspicious", observations: many }))
    .split("\n")
    .filter((line) => line.startsWith("- "));
  assert.equal(bullets.length, 3);
});

test("a link that did not load says 'Link we tried' and shows the original address", () => {
  const reply = formatReply(
    result({ verdict: "couldnt_check", loaded: false, final_url_defanged: null, observations: [] }),
  );
  assert.ok(reply.includes("Tripwire: COULDN'T CHECK"));
  assert.ok(reply.endsWith("Link we tried: hxxps://short[.]example/x"));
});

test("the placeholder verdict is shown as no verdict yet", () => {
  const reply = formatReply(result({ verdict: "unscored", headline: "Opened in the sandbox. No verdict yet." }));
  assert.ok(reply.startsWith("Tripwire: OPENED, NO VERDICT YET"));
});

test("an unknown verdict is treated as could not check, never as clear", () => {
  const reply = formatReply(result({ verdict: "banana" }));
  assert.ok(reply.includes("COULDN'T CHECK"));
  assert.ok(!reply.includes("NO RED FLAGS"));
});

test("a clean verdict says no red flags and never 'safe'", () => {
  const reply = formatReply(result({ verdict: "no_red_flags", headline: "No red flags found.", observations: [] }));
  assert.ok(reply.startsWith("Tripwire: NO RED FLAGS"));
  assert.ok(!/\bsafe\b/i.test(reply), "the gateway's own wording never calls a link safe");
});

test("a live link in the analyzer's text is defanged on the way out", () => {
  const reply = formatReply(result({ observations: ["Redirects to https://evil.example.com/x"] }));
  assert.ok(!reply.includes("https://"));
  assert.ok(reply.includes("hxxps://evil[.]example[.]com/x"));
});
