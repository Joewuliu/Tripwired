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

test("an unknown verdict is treated as could not check, never as clear", () => {
  for (const verdict of ["banana", "unscored", "safe", "constructor", "toString", ""]) {
    const reply = formatReply(result({ verdict }));
    assert.ok(reply.includes("COULDN'T CHECK"), verdict);
    assert.ok(!reply.includes("NO RED FLAGS"), verdict);
  }
});

// What the analyzer really sends for each verdict (see analyzer/score.py), as the phone shows it.
const REAL: Record<string, Partial<AnalysisResult>> = {
  dangerous: {
    verdict: "dangerous",
    headline: "Dangerous: Listed as phishing by OpenPhish",
    observations: ["Listed as phishing by OpenPhish", "Registered 2 days ago, from RDAP", "Page asks for card details (page scan)"],
  },
  suspicious: {
    verdict: "suspicious",
    headline: "Suspicious: Web address uses the name Chase but is not an official site (brand list)",
    observations: ["Web address uses the name Chase but is not an official site (brand list)", "Not listed by Google Safe Browsing, URLhaus or OpenPhish"],
  },
  no_red_flags: {
    verdict: "no_red_flags",
    headline: "No red flags found. That is not a guarantee.",
    observations: ["Registered domain is official for Chase (brand list)", "Not listed by Google Safe Browsing, URLhaus or OpenPhish"],
  },
  couldnt_check: {
    verdict: "couldnt_check",
    headline: "Couldn't get a proper look at this link. Don't enter anything until you verify it another way.",
    observations: ["The site refused the sandbox's phone browser (HTTP 403)"],
    loaded: true,
  },
};
const LABEL: Record<string, string> = {
  dangerous: "Tripwire: DANGEROUS",
  suspicious: "Tripwire: SUSPICIOUS",
  no_red_flags: "Tripwire: NO RED FLAGS",
  couldnt_check: "Tripwire: COULDN'T CHECK",
};

for (const [verdict, fields] of Object.entries(REAL)) {
  test(`the ${verdict} reply says exactly that, and never claims a link is safe`, () => {
    const reply = formatReply(result(fields));
    assert.equal(reply.split("\n")[0], LABEL[verdict]);
    for (const [other, label] of Object.entries(LABEL)) {
      if (other !== verdict) assert.ok(!reply.includes(label), `${verdict} reply must not carry the ${other} label`);
    }
    const claim = reply.toLowerCase().replace("google safe browsing", ""); // a product name, not a claim
    assert.ok(!/\bsafe/.test(claim), reply); // not "safe", "safely", "safety"
  });
}

test("a page we could not inspect shows why, and which link was tried rather than 'opened'", () => {
  const reply = formatReply(result(REAL.couldnt_check));
  assert.ok(reply.includes("- The site refused the sandbox's phone browser (HTTP 403)"));
  assert.ok(reply.endsWith("Link we tried: hxxps://short[.]example/x"));
});

test("a clean reply is not a green light: it carries the caveat and the official-site advice", () => {
  const reply = formatReply(result(REAL.no_red_flags));
  assert.ok(reply.includes("That is not a guarantee."));
  assert.ok(reply.includes("go to the official site yourself"));
});

test("a live link in the analyzer's text is defanged on the way out", () => {
  const reply = formatReply(result({ observations: ["Redirects to https://evil.example.com/x"] }));
  assert.ok(!reply.includes("https://"));
  assert.ok(reply.includes("hxxps://evil[.]example[.]com/x"));
});
