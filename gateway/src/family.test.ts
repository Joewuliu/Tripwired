import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCommand } from "./commands";
import { COOLDOWN_MS, Family, INVITE_TTL_MS, type Person, defangedDomain } from "./family";
import type { Persistence } from "./familyStore";
import { type Outbox, handleInbound } from "./handler";
import type { AnalysisResult } from "./reply";
import { createHasher } from "./sender";

const HOUR = 60 * 60 * 1000;
const hasher = createHasher("a-long-enough-test-salt-0123456789", () => {});
const YOU = "+19195554412"; // the guardian
const GRANDMA = "+19195550142"; // the protected person
const HOST = "https://tripwire.example";

const DANGEROUS: AnalysisResult = {
  id: "abc123abc123",
  verdict: "dangerous",
  headline: "Dangerous: Listed as phishing by OpenPhish",
  observations: ["Listed as phishing by OpenPhish"],
  url_defanged: "hxxps://short[.]example/x",
  final_url_defanged: "hxxps://ezpass-pay[.]top/pay",
  loaded: true,
  screenshot_url: null,
};

function person(address: string): Person {
  return { ...hasher.identify(address), address };
}

/** A family service with a clock we move, a store in memory, and every message it sends recorded. */
function world(initial: string | null = null) {
  const file = { text: initial };
  const persistence: Persistence = { read: () => file.text, write: (text) => void (file.text = text) };
  const clock = { now: 1_000_000_000_000 };
  const sent: { to: string; text: string }[] = [];
  const unreachable = new Set<string>();
  const courier = {
    sendTo: async (to: string, text: string) => {
      if (unreachable.has(to)) throw new Error(`cannot deliver to ${to}`);
      sent.push({ to, text });
    },
  };
  const family = new Family(persistence, courier, (raw) => hasher.identify(raw), () => clock.now);
  async function say(from: string, text: string): Promise<string> {
    const replies: string[] = [];
    const command = parseCommand(text);
    assert.ok(command, `"${text}" should be a command`);
    await family.command(person(from), command, async (reply) => void replies.push(reply));
    assert.equal(replies.length, 1, "exactly one reply to the person who wrote");
    return replies[0];
  }
  const to = (address: string) => sent.filter((m) => m.to === address).map((m) => m.text);
  return { family, say, sent, to, clock, file, unreachable, persistence, courier };
}

async function linked() {
  const w = world();
  await w.say(YOU, "protect +1 919 555 0142");
  await w.say(GRANDMA, "YES");
  w.sent.length = 0;
  return w;
}

// --- consent -----------------------------------------------------------------------------------

test("protect sends an invite with the guardian masked, and links nothing", async () => {
  const w = world();
  const reply = await w.say(YOU, "protect +1 919 555 0142");
  assert.match(reply, /Invite sent to •••-0142\. It's pending/);
  assert.equal(w.sent.length, 1);
  assert.equal(w.sent[0].to, GRANDMA);
  assert.match(w.sent[0].text, /someone at •••-4412 asked/);
  assert.match(w.sent[0].text, /Reply YES to agree, or ignore this message/);
  assert.ok(!w.sent[0].text.includes("9195554412"));
  assert.deepEqual(await w.family.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST), []); // not linked yet
});

test("YES links both and tells both; only then do alerts flow", async () => {
  const w = world();
  await w.say(YOU, "protect (919) 555-0142");
  const reply = await w.say(GRANDMA, "yes");
  assert.match(reply, /You're linked\. •••-4412 will get an alert only when a link you forward is rated Dangerous/);
  assert.match(reply, /Text STOP any time/);
  assert.match(w.to(YOU).at(-1)!, /•••-0142 said YES/);
  const told = await w.family.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST);
  assert.deepEqual(told, [hasher.identify(YOU)]);
});

test("YES with nothing pending links nothing", async () => {
  const w = world();
  assert.match(await w.say(GRANDMA, "YES"), /no request waiting/);
  assert.equal(w.sent.length, 0);
});

test("someone else saying YES does not accept an invite meant for another number", async () => {
  const w = world();
  await w.say(YOU, "protect +1 919 555 0142");
  assert.match(await w.say("+19195559999", "YES"), /no request waiting/);
  assert.deepEqual(await w.family.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST), []);
});

test("you cannot protect yourself, and a bad number gets the how-to", async () => {
  const w = world();
  assert.match(await w.say(YOU, "protect 919-555-4412"), /your own number/);
  assert.match(await w.say(YOU, "protect grandma"), /text: protect and their mobile number/);
  assert.equal(w.sent.length, 0);
});

// --- expiry and cooldown -------------------------------------------------------------------------

test("an invite expires after 24 hours: a late YES does nothing", async () => {
  const w = world();
  await w.say(YOU, "protect +1 919 555 0142");
  w.clock.now += INVITE_TTL_MS + 1;
  assert.match(await w.say(GRANDMA, "YES"), /no request waiting/);
  assert.deepEqual(await w.family.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST), []);
});

test("after an ignored invite the same guardian must wait 24 more hours; another guardian need not", async () => {
  const w = world();
  await w.say(YOU, "protect +1 919 555 0142");
  w.clock.now += INVITE_TTL_MS + 1;
  assert.match(await w.say(YOU, "protect +1 919 555 0142"), /didn't agree last time.*can't ask them again for about 24 hours/);
  assert.equal(w.to(GRANDMA).length, 1); // no second invite reached them
  assert.match(await w.say("+19195557777", "protect +1 919 555 0142"), /Invite sent/);
  w.clock.now += COOLDOWN_MS + 1;
  assert.match(await w.say(YOU, "protect +1 919 555 0142"), /Invite sent/);
});

test("STOP to an invite declines it and starts the same wait", async () => {
  const w = world();
  await w.say(YOU, "protect +1 919 555 0142");
  assert.match(await w.say(GRANDMA, "STOP"), /Done\./);
  assert.match(await w.say(GRANDMA, "YES"), /no request waiting/);
  assert.match(await w.say(YOU, "protect +1 919 555 0142"), /can't ask them again/);
});

// --- stopping, from either side ------------------------------------------------------------------

test("STOP from the protected person unlinks at once and tells the guardian", async () => {
  const w = await linked();
  assert.match(await w.say(GRANDMA, "stop"), /nobody gets alerts about your links/);
  assert.deepEqual(w.to(YOU), ["Phish Finder: •••-0142 turned off alerts. You're no longer linked."]);
  assert.deepEqual(await w.family.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST), []);
  assert.match(await w.say(YOU, "protect +1 919 555 0142"), /can't ask them again/); // and cannot be re-invited for a day
});

test("unprotect from the guardian unlinks and tells the protected person", async () => {
  const w = await linked();
  assert.match(await w.say(YOU, "unprotect +1 919 555 0142"), /no longer get alerts for •••-0142/);
  assert.deepEqual(w.to(GRANDMA), ["Phish Finder: •••-4412 will no longer get alerts about your links."]);
  assert.deepEqual(await w.family.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST), []);
  assert.match(await w.say(YOU, "unprotect +1 919 555 0142"), /aren't getting alerts/);
});

test("STOP from the guardian also ends their links, and tells the person", async () => {
  const w = await linked();
  await w.say(YOU, "STOP");
  assert.match(w.to(GRANDMA)[0], /•••-4412 will no longer get alerts/);
  assert.deepEqual(await w.family.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST), []);
});

test("unprotect cancels a pending invite; STOP with nothing to stop says so", async () => {
  const w = world();
  await w.say(YOU, "protect +1 919 555 0142");
  assert.match(await w.say(YOU, "unprotect 9195550142"), /invite to •••-0142 is cancelled/);
  assert.match(await w.say(GRANDMA, "YES"), /no request waiting/);
  assert.match(await w.say("+19195558888", "STOP"), /nothing to stop/);
});

// --- limits ----------------------------------------------------------------------------------------

test("a guardian can send three invites an hour", async () => {
  const w = world();
  for (const n of [1, 2, 3]) assert.match(await w.say(YOU, `protect +1 919 555 020${n}`), /Invite sent/);
  assert.match(await w.say(YOU, "protect +1 919 555 0204"), /3 invites an hour/);
  assert.equal(w.sent.length, 3);
  w.clock.now += HOUR + 1;
  assert.match(await w.say(YOU, "protect +1 919 555 0204"), /Invite sent/);
});

test("a guardian can protect at most five people, counting pending invites", async () => {
  const w = world();
  for (let n = 1; n <= 5; n++) {
    assert.match(await w.say(YOU, `protect +1 919 555 030${n}`), /Invite sent/);
    await w.say(`+1919555030${n}`, "YES");
    w.clock.now += 25 * 60 * 1000; // stay under three an hour
  }
  assert.match(await w.say(YOU, "protect +1 919 555 0306"), /up to 5 people/);
});

test("a person can have at most three guardians", async () => {
  const w = world();
  for (const n of [1, 2, 3]) {
    await w.say(`+1919555040${n}`, "protect +1 919 555 0142");
    await w.say(GRANDMA, "YES");
  }
  assert.match(await w.say("+19195550404", "protect +1 919 555 0142"), /can't be added right now/);
  assert.equal((await w.family.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST)).length, 3);
});

test("asking twice does not send a second invite", async () => {
  const w = world();
  await w.say(YOU, "protect +1 919 555 0142");
  assert.match(await w.say(YOU, "protect +1 919 555 0142"), /already been asked/);
  await w.say(GRANDMA, "YES");
  assert.match(await w.say(YOU, "protect +1 919 555 0142"), /already get alerts/);
  assert.equal(w.to(GRANDMA).length, 1);
});

test("an invite that cannot be delivered is not left pending", async () => {
  const w = world();
  w.unreachable.add(GRANDMA);
  assert.match(await w.say(YOU, "protect +1 919 555 0142"), /couldn't reach •••-0142/);
  w.unreachable.clear();
  assert.match(await w.say(GRANDMA, "YES"), /no request waiting/);
});

// --- alerts --------------------------------------------------------------------------------------

test("a Dangerous verdict alerts the guardian with the defanged site and our report link, nothing else", async () => {
  const w = await linked();
  await w.family.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST);
  assert.deepEqual(w.to(YOU), [
    "Heads up: •••-0142 was sent a dangerous link: ezpass-pay[.]top. " +
      "Report: https://tripwire.example/r/abc123abc123. They've been warned not to tap it.",
  ]);
  assert.equal(w.to(GRANDMA).length, 0);
});

test("no other verdict alerts anyone", async () => {
  const w = await linked();
  for (const verdict of ["suspicious", "no_red_flags", "couldnt_check", "safe", ""]) {
    assert.deepEqual(await w.family.alertGuardians(hasher.identify(GRANDMA), { ...DANGEROUS, verdict }, HOST), []);
  }
  assert.equal(w.sent.length, 0);
});

test("the alert never carries a live link to the scanned site, whatever the analyzer sent", async () => {
  const w = await linked();
  const sneaky = { ...DANGEROUS, final_url_defanged: "https://evil.example/login?next=1" };
  await w.family.alertGuardians(hasher.identify(GRANDMA), sneaky, undefined);
  const text = w.to(YOU)[0];
  assert.ok(!text.includes("https://") && !text.includes("evil.example"));
  assert.ok(!text.includes("Report:")); // no PUBLIC_URL: no report line, the alert still goes
});

test("the guardian's own links are not alerted about, only the protected person's", async () => {
  const w = await linked();
  assert.deepEqual(await w.family.alertGuardians(hasher.identify(YOU), DANGEROUS, HOST), []);
});

test("the site's name is taken from a defanged address", () => {
  assert.equal(defangedDomain("hxxps://ezpass-pay[.]top/pay?x=1"), "ezpass-pay[.]top");
  assert.equal(defangedDomain("hxxp://a[.]b[.]example"), "a[.]b[.]example");
});

// --- "family" ------------------------------------------------------------------------------------

test("family lists links from both sides with masked numbers only", async () => {
  const w = await linked();
  await w.say(YOU, "protect +1 919 555 0199");
  const mine = await w.say(YOU, "family");
  assert.match(mine, /You get alerts for: •••-0142, •••-0199 \(pending\)/);
  assert.match(await w.say(GRANDMA, "family"), /Alerts about your links go to: •••-4412/);
  assert.match(await w.say("+19195550199", "family"), /Waiting for your YES: •••-4412/);
  assert.match(await w.say("+19195558888", "family"), /You have no family links/);
  assert.ok(!/919555/.test(mine));
});

// --- storage and privacy ---------------------------------------------------------------------------

test("links survive a restart, and the store holds an address only while it is needed", async () => {
  const w = await linked();
  const again = new Family(w.persistence, w.courier, (raw) => hasher.identify(raw), () => w.clock.now);
  assert.equal((await again.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST)).length, 1);
  assert.ok(w.file.text!.includes(GRANDMA) && w.file.text!.includes(YOU)); // needed to send the alert
  await w.say(GRANDMA, "STOP");
  assert.ok(!/\+1919555/.test(w.file.text!)); // the link is gone, so are both numbers
});

test("a store that cannot be read starts empty instead of crashing", () => {
  const original = console.warn;
  console.warn = () => {};
  try {
    const w = world("{not json");
    assert.ok(w.family);
  } finally {
    console.warn = original;
  }
});

test("no raw number reaches a log line, even when a delivery fails with it in the error", async () => {
  const lines: string[] = [];
  const originals = { log: console.log, error: console.error };
  console.log = (...a: unknown[]) => void lines.push(a.map(String).join(" "));
  console.error = (...a: unknown[]) => void lines.push(a.map(String).join(" "));
  try {
    const w = world();
    await w.say(YOU, "protect +1 919 555 0142");
    await w.say(GRANDMA, "YES");
    await w.family.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST);
    w.unreachable.add(YOU);
    await w.family.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST);
    await w.say(GRANDMA, "STOP");
  } finally {
    Object.assign(console, originals);
  }
  const joined = lines.join("\n");
  assert.match(joined, /family invite from [0-9a-f]{8} •••-4412 to [0-9a-f]{8} •••-0142/);
  assert.match(joined, /family alert about [0-9a-f]{8} •••-0142 sent to [0-9a-f]{8} •••-4412/);
  assert.match(joined, /family message to [0-9a-f]{8} •••-4412 failed: cannot deliver to \[number\]/);
  assert.ok(!/919555|5554412|5550142/.test(joined), joined);
});

// --- through the message handler -------------------------------------------------------------------

function recorder(): { out: Outbox; sent: string[] } {
  const sent: string[] = [];
  return { sent, out: { sendText: async (text) => void sent.push(text), sendImage: async () => {} } };
}

function fakeAnalyzer(result: AnalysisResult) {
  const alerts: unknown[] = [];
  const asked: string[] = [];
  return {
    alerts,
    asked,
    analyze: async (url: string) => (asked.push(url), result),
    replySent: async () => {},
    guardianAlerted: async (scan: string, guardian: unknown, sender: unknown) => void alerts.push({ scan, guardian, sender }),
    readImage: async () => ({ status: "ok" as const, urls: [] }),
    fetchScreenshot: async () => Buffer.from([1]),
  };
}

test("a forwarded dangerous link: the person gets their verdict, the guardian an alert, the dashboard an event", async () => {
  const w = await linked();
  const analyzer = fakeAnalyzer(DANGEROUS);
  const { out, sent } = recorder();
  const me = person(GRANDMA);
  await handleInbound({ kind: "text", text: "is this real? https://short.example/x" }, out, analyzer, HOST, undefined, { service: w.family, me });
  assert.ok(sent.at(-1)!.startsWith("Phish Finder: DANGEROUS"));
  assert.equal(w.to(YOU).length, 1);
  assert.ok(!w.to(YOU)[0].includes("is this real")); // never the person's own words
  assert.deepEqual(analyzer.alerts, [{ scan: "abc123abc123", guardian: hasher.identify(YOU), sender: hasher.identify(GRANDMA) }]);
  assert.ok(!JSON.stringify(analyzer.alerts).includes("919555")); // hash and last four only
});

test("a forwarded link with any other verdict alerts nobody and emits nothing", async () => {
  const w = await linked();
  const analyzer = fakeAnalyzer({ ...DANGEROUS, verdict: "suspicious" });
  await handleInbound({ kind: "text", text: "https://short.example/x" }, recorder().out, analyzer, HOST, undefined, { service: w.family, me: person(GRANDMA) });
  assert.equal(w.sent.length, 0);
  assert.deepEqual(analyzer.alerts, []);
});

test("a command is answered as one and scans nothing; ordinary words still get the how-to, which mentions protect", async () => {
  const w = world();
  const analyzer = fakeAnalyzer(DANGEROUS);
  const first = recorder();
  await handleInbound({ kind: "text", text: "protect +1 919 555 0142" }, first.out, analyzer, HOST, undefined, { service: w.family, me: person(YOU) });
  assert.match(first.sent[0], /Invite sent to •••-0142/);
  const second = recorder();
  await handleInbound({ kind: "text", text: "hello?" }, second.out, analyzer, HOST, undefined, { service: w.family, me: person(YOU) });
  assert.match(second.sent[0], /Forward me a suspicious text or link/);
  assert.match(second.sent[0], /protect and their mobile number/);
  assert.deepEqual(analyzer.asked, []);
});

test("a message with YES and a link is a link to check, not consent", async () => {
  const w = world();
  await w.say(YOU, "protect +1 919 555 0142");
  const analyzer = fakeAnalyzer({ ...DANGEROUS, verdict: "no_red_flags" });
  await handleInbound({ kind: "text", text: "yes I got this https://short.example/x" }, recorder().out, analyzer, HOST, undefined, { service: w.family, me: person(GRANDMA) });
  assert.equal(analyzer.asked.length, 1);
  assert.deepEqual(await w.family.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST), []); // still not linked
});

test("the store is a real file: written whole, read back by a new process", async () => {
  const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { fileAt } = await import("./familyStore");
  const dir = mkdtempSync(join(tmpdir(), "tripwire-family-"));
  try {
    const path = join(dir, "nested", "family.json");
    const sent: string[] = [];
    const courier = { sendTo: async (_to: string, text: string) => void sent.push(text) };
    const first = new Family(fileAt(path), courier, (raw) => hasher.identify(raw));
    await first.command(person(YOU), { kind: "protect", number: "19195550142" }, async () => {});
    await first.command(person(GRANDMA), { kind: "yes" }, async () => {});
    assert.equal(JSON.parse(readFileSync(path, "utf8")).links.length, 1);
    const second = new Family(fileAt(path), courier, (raw) => hasher.identify(raw));
    assert.equal((await second.alertGuardians(hasher.identify(GRANDMA), DANGEROUS, HOST)).length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
