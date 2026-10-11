import type { Command } from "./commands";
import { type FamilyData, type Pair, type Persistence, loadFamily, saveFamily } from "./familyStore";
import { type AnalysisResult, defangText, reportLink } from "./reply";
import { type SenderId, label, mask, redact } from "./sender";

/**
 * Family mode: a guardian asks to be told when someone they care about is sent a dangerous link.
 *
 * Nothing is linked without the protected person's YES, and their STOP ends it at once. A guardian
 * is told one thing only: that a link rated Dangerous arrived, the site's name (defanged) and our
 * report. Never the person's messages, never any other verdict.
 */

export const INVITE_TTL_MS = 24 * 60 * 60 * 1000; // an unanswered invite lapses
export const COOLDOWN_MS = 24 * 60 * 60 * 1000; // before the same guardian may ask the same person again
export const INVITES_PER_HOUR = 3;
export const MAX_PROTECTED = 5; // people one guardian may protect (links and pending invites together)
export const MAX_GUARDIANS = 3; // guardians one person may have
const HOUR_MS = 60 * 60 * 1000;

/** The person a message came from: their hash and last four digits, and where to answer them. */
export interface Person extends SenderId {
  address: string;
}

/** Sends a text to someone we are not currently talking to (an invite, an alert). */
export interface Courier {
  sendTo(address: string, text: string): Promise<void>;
}

type Reply = (text: string) => Promise<void>;
type Identify = (raw: string) => SenderId;

const USAGE = "To protect someone, text: protect and their mobile number, like protect +1 919 555 0142";
const UNPROTECT_USAGE = "To stop, text: unprotect and their number, like unprotect +1 919 555 0142";

function hours(ms: number): string {
  const n = Math.max(1, Math.ceil(ms / HOUR_MS));
  return `${n} hour${n === 1 ? "" : "s"}`;
}

function same(a: Pair, b: Pair): boolean {
  return a.guardian === b.guardian && a.protected === b.protected;
}

/** The site's name from a defanged address: "hxxps://ezpass-pay[.]top/pay" -> "ezpass-pay[.]top". */
export function defangedDomain(urlDefanged: string): string {
  return urlDefanged.replace(/^hxxps?:\/\//i, "").split(/[/?#]/)[0];
}

export class Family {
  private data: FamilyData;

  constructor(
    private readonly persistence: Persistence,
    private readonly courier: Courier,
    private readonly identify: Identify,
    private readonly now: () => number = Date.now,
  ) {
    this.data = loadFamily(persistence);
  }

  // --- reading the store -----------------------------------------------------------------------

  private maskOf(hash: string): string {
    return mask({ hash, last4: this.data.people[hash]?.last4 ?? null });
  }

  private guardiansOf(hash: string): string[] {
    return this.data.links.filter((l) => l.protected === hash).map((l) => l.guardian);
  }

  /** Lapsed invites become a cooldown ("ignored"); spent cooldowns and unused addresses are dropped. */
  private tidy(): void {
    const now = this.now();
    for (const invite of this.data.invites.filter((i) => i.expiresAt <= now)) {
      this.data.cooldowns.push({ guardian: invite.guardian, protected: invite.protected, until: invite.expiresAt + COOLDOWN_MS });
    }
    this.data.invites = this.data.invites.filter((i) => i.expiresAt > now);
    this.data.cooldowns = this.data.cooldowns.filter((c) => c.until > now);
    for (const [guardian, times] of Object.entries(this.data.inviteTimes)) {
      const recent = times.filter((at) => now - at < HOUR_MS);
      if (recent.length > 0) this.data.inviteTimes[guardian] = recent;
      else delete this.data.inviteTimes[guardian];
    }
    const needed = new Set([...this.data.links, ...this.data.invites].flatMap((p) => [p.guardian, p.protected]));
    for (const hash of Object.keys(this.data.people)) if (!needed.has(hash)) delete this.data.people[hash];
  }

  private save(): void {
    this.tidy();
    saveFamily(this.persistence, this.data);
  }

  private remember(person: Person): void {
    this.data.people[person.hash] = { address: person.address, last4: person.last4 };
  }

  /** Tell someone other than the sender. A failure is logged without the number and never thrown. */
  private async tell(hash: string, text: string): Promise<boolean> {
    const member = this.data.people[hash];
    if (!member) return false;
    try {
      await this.courier.sendTo(member.address, text);
      return true;
    } catch (error) {
      const who = label({ hash, last4: member.last4 });
      console.error(`family message to ${who} failed:`, redact(error instanceof Error ? error.message : String(error)));
      return false;
    }
  }

  // --- commands --------------------------------------------------------------------------------

  async command(me: Person, command: Command, reply: Reply): Promise<void> {
    this.tidy();
    switch (command.kind) {
      case "protect":
        return command.number ? this.protect(me, command.number, reply) : reply(USAGE);
      case "unprotect":
        return command.number ? this.unprotect(me, command.number, reply) : reply(UNPROTECT_USAGE);
      case "yes":
        return this.accept(me, reply);
      case "stop":
        return this.stop(me, reply);
      case "family":
        return reply(this.summary(me));
    }
  }

  private async protect(me: Person, number: string, reply: Reply): Promise<void> {
    const them = this.identify(number);
    const pair = { guardian: me.hash, protected: them.hash };
    const theirMask = mask(them);
    if (them.hash === me.hash) return reply("That's your own number. Text the number of the person you want to protect.");
    if (this.data.links.some((l) => same(l, pair))) return reply(`You already get alerts for ${theirMask}.`);
    if (this.data.invites.some((i) => same(i, pair))) {
      return reply(`${theirMask} has already been asked. It's pending until they reply YES.`);
    }
    const cooldown = this.data.cooldowns.find((c) => same(c, pair));
    if (cooldown) {
      return reply(`${theirMask} didn't agree last time, so I can't ask them again for about ${hours(cooldown.until - this.now())}.`);
    }
    const sent = this.data.inviteTimes[me.hash] ?? [];
    if (sent.length >= INVITES_PER_HOUR) {
      return reply(`You can send ${INVITES_PER_HOUR} invites an hour. Try again in about ${hours(HOUR_MS - (this.now() - sent[0]))}.`);
    }
    const mine = [...this.data.links, ...this.data.invites].filter((p) => p.guardian === me.hash).length;
    if (mine >= MAX_PROTECTED) {
      return reply(`You can protect up to ${MAX_PROTECTED} people. Text "family" to see them, or unprotect one first.`);
    }
    if (this.guardiansOf(them.hash).length >= MAX_GUARDIANS) return reply(`${theirMask} can't be added right now.`);

    this.remember(me);
    this.data.people[them.hash] = { address: `+${number}`, last4: them.last4 };
    this.data.invites.push({ ...pair, expiresAt: this.now() + INVITE_TTL_MS });
    this.data.inviteTimes[me.hash] = [...sent, this.now()];
    const delivered = await this.tell(
      them.hash,
      `Phish Finder: someone at ${mask(me)} asked to get an alert when you're sent a dangerous link. ` +
        "Reply YES to agree, or ignore this message. Nothing is shared unless you reply YES. " +
        "They would see only the site's name and our report, never your messages.",
    );
    if (!delivered) {
      this.data.invites = this.data.invites.filter((i) => !same(i, pair)); // the hourly count still stands
      this.save();
      return reply(`I couldn't reach ${theirMask}. Check the number and try again.`);
    }
    this.save();
    console.log(`family invite from ${label(me)} to ${label(them)}`);
    return reply(`Invite sent to ${theirMask}. It's pending: nothing is linked until they reply YES, within 24 hours.`);
  }

  private async accept(me: Person, reply: Reply): Promise<void> {
    const pending = this.data.invites.filter((i) => i.protected === me.hash);
    if (pending.length === 0) return reply("There's no request waiting for this number, so there's nothing to agree to.");
    this.remember(me); // from now on answer them where they wrote from
    const linked: string[] = [];
    for (const invite of pending) {
      this.data.invites = this.data.invites.filter((i) => !same(i, invite));
      if (this.guardiansOf(me.hash).length >= MAX_GUARDIANS) continue;
      this.data.links.push({ guardian: invite.guardian, protected: me.hash, since: this.now() });
      linked.push(invite.guardian);
    }
    this.save();
    if (linked.length === 0) return reply(`You already have ${MAX_GUARDIANS} people getting alerts, which is the most allowed.`);
    for (const guardian of linked) {
      console.log(`family link: ${label(me)} agreed to ${label({ hash: guardian, last4: this.data.people[guardian]?.last4 ?? null })}`);
      await this.tell(guardian, `Phish Finder: ${mask(me)} said YES. You'll get an alert if a link they forward is rated Dangerous.`);
    }
    const who = linked.map((g) => this.maskOf(g)).join(" and ");
    return reply(
      `You're linked. ${who} will get an alert only when a link you forward is rated Dangerous: ` +
        "the site's name and our report, nothing else. Text STOP any time to end it.",
    );
  }

  /** STOP ends everything this person is part of, whichever side they are on, and declines what is pending. */
  private async stop(me: Person, reply: Reply): Promise<void> {
    const now = this.now();
    const asProtected = this.data.links.filter((l) => l.protected === me.hash);
    const asGuardian = this.data.links.filter((l) => l.guardian === me.hash);
    const declined = this.data.invites.filter((i) => i.protected === me.hash);
    const withdrawn = this.data.invites.filter((i) => i.guardian === me.hash);
    if (asProtected.length + asGuardian.length + declined.length + withdrawn.length === 0) {
      return reply("You have no family links, so there's nothing to stop.");
    }
    // Messages go out before the addresses are dropped by the save.
    for (const link of asProtected) await this.tell(link.guardian, `Phish Finder: ${mask(me)} turned off alerts. You're no longer linked.`);
    for (const link of asGuardian) await this.tell(link.protected, `Phish Finder: ${mask(me)} will no longer get alerts about your links.`);
    this.data.links = this.data.links.filter((l) => l.protected !== me.hash && l.guardian !== me.hash);
    this.data.invites = this.data.invites.filter((i) => i.protected !== me.hash && i.guardian !== me.hash);
    for (const pair of [...asProtected, ...declined]) {
      this.data.cooldowns.push({ guardian: pair.guardian, protected: me.hash, until: now + COOLDOWN_MS });
    }
    this.save();
    console.log(`family stop from ${label(me)}`);
    return reply("Done. Your family links are off: nobody gets alerts about your links, and you get none.");
  }

  private async unprotect(me: Person, number: string, reply: Reply): Promise<void> {
    const them = this.identify(number);
    const pair = { guardian: me.hash, protected: them.hash };
    const linked = this.data.links.some((l) => same(l, pair));
    const invited = this.data.invites.some((i) => same(i, pair));
    if (!linked && !invited) return reply(`You aren't getting alerts for ${mask(them)}.`);
    if (linked) await this.tell(them.hash, `Phish Finder: ${mask(me)} will no longer get alerts about your links.`);
    this.data.links = this.data.links.filter((l) => !same(l, pair));
    this.data.invites = this.data.invites.filter((i) => !same(i, pair));
    this.save();
    console.log(`family unlink by ${label(me)} of ${label(them)}`);
    return reply(linked ? `Done. You'll no longer get alerts for ${mask(them)}.` : `Done. The invite to ${mask(them)} is cancelled.`);
  }

  private summary(me: Person): string {
    const protecting = this.data.links.filter((l) => l.guardian === me.hash).map((l) => this.maskOf(l.protected));
    const pending = this.data.invites.filter((i) => i.guardian === me.hash).map((i) => `${this.maskOf(i.protected)} (pending)`);
    const guardians = this.guardiansOf(me.hash).map((g) => this.maskOf(g));
    const waiting = this.data.invites.filter((i) => i.protected === me.hash).map((i) => this.maskOf(i.guardian));
    const lines: string[] = [];
    if (protecting.length + pending.length > 0) lines.push(`You get alerts for: ${[...protecting, ...pending].join(", ")}`);
    if (guardians.length > 0) lines.push(`Alerts about your links go to: ${guardians.join(", ")}`);
    if (waiting.length > 0) lines.push(`Waiting for your YES: ${waiting.join(", ")}`);
    if (lines.length === 0) return `You have no family links. ${USAGE}`;
    return [...lines, "Text STOP to end them all."].join("\n");
  }

  // --- alerts ----------------------------------------------------------------------------------

  /**
   * Tell this person's guardians about a Dangerous verdict, and nothing else. Returns who was
   * told (hash and last four digits), for the live dashboard.
   */
  async alertGuardians(me: SenderId, result: AnalysisResult, publicUrl: string | undefined): Promise<SenderId[]> {
    if (result.verdict !== "dangerous") return [];
    const guardians = this.guardiansOf(me.hash);
    if (guardians.length === 0) return [];
    const domain = defangedDomain(result.final_url_defanged ?? result.url_defanged);
    const report = reportLink(publicUrl, result.id);
    // The site's name is defanged again as a last line of defence; our own report link is added after.
    const text =
      defangText(`Heads up: ${mask(me)} was sent a dangerous link: ${domain}.`) +
      (report ? ` Report: ${report}.` : "") +
      " They've been warned not to tap it.";
    const told: SenderId[] = [];
    for (const guardian of guardians) {
      const who = { hash: guardian, last4: this.data.people[guardian]?.last4 ?? null };
      if (await this.tell(guardian, text)) {
        told.push(who);
        console.log(`family alert about ${label(me)} sent to ${label(who)}`);
      }
    }
    return told;
  }
}
