import * as linkify from "linkifyjs";

// Everything here is written for someone who is not technical: short sentences, everyday words.
export const OPENING = "Checking that link for you. This takes about 20 seconds.";
export const NO_URL =
  "Send me a text or link you're not sure about, and I'll check it for you. " +
  "To be told when someone you care about is sent a dangerous link, text: protect and their mobile number.";
export const PICTURE_UNAVAILABLE =
  "I can't look at pictures right now. Please type or paste the link itself and I'll check it.";
export const READING_PICTURE = "Looking for a link in your picture. One moment.";
export const NO_LINK_IN_PICTURE =
  "I couldn't find a link in that picture. If it's a QR code, try a closer, steadier photo. Or type the link in a message.";
export const ONE_AT_A_TIME = "I can only check one link at a time, so I checked the first one.";
export const ANALYZER_DOWN =
  "I can't check links right now. Please don't tap that link. Try me again in a few minutes.";

/** The friendly "slow down" reply: how many checks, and roughly when the next one is free. */
export function rateLimited(limit: number, waitMs: number): string {
  const minutes = Math.max(1, Math.ceil(waitMs / 60_000));
  return (
    `You've used all ${limit} checks for this hour. I can check another one in about ` +
    `${minutes} minute${minutes === 1 ? "" : "s"}. ` +
    "Until then, please don't tap that link or type anything into it."
  );
}

/** Said before the scan of a link that was read from a picture, so a misread is visible. */
export function foundInPicture(url: string): string {
  return `I found this link in your picture: ${defangText(url)}\nChecking it now. This takes about 20 seconds.`;
}

const NO_REASON = "I couldn't get a proper look at that link.";
const MAX_REASONS = 3;

/** What the analyzer sends back for one scan (the fields the reply uses). */
export interface AnalysisResult {
  id: string;
  verdict: string;
  headline: string;
  observations: string[];
  url_defanged: string;
  final_url_defanged: string | null;
  loaded: boolean;
  screenshot_url: string | null;
}

/** The four things Phish Finder ever says. There is no "safe". */
type Verdict = "dangerous" | "suspicious" | "no_red_flags" | "couldnt_check";

const LABELS: Record<Verdict, string> = {
  dangerous: "DANGEROUS",
  suspicious: "SUSPICIOUS",
  no_red_flags: "NO RED FLAGS",
  couldnt_check: "COULDN'T CHECK",
};

/** What to do, in one or two plain sentences. */
const ACTIONS: Record<Verdict, string> = {
  dangerous: "This looks like a scam. Don't tap the link, and don't type anything into it.",
  suspicious:
    "Be careful with this one. Don't type a password or card number into it, and check with the sender another way first.",
  no_red_flags:
    "I didn't find anything wrong, but I can't promise. If it asks for a password or payment, go to the company's own website yourself instead.",
  couldnt_check:
    "That doesn't mean it's fine. Don't type anything into it, and call the company on a number you already trust.",
};

function isVerdict(value: string): value is Verdict {
  return Object.hasOwn(LABELS, value); // not "in": that is also true for "constructor"
}

/** Last line of defence: no live link leaves the gateway, whatever the analyzer sent. */
export function defangText(text: string): string {
  let out = text.replace(/https?:\/\//gi, (scheme) => (scheme.toLowerCase() === "http://" ? "hxxp://" : "hxxps://"));
  for (const link of linkify.find(out)) {
    if (link.type === "url") out = out.replace(link.value, () => link.value.replaceAll(".", "[.]"));
  }
  return out;
}

const REPORT_PATH = "/r"; // the report page, served from the same host as the API
const REPORT_ID = /^[a-f0-9]{12}$/;

/**
 * The link to a scan's full report, or null when there is nothing safe to link to.
 *
 * It is the one live (tappable) link the gateway ever sends, so it is built from the operator's own
 * PUBLIC_URL and an id that must be exactly 12 hex characters. Nothing the analyzer or the scanned
 * page says can reach it.
 */
export function reportLink(publicUrl: string | undefined, id: string): string | null {
  if (!publicUrl || !REPORT_ID.test(id)) return null;
  let base: URL;
  try {
    base = new URL(publicUrl);
  } catch {
    return null;
  }
  if (base.protocol !== "https:" && base.protocol !== "http:") return null;
  return `${base.origin}${REPORT_PATH}/${id}`; // origin: no credentials, path or query from the setting
}

/**
 * The verdict message: label, headline, up to three observations, what to do, which link, and, when
 * PUBLIC_URL is set, a link to the full report. Everything that came from the analyzer is defanged;
 * the report link is added afterwards so it stays tappable.
 */
export function formatReply(result: AnalysisResult, publicUrl?: string): string {
  const known = isVerdict(result.verdict);
  const verdict: Verdict = known ? (result.verdict as Verdict) : "couldnt_check";
  const observations = result.observations.map((line) => line.trim()).filter(Boolean);
  const lines = [`Phish Finder: ${LABELS[verdict]}`];

  if (verdict === "couldnt_check") {
    // The reason comes first: it is the whole point of this message. The analyzer puts it first.
    lines.push(known && observations.length > 0 ? observations[0] : NO_REASON, ACTIONS[verdict]);
  } else {
    // Dangerous and suspicious headlines carry the top reason behind the verdict word: use it first.
    const lead = result.headline.replace(/^(Dangerous|Suspicious):\s*/i, "").trim();
    const reasons = [...new Set([...(verdict === "no_red_flags" ? [] : [lead]), ...observations])]
      .filter(Boolean)
      .slice(0, MAX_REASONS);
    lines.push(ACTIONS[verdict]);
    if (reasons.length > 0) {
      lines.push(verdict === "no_red_flags" ? "What I found:" : "Why:", ...reasons.map((reason) => `- ${reason}`));
    }
  }
  const opened = verdict !== "couldnt_check" && result.loaded;
  const link = opened ? result.final_url_defanged : result.url_defanged;
  lines.push(`The link, made unclickable on purpose: ${link ?? result.url_defanged}`);
  const message = defangText(lines.join("\n"));
  const report = reportLink(publicUrl, result.id);
  return report ? `${message}\n\nFull report: ${report}` : message;
}
