import * as linkify from "linkifyjs";

export const OPENING = "Opening that in a sandbox. About 20 seconds.";
export const NO_URL = "Forward me a suspicious text or link and I'll open it in a sandbox for you.";
export const IMAGE_SOON = "Screenshot checking is coming soon. For now, paste the link itself.";
export const ONE_AT_A_TIME = "I check one link at a time, so I opened the first one.";
export const ANALYZER_DOWN =
  "I couldn't check that right now. Don't tap the link until you can verify it another way.";

const COULDNT_CHECK_HEADLINE =
  "Couldn't get a proper look at this link. Don't enter anything until you verify it another way.";
const MAX_OBSERVATIONS = 3;

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

/** The four things Tripwire ever says. There is no "safe". */
type Verdict = "dangerous" | "suspicious" | "no_red_flags" | "couldnt_check";

const LABELS: Record<Verdict, string> = {
  dangerous: "DANGEROUS",
  suspicious: "SUSPICIOUS",
  no_red_flags: "NO RED FLAGS",
  couldnt_check: "COULDN'T CHECK",
};

const ACTIONS: Record<Verdict, string> = {
  dangerous: "Don't enter anything, and don't tap the link.",
  suspicious: "Be careful. Don't enter passwords or payment details until you verify it another way.",
  no_red_flags: "If it asks for a login or payment, go to the official site yourself instead.",
  couldnt_check: "Contact the sender or company through a phone number or site you already trust.",
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
  const headline = known ? result.headline : COULDNT_CHECK_HEADLINE;
  // Dangerous and suspicious headlines already lead with the top observation.
  const bullets = result.observations
    .filter((observation) => !headline.endsWith(observation))
    .slice(0, MAX_OBSERVATIONS)
    .map((observation) => `- ${observation}`);
  const opened = verdict !== "couldnt_check" && result.loaded;
  const link = opened ? result.final_url_defanged : result.url_defanged;
  const lines = [
    `Tripwire: ${LABELS[verdict]}`,
    headline,
    ...bullets,
    ACTIONS[verdict],
    `${opened ? "Link opened" : "Link we tried"}: ${link ?? result.url_defanged}`,
  ];
  const message = defangText(lines.join("\n"));
  const report = reportLink(publicUrl, result.id);
  return report ? `${message}\n\nFull report: ${report}` : message;
}
