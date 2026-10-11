import { type Analyzer, AnalyzerUnreachable, createAnalyzer } from "./analyzer";
import {
  ANALYZER_DOWN,
  NO_LINK_IN_PICTURE,
  NO_URL,
  ONE_AT_A_TIME,
  OPENING,
  PICTURE_UNAVAILABLE,
  READING_PICTURE,
  defangText,
  foundInPicture,
  formatReply,
  rateLimited,
} from "./reply";
import { parseCommand } from "./commands";
import type { Family, Person } from "./family";
import { type SenderId, redact } from "./sender";
import { extractUrls } from "./urls";

/** A picture that came with a message. Its bytes are read only when we need them. */
export interface Picture {
  mimeType: string;
  size?: number;
  read(): Promise<Buffer>;
}

/** What a message boils down to, whatever platform it came from. */
export type Inbound =
  | { kind: "text"; text: string; hasImage?: boolean; pictures?: Picture[] } // hasImage: a picture came along
  | { kind: "image"; pictures?: Picture[] }
  | { kind: "ignore" };

/**
 * What the sender is allowed to do. `take` counts one check and returns null, or how many
 * milliseconds until the sender may check again. `label` is for log lines: a hash prefix and the
 * masked number, never the number.
 */
export interface Policy {
  sender: SenderId;
  label: string;
  limit: number;
  take(): number | null;
}

/** Family mode for this message: the service, and the person the message came from. */
export interface FamilyContext {
  service: Family;
  me: Person;
}

/** The only two things the gateway ever sends. */
export interface Outbox {
  sendText(text: string): Promise<void>;
  sendImage(bytes: Buffer, name: string, mimeType: string): Promise<void>;
}

/** Pictures are looked at one at a time and only the first few; a big photo is skipped, not sent. */
const MAX_PICTURES = 2;
const MAX_PICTURE_BYTES = 10 * 1024 * 1024;

function logFailure(what: string, error: unknown): void {
  if (error instanceof AnalyzerUnreachable) console.error(error.message);
  else console.error(`${what}:`, redact(error instanceof Error ? error.message : String(error)));
}

async function sendScreenshot(path: string, out: Outbox, analyzer: Analyzer): Promise<void> {
  try {
    const bytes = await analyzer.fetchScreenshot(path);
    await out.sendImage(bytes, path.split("/").pop() ?? "screenshot.png", "image/png");
  } catch (error) {
    logFailure("screenshot not sent", error); // the verdict still goes out
  }
}

type Found = { status: "found"; urls: string[] } | { status: "none" } | { status: "unavailable" };

/** Ask the analyzer to read the link out of the first picture that has one. */
async function linksInPictures(pictures: Picture[], analyzer: Analyzer): Promise<Found> {
  let anyRead = false;
  for (const picture of pictures.slice(0, MAX_PICTURES)) {
    if (picture.size !== undefined && picture.size > MAX_PICTURE_BYTES) continue;
    let bytes: Buffer;
    try {
      bytes = await picture.read();
    } catch (error) {
      logFailure("picture not read", error);
      continue;
    }
    if (bytes.length === 0 || bytes.length > MAX_PICTURE_BYTES) continue;
    const reading = await analyzer.readImage(bytes, picture.mimeType);
    if (reading.status === "unavailable") return { status: "unavailable" };
    anyRead = true;
    if (reading.urls.length > 0) return { status: "found", urls: reading.urls };
  }
  return anyRead ? { status: "none" } : { status: "unavailable" };
}

async function scanAndReply(
  urls: string[],
  out: Outbox,
  analyzer: Analyzer,
  publicUrl: string | undefined,
  opening: string,
  who: string,
  sender?: SenderId,
  family?: FamilyContext,
): Promise<void> {
  console.log(`checking ${defangText(urls[0])} for ${who}`);
  await out.sendText(opening);
  let result;
  try {
    result = await analyzer.analyze(urls[0], sender);
  } catch (error) {
    logFailure("analyzer failed", error);
    return out.sendText(ANALYZER_DOWN);
  }
  if (result.screenshot_url) await sendScreenshot(result.screenshot_url, out, analyzer);
  await out.sendText(formatReply(result, publicUrl));
  await analyzer.replySent(result.id, sender);
  if (family) await alertGuardians(family, result, analyzer, publicUrl);
  if (urls.length > 1) await out.sendText(ONE_AT_A_TIME);
}

/** A Dangerous verdict, and only that, reaches the person's guardians. It never holds up or changes the reply. */
async function alertGuardians(
  family: FamilyContext,
  result: Awaited<ReturnType<Analyzer["analyze"]>>,
  analyzer: Analyzer,
  publicUrl: string | undefined,
): Promise<void> {
  try {
    const sender = { hash: family.me.hash, last4: family.me.last4 };
    for (const guardian of await family.service.alertGuardians(sender, result, publicUrl)) {
      await analyzer.guardianAlerted(result.id, guardian, sender);
    }
  } catch (error) {
    logFailure("guardian alert failed", error);
  }
}

async function handlePictures(
  pictures: Picture[],
  out: Outbox,
  analyzer: Analyzer,
  publicUrl: string | undefined,
  who: string,
  sender?: SenderId,
  family?: FamilyContext,
): Promise<void> {
  if (pictures.length === 0) return out.sendText(PICTURE_UNAVAILABLE);
  await out.sendText(READING_PICTURE);
  let found: Found;
  try {
    found = await linksInPictures(pictures, analyzer);
  } catch (error) {
    logFailure("picture reading failed", error);
    return out.sendText(ANALYZER_DOWN);
  }
  if (found.status === "unavailable") return out.sendText(PICTURE_UNAVAILABLE);
  if (found.status === "none") return out.sendText(NO_LINK_IN_PICTURE);
  // The link is scanned like any typed link: the picture can only get it looked at.
  return scanAndReply(found.urls, out, analyzer, publicUrl, foundInPicture(found.urls[0]), who, sender, family);
}

/** One forwarded message: acknowledgment, then the screenshot, then the verdict. */
export async function handleInbound(
  inbound: Inbound,
  out: Outbox,
  analyzer: Analyzer = createAnalyzer(),
  publicUrl: string | undefined = process.env.PUBLIC_URL,
  policy?: Policy,
  family?: FamilyContext,
): Promise<void> {
  if (inbound.kind === "ignore") return;
  // A message that is exactly a family command (protect, YES, STOP...) is handled as one. It is
  // not a check, so it is not counted against the hourly limit.
  const command = family && inbound.kind === "text" ? parseCommand(inbound.text) : null;
  if (family && command) return family.service.command(family.me, command, (text) => out.sendText(text));
  const who = policy?.label ?? "unknown sender";

  /** A check costs a scan or a picture read, so it is counted before any work or acknowledgment. */
  async function allowed(): Promise<boolean> {
    const waitMs = policy?.take() ?? null;
    if (waitMs === null) return true;
    console.log(`rate limited ${who}`);
    await out.sendText(rateLimited(policy!.limit, waitMs));
    return false;
  }

  if (inbound.kind === "image") {
    if (!(await allowed())) return;
    return handlePictures(inbound.pictures ?? [], out, analyzer, publicUrl, who, policy?.sender, family);
  }

  const urls = extractUrls(inbound.text);
  if (urls.length > 0) {
    if (!(await allowed())) return;
    return scanAndReply(urls, out, analyzer, publicUrl, OPENING, who, policy?.sender, family);
  }
  if (inbound.hasImage) {
    if (!(await allowed())) return;
    return handlePictures(inbound.pictures ?? [], out, analyzer, publicUrl, who, policy?.sender, family);
  }
  return out.sendText(NO_URL);
}
