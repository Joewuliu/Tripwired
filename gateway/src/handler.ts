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
} from "./reply";
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
  else console.error(`${what}:`, error);
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
): Promise<void> {
  console.log(`checking ${defangText(urls[0])}`);
  await out.sendText(opening);
  let result;
  try {
    result = await analyzer.analyze(urls[0]);
  } catch (error) {
    logFailure("analyzer failed", error);
    return out.sendText(ANALYZER_DOWN);
  }
  if (result.screenshot_url) await sendScreenshot(result.screenshot_url, out, analyzer);
  await out.sendText(formatReply(result, publicUrl));
  if (urls.length > 1) await out.sendText(ONE_AT_A_TIME);
}

async function handlePictures(
  pictures: Picture[],
  out: Outbox,
  analyzer: Analyzer,
  publicUrl: string | undefined,
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
  return scanAndReply(found.urls, out, analyzer, publicUrl, foundInPicture(found.urls[0]));
}

/** One forwarded message: acknowledgment, then the screenshot, then the verdict. */
export async function handleInbound(
  inbound: Inbound,
  out: Outbox,
  analyzer: Analyzer = createAnalyzer(),
  publicUrl: string | undefined = process.env.PUBLIC_URL,
): Promise<void> {
  if (inbound.kind === "ignore") return;
  if (inbound.kind === "image") return handlePictures(inbound.pictures ?? [], out, analyzer, publicUrl);

  const urls = extractUrls(inbound.text);
  if (urls.length > 0) return scanAndReply(urls, out, analyzer, publicUrl, OPENING);
  if (inbound.hasImage) return handlePictures(inbound.pictures ?? [], out, analyzer, publicUrl);
  return out.sendText(NO_URL);
}
