import { type Analyzer, AnalyzerUnreachable, createAnalyzer } from "./analyzer";
import { ANALYZER_DOWN, IMAGE_SOON, NO_URL, ONE_AT_A_TIME, OPENING, defangText, formatReply } from "./reply";
import { extractUrls } from "./urls";

/** What a message boils down to, whatever platform it came from. */
export type Inbound = { kind: "text"; text: string } | { kind: "image" } | { kind: "ignore" };

/** The only two things the gateway ever sends. */
export interface Outbox {
  sendText(text: string): Promise<void>;
  sendImage(bytes: Buffer, name: string, mimeType: string): Promise<void>;
}

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

/** One forwarded message: acknowledgment, then the screenshot, then the verdict. */
export async function handleInbound(
  inbound: Inbound,
  out: Outbox,
  analyzer: Analyzer = createAnalyzer(),
): Promise<void> {
  if (inbound.kind === "ignore") return;
  if (inbound.kind === "image") return out.sendText(IMAGE_SOON);

  const urls = extractUrls(inbound.text);
  if (urls.length === 0) return out.sendText(NO_URL);

  console.log(`checking ${defangText(urls[0])}`);
  await out.sendText(OPENING);
  let result;
  try {
    result = await analyzer.analyze(urls[0]);
  } catch (error) {
    logFailure("analyzer failed", error);
    return out.sendText(ANALYZER_DOWN);
  }
  if (result.screenshot_url) await sendScreenshot(result.screenshot_url, out, analyzer);
  await out.sendText(formatReply(result));
  if (urls.length > 1) await out.sendText(ONE_AT_A_TIME);
}
