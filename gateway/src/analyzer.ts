import type { AnalysisResult } from "./reply";
import type { SenderId } from "./sender";

const ANALYZE_TIMEOUT_MS = 45_000;
const SCREENSHOT_TIMEOUT_MS = 10_000;
const READ_IMAGE_TIMEOUT_MS = 25_000; // Gemini gets 15 s inside the analyzer
const DEFAULT_BASE = "http://127.0.0.1:8001";

/** What reading a picture came to: addresses as the picture shows them, or "unavailable". */
export interface PictureReading {
  status: "ok" | "unavailable";
  urls: string[];
}

export interface Analyzer {
  /** Scan a link. The sender (a hash and the last four digits, never the number) only labels live events. */
  analyze(url: string, sender?: SenderId): Promise<AnalysisResult>;
  /** Tell the analyzer the reply went out, so the live stream can show it. Never throws. */
  replySent(scanId: string, sender?: SenderId): Promise<void>;
  /** Tell the analyzer a guardian was alerted about this scan (masked on the live stream). Never throws. */
  guardianAlerted(scanId: string, guardian: SenderId, sender?: SenderId): Promise<void>;
  readImage(bytes: Buffer, mimeType: string): Promise<PictureReading>;
  fetchScreenshot(path: string): Promise<Buffer>;
}

/** Nobody answered (or too slowly): expected when the analyzer is down, so it logs one line. */
export class AnalyzerUnreachable extends Error {
  constructor(base: string, reason: "unreachable" | "timed out") {
    super(`analyzer ${reason} at ${base}`);
  }
}

const CONNECTION_CODES = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ENOTFOUND",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "UND_ERR_CONNECT_TIMEOUT",
]);

function classify(error: unknown, base: string): unknown {
  if (error instanceof Error && error.name === "TimeoutError") return new AnalyzerUnreachable(base, "timed out");
  const cause = (error as { cause?: { code?: string; errors?: { code?: string }[] } }).cause;
  const codes = [cause?.code, ...(cause?.errors ?? []).map((e) => e.code)];
  if (error instanceof TypeError && codes.some((code) => code && CONNECTION_CODES.has(code))) {
    return new AnalyzerUnreachable(base, "unreachable");
  }
  return error;
}

function parse(body: unknown): AnalysisResult {
  const b = body as Partial<AnalysisResult> | null;
  if (
    !b ||
    typeof b.id !== "string" ||
    typeof b.verdict !== "string" ||
    typeof b.headline !== "string" ||
    typeof b.url_defanged !== "string" ||
    !Array.isArray(b.observations)
  ) {
    throw new Error("unexpected analyzer response");
  }
  return {
    id: b.id,
    verdict: b.verdict,
    headline: b.headline,
    observations: b.observations.map(String),
    url_defanged: b.url_defanged,
    final_url_defanged: typeof b.final_url_defanged === "string" ? b.final_url_defanged : null,
    loaded: b.loaded === true,
    screenshot_url: typeof b.screenshot_url === "string" ? b.screenshot_url : null,
  };
}

export function createAnalyzer(base = process.env.ANALYZER_URL || DEFAULT_BASE): Analyzer {
  return {
    async analyze(url, sender) {
      try {
        const response = await fetch(new URL("/analyze", base), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ urls: [url], ...(sender ? { sender } : {}) }),
          signal: AbortSignal.timeout(ANALYZE_TIMEOUT_MS),
        });
        if (!response.ok) throw new Error(`analyzer returned ${response.status}`);
        return parse(await response.json());
      } catch (error) {
        throw classify(error, base);
      }
    },

    async replySent(scanId, sender) {
      try {
        await fetch(new URL("/internal/reply-sent", base), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ scan: scanId, ...(sender ? { sender } : {}) }),
          signal: AbortSignal.timeout(5_000),
        });
      } catch {
        // the event stream is a view, not part of the reply: losing one event costs nothing
      }
    },

    async guardianAlerted(scanId, guardian, sender) {
      try {
        await fetch(new URL("/internal/guardian-alerted", base), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ scan: scanId, guardian, ...(sender ? { sender } : {}) }),
          signal: AbortSignal.timeout(5_000),
        });
      } catch {
        // as with replySent: the stream is a view, and the alert itself has already gone out
      }
    },

    async readImage(bytes, mimeType) {
      try {
        const response = await fetch(new URL("/read-image", base), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ mime_type: mimeType, data_base64: bytes.toString("base64") }),
          signal: AbortSignal.timeout(READ_IMAGE_TIMEOUT_MS),
        });
        if (!response.ok) throw new Error(`analyzer returned ${response.status}`);
        const body = (await response.json()) as { status?: unknown; urls?: unknown };
        const urls = Array.isArray(body.urls) ? body.urls.filter((u): u is string => typeof u === "string") : [];
        return { status: body.status === "ok" ? "ok" : "unavailable", urls };
      } catch (error) {
        throw classify(error, base);
      }
    },

    async fetchScreenshot(path) {
      const target = new URL(path, base);
      if (target.origin !== new URL(base).origin) throw new Error("screenshot is not on the analyzer");
      try {
        const response = await fetch(target, { signal: AbortSignal.timeout(SCREENSHOT_TIMEOUT_MS) });
        if (!response.ok) throw new Error(`screenshot returned ${response.status}`);
        return Buffer.from(await response.arrayBuffer());
      } catch (error) {
        throw classify(error, base);
      }
    },
  };
}
