import type { AnalysisResult } from "./reply";

const ANALYZE_TIMEOUT_MS = 45_000;
const SCREENSHOT_TIMEOUT_MS = 10_000;
const DEFAULT_BASE = "http://127.0.0.1:8001";

export interface Analyzer {
  analyze(url: string): Promise<AnalysisResult>;
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
    async analyze(url) {
      try {
        const response = await fetch(new URL("/analyze", base), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ urls: [url] }),
          signal: AbortSignal.timeout(ANALYZE_TIMEOUT_MS),
        });
        if (!response.ok) throw new Error(`analyzer returned ${response.status}`);
        return parse(await response.json());
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
