export type Verdict = 'dangerous' | 'suspicious' | 'no_red_flags';
export type InputType = 'url' | 'message_screenshot' | 'qr_image';
export type JobState = 'queued' | 'running' | 'complete' | 'partial' | 'failed';
export type CheckStatus = 'pending' | 'running' | 'complete' | 'unavailable' | 'skipped' | 'error';
export type Outcome = 'concerning' | 'clear' | 'inconclusive';
export type Mode = 'demo' | 'live';
export interface EvidenceItem { id: string; ruleId: string | null; summary: string; source: string; observedAt: string; points: number | null }
export interface ScanCheck { id: string; order: number; label: string; status: CheckStatus; outcome: Outcome | null; finding: string | null; source: string; evidenceIds: string[]; startedAt: string | null; finishedAt: string | null; limitation: string | null }
export interface ScanSummary {
  id: string; revision: number; inputType: InputType; submittedUrlDisplay: string | null;
  headline: string; state: JobState; verdict: Verdict | null; score: number | null;
  submittedAt: string; completedAt: string | null; isRecorded: boolean;
}
export interface ScanDetail extends ScanSummary {
  hostnameDisplay?: { unicode: string; ascii: string };
  finalUrlDisplay: string | null; registeredDomainDisplay: string | null; checks: ScanCheck[]; evidence: EvidenceItem[];
  screenshot: { state: 'pending' | 'capturing' | 'available' | 'unavailable' | 'expired'; path: string | null; capturedAt: string | null; source: 'tripwire' | 'urlscan' | null; description: string | null };
  explanation: { lines: string[]; source: 'gemini' | 'template' | null };
  coverage: { completed: number; required: number; missingCheckIds: string[] };
  scoringVersion: string; limitations: string[];
  error: { code: string; message: string; retryable: boolean } | null;
}
export interface HistoryPage { items: ScanSummary[]; nextCursor: string | null; totalMatching: number; serverTime: string }
export interface Filters { q: string; window: string; risk: string; input: string; status: string; sort: string }
export interface Session { scopeKey: string; csrfToken: string; retentionDays: number; inputTypes: InputType[]; scanTimeoutSeconds: number }
export const isActive = (state: JobState) => state === 'queued' || state === 'running';
export const inputLabels: Record<InputType, string> = { url: 'URL', message_screenshot: 'Message screenshot', qr_image: 'QR image' };
