import { z } from 'zod';

const date = z.string().datetime({ offset: true });
const nullableDate = date.nullable();
const verdict = z.enum(['dangerous', 'suspicious', 'no_red_flags']).nullable();
const state = z.enum(['queued', 'running', 'complete', 'partial', 'failed']);
const inputType = z.enum(['url', 'message_screenshot', 'qr_image']);
export const summarySchema = z.object({
  id: z.string().regex(/^[a-zA-Z0-9_-]{1,128}$/), revision: z.number().int().nonnegative(),
  inputType, submittedUrlDisplay: z.string().max(8192).nullable(), headline: z.string().max(2000), state, verdict,
  score: z.number().int().min(0).max(100).nullable(), submittedAt: date, completedAt: nullableDate, isRecorded: z.boolean(),
});
export const detailSchema = summarySchema.extend({
  hostnameDisplay: z.object({ unicode: z.string().max(512), ascii: z.string().max(512) }).optional(),
  finalUrlDisplay: z.string().max(8192).nullable(), registeredDomainDisplay: z.string().nullable(),
  checks: z.array(z.object({
    id: z.string(), order: z.number().int(), label: z.string(),
    status: z.enum(['pending', 'running', 'complete', 'unavailable', 'skipped', 'error']),
    outcome: z.enum(['concerning', 'clear', 'inconclusive']).nullable(), finding: z.string().nullable(), source: z.string(),
    evidenceIds: z.array(z.string()), startedAt: nullableDate, finishedAt: nullableDate, limitation: z.string().nullable(),
  })).max(50),
  evidence: z.array(z.object({ id: z.string(), ruleId: z.string().nullable(), summary: z.string(), source: z.string(), observedAt: date, points: z.number().nullable() })).max(500),
  screenshot: z.object({ state: z.enum(['pending', 'capturing', 'available', 'unavailable', 'expired']), path: z.string().nullable(), capturedAt: nullableDate, source: z.enum(['tripwire', 'urlscan']).nullable(), description: z.string().nullable() }),
  explanation: z.object({ lines: z.array(z.string()).max(10), source: z.enum(['gemini', 'template']).nullable() }),
  coverage: z.object({ completed: z.number().int().nonnegative(), required: z.number().int().nonnegative(), missingCheckIds: z.array(z.string()) }),
  scoringVersion: z.string(), limitations: z.array(z.string()), error: z.object({ code: z.string(), message: z.string(), retryable: z.boolean() }).nullable(),
});
export const historySchema = z.object({ items: z.array(summarySchema), nextCursor: z.string().nullable(), totalMatching: z.number().int().nonnegative(), serverTime: date });
export const createdSchema = z.object({ id: summarySchema.shape.id, revision: z.number().int().nonnegative(), state, reportPath: z.string(), detailPath: z.string() });
export const sessionSchema = z.object({ scopeKey: z.string().min(1), csrfToken: z.string().min(1), retentionDays: z.number().positive(), inputTypes: z.array(inputType), scanTimeoutSeconds: z.number().positive() });

export function approvedScreenshot(scanId: string, path: string | null, recorded = false): string | null {
  if (!path) return null;
  if (recorded) return path === '/demo/toll-capture.png' ? path : null;
  // No third-party images, queries, SVGs, or arbitrary same-origin asset paths.
  return path === `/api/scans/${encodeURIComponent(scanId)}/screenshot` ? path : null;
}
