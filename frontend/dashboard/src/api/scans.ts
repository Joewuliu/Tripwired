import type { ZodType } from 'zod';
import type { Filters, ScanDetail, Session } from '../types/scan';
import { serializeFilters } from '../utils/filters';
import { createdSchema, detailSchema, historySchema, sessionSchema } from './schema';

export class ApiError extends Error {
  constructor(message: string, public status = 0, public retryAfterSeconds = 0) { super(message); this.name = 'ApiError'; }
}
async function request<T>(path: string, schema: ZodType<T>, signal?: AbortSignal, init?: RequestInit): Promise<T> {
  let response: Response;
  try { response = await fetch(path, { ...init, signal, credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json', ...init?.headers } }); }
  catch (error) {
    if (signal?.aborted) throw error;
    throw new ApiError('Connection interrupted. Showing the latest received results.');
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    const retryHeader = response.headers.get('Retry-After');
    const delay = retryHeader ? (/^\d+$/.test(retryHeader) ? Number(retryHeader) : Math.max(0, Math.ceil((Date.parse(retryHeader) - Date.now()) / 1000))) : Number(payload?.error?.retryAfterSeconds || 0);
    const known: Record<number, string> = { 401: 'Your session has expired. Start a new session to continue.', 403: 'This action is not authorized for your current session.', 404: 'This report is unavailable or the link has expired.', 410: 'This report is unavailable or the link has expired.', 429: 'Too many scans. Please wait before trying again.', 503: 'The analyzer is unavailable. Please try again later.' };
    throw new ApiError(known[response.status] || (typeof payload?.error?.message === 'string' ? payload.error.message : 'The request could not be completed.'), response.status, Number.isFinite(delay) ? delay : 0);
  }
  const json = await response.json().catch(() => { throw new ApiError('The server returned an unexpected response.', 502); });
  const result = schema.safeParse(json);
  if (!result.success) throw new ApiError('The server returned an incompatible report. Please check the API connection.', 502);
  return result.data;
}
export const getSession = (signal?: AbortSignal) => request('/api/session', sessionSchema, signal);
export function getHistory(filters: Filters, cursor: string | null, signal?: AbortSignal) {
  const query = serializeFilters(filters); query.set('limit', '20'); if (cursor) query.set('cursor', cursor);
  return request(`/api/scans?${query}`, historySchema, signal).then(page => {
    if (page.items.some(scan => scan.isRecorded)) throw new ApiError('Recorded demo data was received in live mode. Check the analyzer configuration.', 502);
    return page;
  });
}
export const getScanDetail = (id: string, signal?: AbortSignal) => request(`/api/scans/${encodeURIComponent(id)}`, detailSchema, signal).then(scan => {
  if (scan.isRecorded) throw new ApiError('Recorded demo data was received in live mode. Check the analyzer configuration.', 502);
  return scan;
});
export function createScan(url: string, key: string, session: Session) {
  return request('/api/scans', createdSchema, undefined, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrfToken, 'Idempotency-Key': key }, body: JSON.stringify({ url, inputType: 'url' }) });
}
export function rescanScan(id: string, key: string, session: Session) {
  // Display URLs are redacted. Only the analyzer can rescan the protected original.
  return request(`/api/scans/${encodeURIComponent(id)}/rescan`, createdSchema, undefined, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrfToken, 'Idempotency-Key': key }, body: '{}' });
}
export async function exchangeCapability(scanId: string, capability: string, session: Session) {
  const response = await fetch('/api/report-access', { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ scanId, capability }) });
  if (!response.ok) throw new ApiError('This report is unavailable or the link has expired.', response.status);
}
export function keepNewest(old: ScanDetail | undefined, next: ScanDetail): ScanDetail {
  return old?.id === next.id && old.revision > next.revision ? old : next;
}
export function retryRequest(count: number, error: Error) {
  return count < 3 && (!(error instanceof ApiError) || error.status === 0 || error.status >= 500);
}
export const retryDelay = (attempt: number) => Math.min(1000 * 2 ** attempt, 8000);
