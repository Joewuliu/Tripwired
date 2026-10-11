import { ContractError, parseReport } from './contract.ts'
import type { Report } from './contract.ts'

// Both calls go to the same host as the page (Caddy forwards /api/report/* and /api/check to the
// analyzer), so there is nothing to configure and nothing cross-origin.

type Fetcher = typeof fetch

const REPORT_ID = /^[a-f0-9]{12}$/
const CHECK_TIMEOUT_MS = 90_000 // a scan whose every read stalls takes about 28 s

export type ReportResult = { kind: 'ok'; report: Report } | { kind: 'missing' } | { kind: 'error'; message: string }

/** Fetch a stored report and check it against the contract. */
export async function fetchReport(id: string, doFetch: Fetcher = fetch, signal?: AbortSignal): Promise<ReportResult> {
  if (!REPORT_ID.test(id)) return { kind: 'missing' }
  let response: Response
  try {
    response = await doFetch(`/api/report/${id}`, { signal, headers: { Accept: 'application/json' } })
  } catch {
    return { kind: 'error', message: "We couldn't reach Phish Finder." }
  }
  if (response.status === 404) return { kind: 'missing' }
  if (!response.ok) return { kind: 'error', message: `Phish Finder answered with an error (${response.status}).` }
  try {
    return { kind: 'ok', report: parseReport(await response.json()) }
  } catch (error) {
    const detail = error instanceof ContractError ? error.message : 'not JSON'
    return { kind: 'error', message: `That report is not in a shape this page understands (${detail}).` }
  }
}

export type CheckResult =
  | { kind: 'ok'; id: string }
  | { kind: 'invalid' }
  | { kind: 'limited'; retryMinutes: number }
  | { kind: 'error' }

/** Ask Tripwire to check one pasted link. Resolves when the scan is done, with the report id. */
export async function submitLink(url: string, doFetch: Fetcher = fetch): Promise<CheckResult> {
  let response: Response
  try {
    response = await doFetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(CHECK_TIMEOUT_MS),
    })
  } catch {
    return { kind: 'error' }
  }
  if (response.status === 422) return { kind: 'invalid' }
  if (response.status === 429) {
    const seconds = Number(response.headers.get('retry-after'))
    return { kind: 'limited', retryMinutes: Math.max(1, Math.ceil((Number.isFinite(seconds) ? seconds : 60) / 60)) }
  }
  if (!response.ok) return { kind: 'error' }
  try {
    const body: unknown = await response.json()
    const id = typeof body === 'object' && body !== null ? (body as { id?: unknown }).id : undefined
    return typeof id === 'string' && REPORT_ID.test(id) ? { kind: 'ok', id } : { kind: 'error' }
  } catch {
    return { kind: 'error' }
  }
}
