import type { Report, Verdict } from './contract.ts'

/** The links this browser has looked at, newest first. It lives only in this browser's storage. */
export interface HistoryEntry {
  id: string
  url: string // defanged, as in the report
  verdict: Verdict
  at: string
}

const KEY = 'tripwire.history'
const LIMIT = 8
const VERDICTS = ['dangerous', 'suspicious', 'no_red_flags', 'couldnt_check']

function isEntry(value: unknown): value is HistoryEntry {
  if (typeof value !== 'object' || value === null) return false
  const o = value as Record<string, unknown>
  return (
    typeof o.id === 'string' &&
    /^[a-f0-9]{12}$/.test(o.id) &&
    typeof o.url === 'string' &&
    typeof o.verdict === 'string' &&
    VERDICTS.includes(o.verdict) &&
    typeof o.at === 'string'
  )
}

/** Storage can be missing or blocked (private windows); the page works without it. */
export function readHistory(storage: Pick<Storage, 'getItem'> | null = safeStorage()): HistoryEntry[] {
  try {
    const parsed: unknown = JSON.parse(storage?.getItem(KEY) ?? '[]')
    return Array.isArray(parsed) ? parsed.filter(isEntry).slice(0, LIMIT) : []
  } catch {
    return []
  }
}

/** Put a viewed report at the top of the list, once, and keep the list short. */
export function remember(report: Report, storage: Pick<Storage, 'getItem' | 'setItem'> | null = safeStorage()): void {
  const entry: HistoryEntry = { id: report.id, url: report.url_defanged, verdict: report.verdict, at: report.created_at }
  try {
    const rest = readHistory(storage).filter((old) => old.id !== entry.id)
    storage?.setItem(KEY, JSON.stringify([entry, ...rest].slice(0, LIMIT)))
  } catch {
    // storage full or blocked: losing the history costs nothing
  }
}

function safeStorage(): Storage | null {
  try {
    return globalThis.localStorage ?? null
  } catch {
    return null
  }
}
