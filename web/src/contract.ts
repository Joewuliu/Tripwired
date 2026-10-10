// The result of one scan, as the analyzer returns it. Mirrors analyzer/contract.py; both are checked
// against the one example in ./sample/report.sample.json. Change all three together.

export type Verdict = 'dangerous' | 'suspicious' | 'no_red_flags' | 'couldnt_check' | 'unscored'

const VERDICTS: readonly string[] = ['dangerous', 'suspicious', 'no_red_flags', 'couldnt_check', 'unscored']

export interface Evidence {
  id: string
  label: string
  points: number
  source: string
}

export interface PointsRule {
  id: string
  label: string
  points: number
}

export interface Hop {
  status: number
  url: string
}

export interface BrandMatch {
  brand: string
  official_domain_defanged: string
  real_screenshot_url: string | null
  similarity: number | null
}

export interface Report {
  id: string
  created_at: string
  verdict: Verdict
  score: number | null
  headline: string
  observations: string[]
  evidence: Evidence[]
  points_table: PointsRule[]
  brand_match: BrandMatch | null
  url_defanged: string
  final_url_defanged: string | null
  redirects_defanged: Hop[]
  title: string | null
  loaded: boolean
  complete: boolean
  final_status: number | null
  blocked_requests: number
  screenshot_url: string | null
}

export class ContractError extends Error {}

function fail(path: string, expected: string): never {
  throw new ContractError(`${path}: expected ${expected}`)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function str(value: unknown, path: string): string {
  return typeof value === 'string' ? value : fail(path, 'a string')
}

function int(value: unknown, path: string): number {
  return typeof value === 'number' && Number.isInteger(value) ? value : fail(path, 'an integer')
}

function bool(value: unknown, path: string): boolean {
  return typeof value === 'boolean' ? value : fail(path, 'true or false')
}

function nullable<T>(value: unknown, path: string, read: (v: unknown, p: string) => T): T | null {
  return value === null ? null : read(value, path)
}

function list<T>(value: unknown, path: string, read: (v: unknown, p: string) => T): T[] {
  if (!Array.isArray(value)) return fail(path, 'a list')
  return value.map((item, i) => read(item, `${path}[${i}]`))
}

function record(value: unknown, path: string): Record<string, unknown> {
  return isRecord(value) ? value : fail(path, 'an object')
}

function readEvidence(value: unknown, path: string): Evidence {
  const o = record(value, path)
  return {
    id: str(o.id, `${path}.id`),
    label: str(o.label, `${path}.label`),
    points: int(o.points, `${path}.points`),
    source: str(o.source, `${path}.source`),
  }
}

function readRule(value: unknown, path: string): PointsRule {
  const o = record(value, path)
  return { id: str(o.id, `${path}.id`), label: str(o.label, `${path}.label`), points: int(o.points, `${path}.points`) }
}

function readHop(value: unknown, path: string): Hop {
  const o = record(value, path)
  return { status: int(o.status, `${path}.status`), url: str(o.url, `${path}.url`) }
}

function readBrandMatch(value: unknown, path: string): BrandMatch {
  const o = record(value, path)
  return {
    brand: str(o.brand, `${path}.brand`),
    official_domain_defanged: str(o.official_domain_defanged, `${path}.official_domain_defanged`),
    real_screenshot_url: nullable(o.real_screenshot_url, `${path}.real_screenshot_url`, str),
    similarity: nullable(o.similarity, `${path}.similarity`, (v, p) =>
      typeof v === 'number' ? v : fail(p, 'a number'),
    ),
  }
}

function readVerdict(value: unknown, path: string): Verdict {
  return typeof value === 'string' && VERDICTS.includes(value) ? (value as Verdict) : fail(path, `one of ${VERDICTS.join(', ')}`)
}

/** Check an unknown value against the contract and return it typed, or throw ContractError. */
export function parseReport(value: unknown): Report {
  const o = record(value, 'report')
  return {
    id: str(o.id, 'id'),
    created_at: str(o.created_at, 'created_at'),
    verdict: readVerdict(o.verdict, 'verdict'),
    score: nullable(o.score, 'score', int),
    headline: str(o.headline, 'headline'),
    observations: list(o.observations, 'observations', str),
    evidence: list(o.evidence, 'evidence', readEvidence),
    points_table: list(o.points_table, 'points_table', readRule),
    brand_match: nullable(o.brand_match, 'brand_match', readBrandMatch),
    url_defanged: str(o.url_defanged, 'url_defanged'),
    final_url_defanged: nullable(o.final_url_defanged, 'final_url_defanged', str),
    redirects_defanged: list(o.redirects_defanged, 'redirects_defanged', readHop),
    title: nullable(o.title, 'title', str),
    loaded: bool(o.loaded, 'loaded'),
    complete: bool(o.complete, 'complete'),
    final_status: nullable(o.final_status, 'final_status', int),
    blocked_requests: int(o.blocked_requests, 'blocked_requests'),
    screenshot_url: nullable(o.screenshot_url, 'screenshot_url', str),
  }
}
