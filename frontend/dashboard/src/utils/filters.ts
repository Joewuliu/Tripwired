import type { Filters, ScanSummary } from '../types/scan';
import { isActive } from '../types/scan';

export const defaultFilters: Filters = { q: '', window: 'all', risk: 'all', input: 'all', status: 'all', sort: 'newest' };
const allowed: Record<Exclude<keyof Filters, 'q'>, string[]> = {
  window: ['all', '24h', '7d', '30d'], risk: ['all', 'dangerous', 'suspicious', 'no_red_flags', 'unknown'],
  input: ['all', 'url', 'message_screenshot', 'qr_image'], status: ['all', 'running', 'complete', 'partial', 'failed'],
  sort: ['newest', 'oldest', 'risk_desc', 'risk_asc', 'input'],
};
export function readFilters(params: URLSearchParams): Filters {
  const result = { ...defaultFilters, q: (params.get('q') || '').slice(0, 200) };
  for (const key of Object.keys(allowed) as (keyof typeof allowed)[]) {
    const value = params.get(key); if (value && allowed[key].includes(value)) result[key] = value;
  }
  return result;
}
export function serializeFilters(filters: Filters) {
  const params = new URLSearchParams();
  for (const key of Object.keys(filters) as (keyof Filters)[]) if (filters[key] !== defaultFilters[key]) params.set(key, filters[key]);
  return params;
}
export function filterRecords(records: ScanSummary[], filters: Filters, now = Date.now()) {
  const windows: Record<string, number> = { '24h': 86400000, '7d': 604800000, '30d': 2592000000 };
  const filtered = records.filter(scan => {
    const time = Date.parse(scan.submittedAt);
    if (filters.window !== 'all' && (!Number.isFinite(time) || time < now - windows[filters.window])) return false;
    if (filters.input !== 'all' && filters.input !== scan.inputType) return false;
    if (filters.status !== 'all' && !(filters.status === 'running' ? isActive(scan.state) : filters.status === scan.state)) return false;
    if (filters.risk === 'unknown' && (scan.verdict !== null || isActive(scan.state))) return false;
    if (!['all', 'unknown'].includes(filters.risk) && scan.verdict !== filters.risk) return false;
    return `${scan.submittedUrlDisplay || ''} ${scan.headline}`.toLowerCase().includes(filters.q.toLowerCase());
  });
  const newest = (a: ScanSummary, b: ScanSummary) => Date.parse(b.submittedAt) - Date.parse(a.submittedAt) || a.id.localeCompare(b.id);
  return filtered.sort((a, b) => {
    if (filters.sort === 'oldest') return Date.parse(a.submittedAt) - Date.parse(b.submittedAt) || a.id.localeCompare(b.id);
    if (filters.sort.startsWith('risk')) {
      const aScore = isActive(a.state) ? null : a.score, bScore = isActive(b.state) ? null : b.score;
      if (aScore === null && bScore !== null) return 1;
      if (bScore === null && aScore !== null) return -1;
      if (aScore !== null && bScore !== null && aScore !== bScore) return filters.sort === 'risk_desc' ? bScore - aScore : aScore - bScore;
    }
    if (filters.sort === 'input') {
      const order = ['url', 'message_screenshot', 'qr_image'];
      const diff = order.indexOf(a.inputType) - order.indexOf(b.inputType); if (diff) return diff;
    }
    return newest(a, b);
  });
}
