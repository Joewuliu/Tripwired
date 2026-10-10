import { useEffect, useState } from 'react';
import { Search, RotateCcw, SlidersHorizontal } from 'lucide-react';
import type { Filters, InputType } from '../types/scan';
import { defaultFilters } from '../utils/filters';

export function ScanFilters({ filters, onChange, inputTypes }: { filters: Filters; onChange: (filters: Filters) => void; inputTypes: InputType[] }) {
  const [search, setSearch] = useState(filters.q);
  useEffect(() => setSearch(filters.q), [filters.q]);
  useEffect(() => {
    if (search === filters.q) return;
    const timer = setTimeout(() => onChange({ ...filters, q: search }), 250); return () => clearTimeout(timer);
  }, [search, filters, onChange]);
  function update(key: keyof Filters, value: string) { onChange({ ...filters, [key]: value }); }
  const active = Object.entries(filters).some(([key, value]) => value !== defaultFilters[key as keyof Filters]);
  return <div className="filter-toolbar">
    <div className="search-wrap"><Search size={17} aria-hidden="true" /><input aria-label="Search URL or summary" placeholder="Search URL or summary" value={search} onChange={e => setSearch(e.target.value)} maxLength={200} /></div>
    <div className="filters-grid">
      <label className="filter-control"><span>Time</span><select aria-label="Time window" value={filters.window} onChange={e => update('window', e.target.value)}><option value="all">All history</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option></select></label>
      <label className="filter-control"><span>Risk</span><select aria-label="Risk" value={filters.risk} onChange={e => update('risk', e.target.value)}><option value="all">All levels</option><option value="dangerous">Dangerous</option><option value="suspicious">Suspicious</option><option value="no_red_flags">No red flags found</option><option value="unknown">Unknown</option></select></label>
      <label className="filter-control"><span>Type</span><select aria-label="Input type" value={filters.input} onChange={e => update('input', e.target.value)}><option value="all">All inputs</option>{(['url', 'message_screenshot', 'qr_image'] as InputType[]).map((type, i) => <option key={type} value={type} disabled={!inputTypes.includes(type)}>{['URL', 'Message screenshot', 'QR image'][i]}{!inputTypes.includes(type) ? ' · Not connected yet' : ''}</option>)}</select></label>
      <label className="filter-control"><span>Status</span><select aria-label="Status" value={filters.status} onChange={e => update('status', e.target.value)}><option value="all">All statuses</option><option value="running">Running</option><option value="complete">Complete</option><option value="partial">Partial</option><option value="failed">Failed</option></select></label>
    </div>
    <label className="sort-control"><SlidersHorizontal size={15} aria-hidden="true" /><span className="sr-only">Sort scans</span><select aria-label="Sort scans" value={filters.sort} onChange={e => update('sort', e.target.value)}><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="risk_desc">Highest risk first</option><option value="risk_asc">Lowest risk first</option><option value="input">Input type</option></select></label>
    {active && <button className="reset-button" onClick={() => { setSearch(''); onChange({ ...defaultFilters }); }}><RotateCcw size={14} />Reset filters</button>}
  </div>;
}
