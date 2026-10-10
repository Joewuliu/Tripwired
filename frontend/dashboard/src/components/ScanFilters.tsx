import { useCallback, useEffect, useState } from 'react';
import { Search, RotateCcw } from 'lucide-react';
import type { Filters, InputType } from '../types/scan';
import { FilterDropdown, type FilterOption } from './FilterDropdown';
import { defaultFilters } from '../utils/filters';

export function ScanFilters({ filters, onChange, inputTypes }: { filters: Filters; onChange: (filters: Filters) => void; inputTypes: InputType[] }) {
  const [openKey, setOpenKey] = useState<string | null>(null);
  const closeDropdown = useCallback(() => setOpenKey(null), []);
  const [search, setSearch] = useState(filters.q);
  useEffect(() => setSearch(filters.q), [filters.q]);
  useEffect(() => {
    if (search === filters.q) return;
    const timer = setTimeout(() => onChange({ ...filters, q: search }), 250); return () => clearTimeout(timer);
  }, [search, filters, onChange]);
  function update(key: keyof Filters, value: string) { onChange({ ...filters, [key]: value }); }
  function dropdown(key: keyof Filters, label: string, caption: string | undefined, options: FilterOption[]) {
    return <FilterDropdown label={label} caption={caption} value={filters[key]} options={options} open={openKey === key} onToggle={() => setOpenKey(current => current === key ? null : key)} onClose={closeDropdown} onChange={value => update(key, value)} />;
  }
  const active = Object.entries(filters).some(([key, value]) => value !== defaultFilters[key as keyof Filters]);
  return <div className="filter-toolbar">
    <div className="search-wrap"><Search size={17} aria-hidden="true" /><input aria-label="Search URL or summary" placeholder="Search URL or summary" value={search} onChange={e => setSearch(e.target.value)} maxLength={200} /></div>
    <div className="filters-grid">
      {dropdown('window', 'Time window', 'Time', [{value:'all',label:'All history'},{value:'24h',label:'Last 24 hours'},{value:'7d',label:'Last 7 days'},{value:'30d',label:'Last 30 days'}])}
      {dropdown('risk', 'Risk', 'Risk', [{value:'all',label:'All levels'},{value:'dangerous',label:'Dangerous'},{value:'suspicious',label:'Suspicious'},{value:'no_red_flags',label:'No red flags found'},{value:'unknown',label:'Unknown'}])}
      {dropdown('input', 'Input type', 'Type', [{value:'all',label:'All inputs'}, ...(['url','message_screenshot','qr_image'] as InputType[]).map((type, i) => ({value:type,label:['URL','Message screenshot','QR image'][i] + (!inputTypes.includes(type) ? ' · Not connected yet' : ''),disabled:!inputTypes.includes(type)}))])}
      {dropdown('status', 'Status', 'Status', [{value:'all',label:'All statuses'},{value:'running',label:'Running'},{value:'complete',label:'Complete'},{value:'partial',label:'Partial'},{value:'failed',label:'Failed'}])}
    </div>
    <div className="sort-control">{dropdown('sort', 'Sort scans', undefined, [{value:'newest',label:'Newest first'},{value:'oldest',label:'Oldest first'},{value:'risk_desc',label:'Highest risk first'},{value:'risk_asc',label:'Lowest risk first'},{value:'input',label:'Input type'}])}</div>
    {active && <button className="reset-button" onClick={() => { setSearch(''); onChange({ ...defaultFilters }); }}><RotateCcw size={14} />Reset filters</button>}
  </div>;
}
