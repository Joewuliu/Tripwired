import { SearchX, Inbox, LoaderCircle, ArrowDown } from 'lucide-react';
import type { ScanSummary } from '../types/scan';
import { ScanBubble } from './ScanBubble';

export function ScanList({ records, loading, total, hasFilters, error, onRetry, onReset, onOpen, onMore, hasMore, fetchingMore }: { records: ScanSummary[]; loading: boolean; total: number; hasFilters: boolean; error: string | null; onRetry: () => void; onReset: () => void; onOpen: (id: string) => void; onMore: () => void; hasMore: boolean; fetchingMore: boolean }) {
  if (loading) return <div className="scan-skeletons" role="status" aria-label="Loading recent scans">{Array.from({ length: 5 }, (_, i) => <div key={i} className="scan-skeleton" />)}<span className="sr-only">Loading recent scans</span></div>;
  return <>
    {error && <div className="error-panel" role="status"><p>{error}</p><button className="button button-small" onClick={onRetry}>Retry connection</button></div>}
    <div className="result-line"><p role="status" aria-live="polite">{total === 1 ? '1 scan' : `${total} scans`}{hasFilters ? ' match these filters' : ' in your history'}</p><span className="list-guide">LINK <span>/</span> VERDICT <span>/</span> FINDING</span></div>
    {!records.length && !error && <div className="empty-state">{hasFilters ? <SearchX size={28} /> : <Inbox size={28} />}<h3>{hasFilters ? 'No scans match these filters.' : 'No scans yet.'}</h3><p>{hasFilters ? 'Try another search or reset your filters.' : 'Paste a suspicious link to start.'}</p><button className="button" onClick={hasFilters ? onReset : () => document.getElementById('suspicious-url')?.focus()}>{hasFilters ? 'Reset filters' : 'Check a link'}</button></div>}
    <div className="scan-rows">{records.map(scan => <ScanBubble key={scan.id} scan={scan} onOpen={onOpen} />)}</div>
    {hasMore && <div className="load-more"><button className="button" disabled={fetchingMore} onClick={onMore}>{fetchingMore ? <><LoaderCircle size={15} className="spin" />Loading…</> : <>Load more<ArrowDown size={15} /></>}</button><p>{records.length} of {total} scans</p></div>}
  </>;
}
