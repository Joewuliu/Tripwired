import { useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { X, ShieldCheck, Clock3, AlertTriangle, LoaderCircle } from 'lucide-react';
import type { ScanDetail } from '../types/scan';
import { isActive } from '../types/scan';
import { ApiError, getScanDetail, keepNewest, retryDelay, retryRequest } from '../api/scans';
import { defangUrl } from '../utils/defang';
import { formatDate } from '../utils/time';
import { CheckTimeline } from './CheckTimeline';
import { ScreenshotPanel } from './ScreenshotPanel';
import { ReportSummary } from './ReportSummary';
import { FtcHandoff } from './FtcHandoff';

export function ReportDialog({ id, scope, ready, close, onRescan, rescanning, accessError, actionError, onUnauthorized }: { id: string; scope: string; ready: boolean; close: () => void; onRescan: (scan: ScanDetail) => void; rescanning: boolean; accessError: string | null; actionError: string; onUnauthorized: () => void }) {
  const ref = useRef<HTMLDialogElement>(null); const initial = useRef<HTMLHeadingElement>(null);
  const focusedReport = useRef(false);
  const previouslyActive = useRef(false);
  const report = useQuery({ queryKey: ['scan', 'live', scope, id], queryFn: ({ signal }) => getScanDetail(id, signal), enabled: ready && !accessError,
    retry: retryRequest, retryDelay, refetchInterval: query => {
      if (query.state.error || !query.state.data) return false;
      return isActive(query.state.data.state) ? 1500 : false;
    }, refetchIntervalInBackground: false,
    structuralSharing: (old, next) => keepNewest(old as ScanDetail | undefined, next as ScanDetail),
  });
  useEffect(() => {
    const dialog = ref.current!;
    const previous = document.activeElement as HTMLElement | null;
    const position = window.scrollY;
    const bodyOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    dialog.showModal(); initial.current?.focus();
    function trapFocus(event: KeyboardEvent) {
      if (event.key !== 'Tab') return;
      const elements = [...dialog.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), summary, [tabindex="0"]')].filter(element => element.getClientRects().length > 0);
      const first = elements[0], last = elements.at(-1);
      if (event.shiftKey && (document.activeElement === first || document.activeElement === initial.current)) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }
    dialog.addEventListener('keydown', trapFocus);
    return () => {
      dialog.removeEventListener('keydown', trapFocus);
      dialog.close(); document.body.style.overflow = bodyOverflow;
      requestAnimationFrame(() => { window.scrollTo(0, position); (previous?.isConnected ? previous : document.getElementById('recent-scans-title'))?.focus({ preventScroll: true }); });
    };
  }, []);
  const scan = accessError || report.error instanceof ApiError && report.error.status === 401 ? undefined : report.data; const active = scan ? isActive(scan.state) : false;
  useEffect(() => {
    if (!scan) return;
    if (previouslyActive.current && !active) ref.current?.querySelector('.report-dialog-body')?.scrollTo({ top: 0, behavior: 'auto' });
    previouslyActive.current = active;
  }, [scan, active]);
  useEffect(() => {
    if (!scan || focusedReport.current) return;
    focusedReport.current = true;
    if (document.activeElement === document.body || document.activeElement === ref.current || document.activeElement === initial.current) initial.current?.focus();
  }, [scan]);
  useEffect(() => {
    if (report.error instanceof ApiError && report.error.status === 401) onUnauthorized();
  }, [report.error, onUnauthorized]);
  const late = scan && active && Date.now() - Date.parse(scan.submittedAt) > 30000;
  return <dialog ref={ref} className="report-dialog" aria-labelledby="report-title" onCancel={e => { e.preventDefault(); close(); }} onClick={e => { if (e.target === ref.current) { const box = ref.current!.getBoundingClientRect(); if (e.clientX < box.left || e.clientX > box.right || e.clientY < box.top || e.clientY > box.bottom) close(); } }}>
    <div className="report-toolbar"><span className="toolbar-label"><ShieldCheck size={17} aria-hidden="true" />Scan report</span><span className="toolbar-time">{scan ? formatDate(scan.submittedAt) : 'Loading report'}</span><button className="icon-button" aria-label="Close report" onClick={close}><X size={20} /></button></div>
    <div className="report-dialog-body">
      {!scan && <h2 ref={initial} id="report-title" className="loading-title" tabIndex={-1}>Scan report</h2>}
      {(accessError || report.error) && <div className="error-panel" role="status"><p>{accessError || report.error?.message}</p>{!accessError && <button className="button" onClick={() => report.refetch()}>Retry report</button>}<button className="button" onClick={close}>Back to scans</button></div>}
      {!scan && !report.error && !accessError && <div className="report-loading" role="status"><LoaderCircle size={30} className="spin" /><p>Loading this report…</p></div>}
      {scan && <>
        {active && scan.verdict === 'dangerous' && <p className="provisional-warning" role="alert"><AlertTriangle size={18} />Potential threat identified. Avoid entering personal information while the remaining checks finish.</p>}
        <div className="report-top"><div className="report-intro"><h2 ref={initial} id="report-title" tabIndex={-1} className="report-headline">{active ? 'Checking this link.' : scan.headline}</h2>
          <div className="report-url"><span className="field-caption">Submitted link</span><p dir="ltr">{defangUrl(scan.submittedUrlDisplay || 'URL extraction pending')}</p></div>
          {scan.finalUrlDisplay && scan.finalUrlDisplay !== scan.submittedUrlDisplay && <div className="report-url"><span className="field-caption">Observed destination</span><p dir="ltr">{defangUrl(scan.finalUrlDisplay)}</p></div>}
          {scan.registeredDomainDisplay && <p className="small domain-label">Registered domain: <span dir="ltr">{defangUrl(scan.registeredDomainDisplay)}</span></p>}
          {scan.hostnameDisplay && scan.hostnameDisplay.unicode !== scan.hostnameDisplay.ascii && <div className="hostname-variants"><p className="small">Unicode hostname: <span dir="ltr">{defangUrl(scan.hostnameDisplay.unicode)}</span></p><p className="small">ASCII / punycode: <span dir="ltr">{defangUrl(scan.hostnameDisplay.ascii)}</span></p></div>}
          {active && <div className="working-note" role="status"><Clock3 size={16} />{scan.state === 'queued' ? 'Waiting for a scanning slot.' : `${scan.coverage.completed} of ${scan.coverage.required} required checks finished.`}{late && <p>This scan is taking longer than usual. You can close this report and return later.</p>}<p className="small">Closing this report does not cancel the scan.</p></div>}
        </div>
        {!active && <ReportSummary scan={scan} />}
        <ScreenshotPanel key={scan.id} scan={scan} />
        <CheckTimeline key={scan.id} scan={scan} /></div>
        {scan.error && <div className="error-panel"><p>{scan.error.message}</p></div>}
        {actionError && <div className="error-panel" role="alert"><p>{actionError}</p></div>}
        {!active && <FtcHandoff scan={scan} close={close} rescan={() => onRescan(scan)} rescanning={rescanning} />}
        {active && <div className="running-footer"><button className="button" onClick={close}>Back to scans</button><p>You can return to this report as the checks finish.</p></div>}
      </>}
    </div>
  </dialog>;
}
