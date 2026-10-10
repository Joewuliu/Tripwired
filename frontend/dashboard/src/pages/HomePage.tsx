import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useInfiniteQuery, useQuery, useQueryClient, type InfiniteData } from '@tanstack/react-query';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import { ArrowUp } from 'lucide-react';
import type { Filters, HistoryPage, ScanDetail } from '../types/scan';
import { ApiError, createScan, exchangeCapability, getHistory, getSession, rescanScan, retryDelay, retryRequest } from '../api/scans';
import { defaultFilters, readFilters, serializeFilters } from '../utils/filters';
import { PhishFinderHeader } from '../components/PhishFinderHeader';
import { ScanInput } from '../components/ScanInput';
import { ScanFilters } from '../components/ScanFilters';
import { ScanList } from '../components/ScanList';
import { ReportDialog } from '../components/ReportDialog';

export function HomePage() {
  const location = useLocation(); const navigate = useNavigate(); const { scanId } = useParams(); const client = useQueryClient();
  const params = useMemo(() => new URLSearchParams(location.search), [location.search]);
  const mode = 'live';
  useEffect(() => {
    if (!params.has('mode')) return;
    const next = new URLSearchParams(location.search); next.delete('mode');
    navigate(`${location.pathname}${next.size ? `?${next}` : ''}`, { replace: true, state: location.state });
  }, [params, location.pathname, location.search, location.state, navigate]);
  const filters = useMemo(() => readFilters(params), [params]);
  const [starting, setStarting] = useState(false); const startingRef = useRef(false);
  const [retryUntil, setRetryUntil] = useState(0); const [clock, setClock] = useState(Date.now());
  const [pending, setPending] = useState<HistoryPage | null>(null); const [pollError, setPollError] = useState('');
  const [actionError, setActionError] = useState('');
  const [expired, setExpired] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null); const [capabilityReady, setCapabilityReady] = useState(!params.has('cap'));
  const capabilityAttempt = useRef('');
  const requestKey = useRef<{ url: string; key: string } | null>(null);
  const session = useQuery({ queryKey: ['session', mode], queryFn: ({ signal }) => getSession(signal), enabled: !expired, retry: retryRequest, retryDelay, staleTime: 60000 });
  const scope = session.data?.scopeKey || 'unconnected';
  const previousScope = useRef<string | null>(null);
  useEffect(() => {
    if (!session.data) return;
    if (previousScope.current && previousScope.current !== session.data.scopeKey) {
      const obsolete = previousScope.current;
      client.removeQueries({ predicate: query => query.queryKey.includes('live') && query.queryKey.includes(obsolete) });
    }
    previousScope.current = session.data.scopeKey;
  }, [mode, session.data, client]);
  const ready = Boolean(session.data) && !expired;
  const onUnauthorized = useCallback(() => {
    setExpired(true);
    client.removeQueries({ predicate: query => query.queryKey.includes('live') });
  }, [client]);
  const historyKey = useMemo(() => ['history', mode, scope, filters] as const, [mode, scope, filters]);
  const fetchPage = useCallback((cursor: string | null, signal?: AbortSignal) => getHistory(filters, cursor, signal), [mode, filters]);
  const history = useInfiniteQuery({ queryKey: historyKey, queryFn: ({ pageParam, signal }) => fetchPage(pageParam, signal), initialPageParam: null as string | null, getNextPageParam: last => last.nextCursor || undefined, enabled: ready, retry: retryRequest, retryDelay });
  const rows = history.data?.pages.flatMap(page => page.items).filter((item, index, items) => items.findIndex(s => s.id === item.id) === index) || [];
  const total = history.data?.pages[0]?.totalMatching || 0;
  const hasFilters = Object.entries(filters).some(([key, value]) => value !== defaultFilters[key as keyof Filters]);
  useEffect(() => { setPending(null); setPollError(''); }, [historyKey]);
  useEffect(() => {
    const timer = setInterval(() => setClock(Date.now()), 1000); return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    if (!ready) return;
    let stopped = false; let controller: AbortController | null = null;
    async function poll() {
      if (document.hidden || stopped) return;
      controller?.abort(); controller = new AbortController();
      try {
        const first = await fetchPage(null, controller.signal); if (stopped) return;
        setPollError('');
        const old = client.getQueryData<InfiniteData<HistoryPage>>(historyKey);
        if (!old) return;
        const oldIds = new Set(old.pages.flatMap(page => page.items.map(item => item.id)));
        const additions = first.items.filter(item => !oldIds.has(item.id));
        if (additions.length && (window.scrollY > 160 || old.pages.length > 1)) { setPending(first); return; }
        client.setQueryData<InfiniteData<HistoryPage>>(historyKey, { pages: [first, ...old.pages.slice(1)], pageParams: old.pageParams });
      } catch (error) {
        if (stopped || controller?.signal.aborted) return;
        if (error instanceof ApiError && error.status === 401) onUnauthorized();
        setPollError(error instanceof Error ? error.message : 'Connection interrupted. Showing saved results.');
      }
    }
    const timer = setInterval(poll, 10000);
    const onVisibility = () => { if (!document.hidden) void poll(); };
    document.addEventListener('visibilitychange', onVisibility);
    return () => { stopped = true; controller?.abort(); clearInterval(timer); document.removeEventListener('visibilitychange', onVisibility); };
  }, [ready, fetchPage, historyKey, client, onUnauthorized]);
  useEffect(() => {
    const capability = params.get('cap');
    if (!capability || !scanId) { setCapabilityReady(true); return; }
    setCapabilityReady(false);
    if (!session.data) return;
    const key = `${scanId}:${capability}`;
    if (capabilityAttempt.current === key) return;
    capabilityAttempt.current = key;
    void exchangeCapability(scanId, capability, session.data).then(() => {
      const next = new URLSearchParams(location.search); next.delete('cap');
      navigate(`${location.pathname}?${next}`, { replace: true, state: location.state });
      setCapabilityReady(true);
    }).catch(() => { setAccessError('This report is unavailable or the link has expired.'); });
  }, [params, scanId, mode, session.data, navigate, location.pathname, location.search, location.state]);
  useEffect(() => {
    if (history.error instanceof ApiError && history.error.status === 401 || session.error instanceof ApiError && session.error.status === 401) onUnauthorized();
  }, [history.error, session.error, onUnauthorized]);
  const changeFilters = useCallback((next: Filters) => {
    const query = serializeFilters(next); 
    navigate(`${location.pathname}?${query}`, { replace: true, state: location.state });
  }, [mode, navigate, location.pathname, location.state]);
  function openReport(id: string, replace = false) {
    const query = serializeFilters(filters); 
    navigate(`/r/${encodeURIComponent(id)}?${query}`, { replace, state: scanId ? location.state : { fromHomepage: true, returnTo: `${location.pathname}${location.search}` } });
  }
  function closeReport() {
    setAccessError(null);
    if (location.state?.fromHomepage) navigate(-1);
    else { const query = serializeFilters(filters);  navigate(`/?${query}`, { replace: true }); }
  }
  async function submit(url: string) {
    if (startingRef.current) return;
    startingRef.current = true; setStarting(true); setActionError('');
    if (!requestKey.current || requestKey.current.url !== url) requestKey.current = { url, key: crypto.randomUUID() };
    try {
      let id: string;
      {
        if (!session.data) throw new Error('The analyzer is not connected. Retry the connection before submitting.');
        id = (await createScan(url, requestKey.current.key, session.data)).id;
      }
      requestKey.current = null;
      await client.invalidateQueries({ queryKey: ['history', mode, scope] });
      openReport(id, Boolean(scanId));
    } catch (error) {
      if (error instanceof ApiError && error.status === 429) setRetryUntil(Date.now() + Math.max(1, error.retryAfterSeconds) * 1000);
      throw error;
    } finally { startingRef.current = false; setStarting(false); }
  }
  async function rescan(scan: ScanDetail) {
    if (!session.data || startingRef.current) return;
    startingRef.current = true; setStarting(true); setActionError('');
    const marker = `rescan:${scan.id}`;
    if (requestKey.current?.url !== marker) requestKey.current = { url: marker, key: crypto.randomUUID() };
    try {
      const result = await rescanScan(scan.id, requestKey.current.key, session.data);
      requestKey.current = null; await client.invalidateQueries({ queryKey: ['history', mode, scope] }); openReport(result.id, true);
    } catch (error) {
      if (error instanceof ApiError && error.status === 429) setRetryUntil(Date.now() + Math.max(1, error.retryAfterSeconds) * 1000);
      throw error;
    } finally { startingRef.current = false; setStarting(false); }
  }
  const newCount = pending ? pending.items.filter(item => !rows.some(row => row.id === item.id)).length : 0;
  const error = expired ? 'Your session has expired. Start a new session to continue.' : history.error?.message || session.error?.message || null;
  return <>
    <div className="aero-landscape" aria-hidden="true" />
    <a className="skip-link" href="#recent-scans-title">Skip to recent scans</a>
    <main className="home-shell">
      <PhishFinderHeader />
      <ScanInput submit={submit} starting={starting} disabled={!ready} retentionDays={session.data?.retentionDays || null} retrySeconds={Math.max(0, Math.ceil((retryUntil - clock) / 1000))} />
      <section className="history-panel glass-panel" aria-labelledby="recent-scans-title"><div className="history-heading"><div><h2 id="recent-scans-title" tabIndex={-1}>Recent scans <span className="count-orb">{total}</span></h2></div></div>
        <ScanFilters filters={filters} onChange={changeFilters} inputTypes={session.data?.inputTypes || ['url']} />
        {pending && <button className="new-scans-button" onClick={() => { client.setQueryData<InfiniteData<HistoryPage>>(historyKey, { pages: [pending], pageParams: [null] }); setPending(null); document.getElementById('recent-scans-title')?.scrollIntoView({ block: 'start' }); }}><ArrowUp size={15} />{newCount} new scans — show</button>}
        <ScanList records={expired ? [] : rows} total={expired ? 0 : total} loading={!expired && (ready && history.isPending || session.isPending)} error={error} hasFilters={hasFilters} onRetry={() => { if (expired) { setExpired(false); } else { void session.refetch(); if (ready) void history.refetch(); } }} onReset={() => changeFilters({ ...defaultFilters })} onOpen={id => openReport(id)} onMore={() => { void history.fetchNextPage(); }} hasMore={Boolean(history.hasNextPage)} fetchingMore={history.isFetchingNextPage} />
        <div className="history-footer"><span className={`status-dot ${pollError || error ? 'offline' : ''}`} aria-hidden="true" /><p>{pollError || (error ? 'Analyzer connection unavailable' : history.dataUpdatedAt ? 'Updated just now' : 'Waiting for connection')}</p></div>
      </section>
    </main>
    {actionError && !scanId && <div className="toast" role="alert">{actionError}<button className="text-button" onClick={() => setActionError('')}>Dismiss</button></div>}
    {scanId && <ReportDialog key={`${mode}:${scanId}`} id={scanId} scope={scope} ready={ready && capabilityReady} accessError={accessError || (expired ? 'Your session has expired. Start a new session to continue.' : session.error ? session.error.message : null)} actionError={actionError} close={closeReport} onUnauthorized={onUnauthorized} rescanning={starting || retryUntil > clock} onRescan={scan => { void rescan(scan).catch(error => setActionError(error instanceof Error ? error.message : 'The scan could not be started.')); }} />}
  </>;
}
