import { useEffect, useRef, useState } from 'react';
import type { ScanDetail } from '../types/scan';
import { isActive } from '../types/scan';
import { CheckCard } from './CheckCard';

export function CheckTimeline({ scan }: { scan: ScanDetail }) {
  const checks = [...scan.checks].sort((a, b) => a.order - b.order);
  const [visible, setVisible] = useState(0);
  const [showAll, setShowAll] = useState(false);
  const [reduced, setReduced] = useState(() => matchMedia('(prefers-reduced-motion: reduce)').matches);
  const wasActive = useRef(isActive(scan.state));
  const pacingStarted = useRef<number | null>(null);
  useEffect(() => {
    const query = matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setReduced(query.matches); query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, []);
  let eligible = 0;
  for (const check of checks) { if (['pending', 'running'].includes(check.status)) break; eligible++; }
  const instant = reduced || showAll || !wasActive.current;
  useEffect(() => {
    if (instant || visible >= eligible) return;
    // Across a fast burst, add at most 1.5 seconds of educational pacing.
    if (pacingStarted.current === null) pacingStarted.current = Date.now();
    if (Date.now() - pacingStarted.current >= 1500) { setVisible(eligible); return; }
    const timer = setTimeout(() => setVisible(n => Math.min(n + 1, eligible)), 300);
    return () => clearTimeout(timer);
  }, [eligible, visible, instant]);
  const displayed = instant ? checks.length : visible;
  const finished = checks.filter(c => !['pending', 'running'].includes(c.status)).length;
  return <section className="checks-section" aria-labelledby="checks-heading">
    <div className="section-heading"><div><h3 id="checks-heading">A closer look</h3></div><span className="coverage-pill">{finished} of {checks.length} checks finished</span></div>
    <p className="checks-description">Each check adds context. No single clear result guarantees safety.</p>
    {isActive(scan.state) && <button className="text-button" onClick={() => setShowAll(true)} disabled={showAll}>Show all available findings</button>}
    <div className="check-timeline">{checks.map((check, index) => <CheckCard key={check.id} check={check} revealed={!['pending', 'running'].includes(check.status) && (instant || index < displayed)} evidence={scan.evidence.filter(e => check.evidenceIds.includes(e.id))} />)}</div>
    <p className="sr-only" aria-live="polite">{finished} of {checks.length} checks finished.{!isActive(scan.state) ? ' Report complete.' : ''}</p>
  </section>;
}
