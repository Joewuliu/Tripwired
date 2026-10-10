import { useRef, useState } from 'react';
import { Copy, ArrowUpRight, Flag, Check } from 'lucide-react';
import type { ScanDetail } from '../types/scan';
import { reportText } from '../utils/reportText';

export function FtcHandoff({ scan, close, rescan, rescanning }: { scan: ScanDetail; close: () => void; rescan: () => void; rescanning: boolean }) {
  const [open, setOpen] = useState(false); const [copyState, setCopyState] = useState<'idle' | 'copied' | 'manual'>('idle');
  const area = useRef<HTMLTextAreaElement>(null); const summary = reportText(scan);
  async function copy() {
    try { await navigator.clipboard.writeText(summary); setCopyState('copied'); }
    catch { setOpen(true); setCopyState('manual'); requestAnimationFrame(() => { area.current?.focus(); area.current?.select(); }); }
  }
  return <section className="report-actions" aria-label="Report actions">
    <div className="report-actions-top"><div><h3>A suspicious link is worth reporting.</h3><p>Opens the FTC’s official reporting form. You review and submit the report there.</p></div><button className="button button-primary" onClick={() => setOpen(v => !v)} aria-expanded={open} aria-controls="ftc-panel"><Flag size={16} />Report to the FTC</button></div>
    {open && <div className="ftc-panel" id="ftc-panel"><h4>Prepare your report</h4><ol><li>Review the summary below.</li><li>Copy it for the FTC’s reporting form.</li><li>Continue to the FTC and submit there.</li></ol><label htmlFor="ftc-summary">Prepared report summary</label><textarea id="ftc-summary" ref={area} readOnly value={summary} rows={7} /><div className="ftc-buttons"><button className="button" onClick={copy}><Copy size={15} />Copy report summary</button><a className="button button-primary" href="https://reportfraud.ftc.gov/" target="_blank" rel="noopener noreferrer">Continue to FTC<ArrowUpRight size={16} /></a></div><p className="small">PhishFinder cannot confirm submission to the FTC.{scan.isRecorded ? ' This is a demo report; do not submit fictional findings as real evidence.' : ''}</p></div>}
    <div className="secondary-actions"><button className="text-button" onClick={copy}>{copyState === 'copied' ? <Check size={15} /> : <Copy size={15} />}{copyState === 'copied' ? 'Summary copied' : 'Copy report summary'}</button><button className="text-button" onClick={rescan} disabled={rescanning || !scan.submittedUrlDisplay}>{rescanning ? 'Starting scan…' : 'Scan again'}</button><button className="text-button" onClick={close}>Back to scans</button></div>
    <p className="copy-feedback" role="status">{copyState === 'copied' ? 'Report summary copied. This does not submit a report.' : copyState === 'manual' ? 'Copy could not be completed automatically. Select and copy the prepared summary above.' : ''}</p>
  </section>;
}
