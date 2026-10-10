import { ShieldCheck, ArrowRight, Info } from 'lucide-react';
import type { ScanDetail } from '../types/scan';
import { RiskBadge } from './RiskBadge';
import { defangText } from '../utils/defang';
export function ReportSummary({ scan }: { scan: ScanDetail }) {
  const missing = scan.checks.filter(c => scan.coverage.missingCheckIds.includes(c.id));
  return <section className="report-summary" aria-labelledby="report-summary-title">
    <div className="section-heading"><div><h3 id="report-summary-title">Report summary</h3></div><ShieldCheck size={23} aria-hidden="true" /></div>
    <div className="summary-verdict"><RiskBadge verdict={scan.verdict} state={scan.state} /><span>{scan.score === null ? 'Evidence score unavailable' : `Evidence score: ${scan.score}/100`}</span>{scan.state === 'partial' && <span className="coverage-pill">Partial report</span>}</div>
    <p className="small">{scan.coverage.completed} of {scan.coverage.required} required checks completed. The score describes recorded evidence; it is not a probability.</p>
    <ul className="summary-reasons">{scan.explanation.lines.map((line, i) => <li key={i}><ArrowRight size={15} aria-hidden="true" /><span>{defangText(line)}</span></li>)}</ul>
    {scan.verdict === 'no_red_flags' && <p className="reassurance-limit"><Info size={16} />No red flags found. This does not guarantee the link is safe.</p>}
    {scan.verdict === null && <p className="reassurance-limit"><Info size={16} />There is not enough usable evidence for a reassuring verdict.</p>}
    <div className="next-step-note"><strong>{scan.verdict === 'dangerous' || scan.verdict === 'suspicious' ? 'Pause before responding.' : 'Keep a little caution.'}</strong><p>Use a known official app or independently find the organization’s website. Avoid entering passwords or payment details through an unexpected link.</p>{scan.inputType !== 'url' && <p>For a suspicious text, you may be able to forward the original message to 7726 (SPAM). Carrier support varies.</p>}</div>
    <details className="limitations"><summary>Coverage, sources & limitations</summary><p className="small">Explanation: {scan.explanation.source === 'gemini' ? 'Gemini, based on recorded evidence' : 'Evidence-based template'} · Scoring version: {scan.scoringVersion}</p>{missing.length > 0 && <p>Required checks unavailable: {missing.map(c => c.label).join(', ')}.</p>}<ul>{scan.limitations.map((line, i) => <li key={i}>{defangText(line)}</li>)}</ul></details>
  </section>;
}
