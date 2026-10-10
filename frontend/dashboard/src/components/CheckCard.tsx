import { Check, AlertTriangle, Clock3, LoaderCircle, Minus, ChevronDown } from 'lucide-react';
import type { EvidenceItem, ScanCheck } from '../types/scan';
import { defangText } from '../utils/defang';
import { formatDate } from '../utils/time';

export function CheckCard({ check, revealed, evidence }: { check: ScanCheck; revealed: boolean; evidence: EvidenceItem[] }) {
  const terminal = !['pending', 'running'].includes(check.status);
  const hasFinding = Boolean(check.finding);
  const warning = revealed && check.outcome === 'concerning';
  const unavailable = ['unavailable', 'error', 'skipped'].includes(check.status);
  const label = terminal && hasFinding && !revealed ? 'Result ready' : check.status === 'running' ? 'Checking' : check.status === 'pending' ? 'Pending' : unavailable ? 'Unavailable' : check.outcome === 'concerning' ? 'Concerning' : check.outcome === 'clear' ? 'No concern observed' : 'Inconclusive';
  const Icon = !revealed && terminal && hasFinding ? Clock3 : check.status === 'running' ? LoaderCircle : check.status === 'pending' ? Clock3 : unavailable ? Minus : warning ? AlertTriangle : Check;
  return <article className={`check-card ${warning ? 'check-concerning' : ''} ${revealed ? 'check-revealed' : ''}`}>
    <span className="check-number" aria-hidden="true">{String(check.order).padStart(2, '0')}</span>
    <div className="check-content"><div className="check-title-line"><h4>{check.label}</h4><span className={`check-status ${warning ? 'text-danger' : ''}`}><Icon size={13} className={check.status === 'running' ? 'spin' : ''} aria-hidden="true" />{label}</span></div>
      {revealed && <><p className="check-finding">{defangText(check.finding || check.limitation || 'No finding is available for this check.')}</p><p className="check-source">Source: {check.source}</p>
        {(evidence.length > 0 || check.limitation) && <details><summary>Evidence details<ChevronDown size={12} aria-hidden="true" /></summary><div className="evidence-details">{evidence.map(item => <div key={item.id}><p>{defangText(item.summary)}</p><p className="small">{item.source} · {formatDate(item.observedAt)}{item.ruleId ? ` · Rule ${item.ruleId}` : ''}{item.points === null ? '' : ` · ${item.points > 0 ? '+' : ''}${item.points} points`}</p></div>)}{check.limitation && <p>Limitation: {check.limitation}</p>}</div></details>}
      </>}
      {!revealed && <p className="check-placeholder">{terminal && hasFinding ? 'Finding ready. Waiting for earlier checks to be explained.' : check.status === 'pending' ? 'Waiting for the analyzer.' : 'The analyzer is collecting evidence.'}</p>}
    </div>
  </article>;
}
