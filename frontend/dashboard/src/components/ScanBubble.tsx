import { ChevronRight } from 'lucide-react';
import type { ScanSummary } from '../types/scan';
import { inputLabels } from '../types/scan';
import { defangUrl } from '../utils/defang';
import { formatDate, formatRelative } from '../utils/time';
import { RiskBadge, riskLabel } from './RiskBadge';
export function ScanBubble({ scan, onOpen }: { scan: ScanSummary; onOpen: (id: string) => void }) {
  const display = defangUrl(scan.submittedUrlDisplay || 'URL extraction pending');
  return <button id={`scan-${scan.id}`} type="button" className="scan-bubble" onClick={() => onOpen(scan.id)} aria-label={`View report for ${display}. ${riskLabel(scan.verdict, scan.state)}. ${formatDate(scan.submittedAt)}. ${scan.headline}`}>
    <span className="scan-bubble-risk"><RiskBadge verdict={scan.verdict} state={scan.state} /></span>
    <span className="scan-bubble-url" dir="ltr">{display}</span>
    <span className="scan-bubble-summary">{scan.headline}{scan.state === 'partial' ? ' · Partial' : ''}</span>
    <time className="scan-bubble-time" dateTime={scan.submittedAt} title={formatDate(scan.submittedAt)}>{formatRelative(scan.submittedAt)}</time>
    <ChevronRight className="row-chevron" size={17} aria-hidden="true" /><span className="sr-only">{inputLabels[scan.inputType]}{scan.isRecorded ? '. Recorded demo' : ''}</span>
  </button>;
}
