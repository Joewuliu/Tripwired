import type { ScanDetail } from '../types/scan';
import { defangUrl, defangText } from './defang';
import { formatDate } from './time';
export const verdictLabels = { dangerous: 'Dangerous', suspicious: 'Suspicious', no_red_flags: 'No red flags found' };
export function reportText(scan: ScanDetail): string {
  return [
    'Tripwire scan report', scan.isRecorded ? 'Recorded demo - no live scan. Findings are illustrative.' : '',
    `Scanned: ${formatDate(scan.submittedAt)}`,
    `Submitted link: ${defangUrl(scan.submittedUrlDisplay || 'URL extraction pending')}`,
    scan.finalUrlDisplay ? `Observed destination: ${defangUrl(scan.finalUrlDisplay)}` : '',
    `Verdict: ${scan.verdict ? verdictLabels[scan.verdict] : 'Unknown'}`,
    `Evidence score: ${scan.score === null ? 'Unavailable' : `${scan.score}/100`}`,
    `Coverage: ${scan.coverage.completed} of ${scan.coverage.required} required checks`,
    ...scan.checks.filter(c => c.finding).map(c => `${c.label}: ${defangText(c.finding!)} (Source: ${c.source})`),
    ...scan.limitations.map(l => `Limitation: ${defangText(l)}`),
    'Results cannot guarantee a site is safe. The evidence score is not a probability.',
  ].filter(Boolean).join('\n');
}
