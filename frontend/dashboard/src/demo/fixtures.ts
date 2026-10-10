import type { ScanCheck, ScanDetail, InputType, Verdict } from '../types/scan';
import { defangUrl } from '../utils/defang';

export const checkLabels = ['Official domain comparison', 'Domain registration age', 'Google Safe Browsing', 'Threat intelligence feeds', 'Page & sensitive form review', 'Visual brand comparison'];
const sources = ['Tripwire verified brand catalog', 'RDAP', 'Google Safe Browsing', 'URLhaus / OpenPhish', 'Tripwire sandbox', 'Visual reference catalog'];
const captureTime = '2026-10-04T15:30:00.000Z';

export function fixture(id: string, raw: string, headline: string, verdict: Verdict | null, score: number | null, ageHours: number, inputType: InputType = 'url', partial = false): ScanDetail {
  const submittedAt = new Date(Date.now() - ageHours * 3600000).toISOString();
  const concerning = verdict === 'dangerous' || verdict === 'suspicious';
  const findings = concerning ? [
    'The destination is outside the verified domains for the claimed service.',
    'Illustrative RDAP observation: the domain was registered 3 days before capture.',
    verdict === 'dangerous' ? 'Illustrative threat-list match recorded for this destination.' : 'No threat-list match in this example. This does not establish legitimacy.',
    'No additional matches in this example. Negative feed results do not guarantee safety.',
    'The example page requests card details on an unofficial domain. No form was submitted.',
    null,
  ] : [
    'The example domain is consistent with the verified brand catalog.',
    'Illustrative RDAP observation: the domain predates the scan by several years.',
    'No threat-list match in this example. This does not guarantee the link is safe.',
    'No matches in the configured example feeds. Coverage is limited to those sources.',
    'No sensitive form fields were observed in this recorded example.', null,
  ];
  const missing = partial || verdict === null;
  const checks: ScanCheck[] = checkLabels.map((label, i) => ({
    id: `check-${i + 1}`, order: i + 1, label,
    status: i === 5 || (missing && i === 2) ? 'unavailable' : 'complete',
    outcome: i === 5 || (missing && i === 2) ? null : concerning && [0, 1, 4, ...(verdict === 'dangerous' ? [2] : [])].includes(i) ? 'concerning' : 'clear',
    finding: i === 5 ? null : missing && i === 2 ? null : findings[i], source: sources[i],
    evidenceIds: i === 5 || (missing && i === 2) ? [] : [`e-${i + 1}`], startedAt: submittedAt, finishedAt: submittedAt,
    limitation: i === 5 ? 'Visual comparison not available. No reference set is configured.' : missing && i === 2 ? 'Threat-list lookup timed out in this example.' : null,
  }));
  return {
    id, revision: 10, inputType, submittedUrlDisplay: defangUrl(raw), headline,
    state: missing ? 'partial' : 'complete', verdict, score, submittedAt, completedAt: submittedAt, isRecorded: true,
    finalUrlDisplay: defangUrl(raw), registeredDomainDisplay: defangUrl(new URL(raw).hostname), checks,
    evidence: checks.filter(c => c.finding).map(c => ({ id: c.evidenceIds[0], ruleId: null, summary: c.finding!, source: c.source, observedAt: submittedAt, points: null })),
    screenshot: {
      state: concerning && !missing ? 'available' : 'unavailable', path: concerning && !missing ? '/demo/toll-capture.png' : null,
      capturedAt: concerning && !missing ? captureTime : null, source: concerning && !missing ? 'tripwire' : null,
      description: concerning ? 'Illustrative payment page with a card-entry form. This local image is a design example, not a live capture.' : null,
    },
    explanation: { lines: verdict === null ? ['Some required checks are unavailable.', 'There is not enough evidence for a reassuring verdict.', 'Verify the request independently through a known official channel.'] : concerning ? ['The claimed service and destination domain do not match.', 'Sensitive information is requested on an unofficial page.', 'Contact the organization through a known official channel.'] : ['No red flags were found in the recorded checks.', 'A negative threat-list result cannot rule out new scams.', 'Verify unexpected requests before sharing personal information.'], source: 'template' },
    coverage: { completed: missing ? 4 : 5, required: 5, missingCheckIds: missing ? ['check-3'] : [] },
    scoringVersion: 'recorded-fixture-v1', limitations: ['Recorded demo - no live scan. All findings are illustrative.', 'Visual comparison is not configured.', ...(missing ? ['Google Safe Browsing was unavailable.'] : [])], error: null,
  };
}
export function seedFixtures(): ScanDetail[] {
  return [
    fixture('demo-toll', 'https://toll-payment.test/claim', 'Possible toll-payment impersonation', 'dangerous', 87, 0.04),
    fixture('demo-delivery', 'https://parcel-update.test/redelivery', 'Delivery notice on an unofficial domain', 'dangerous', 80, 0.5, 'message_screenshot'),
    fixture('demo-account', 'https://account-review.test/verify', 'Account review request needs a closer look', 'suspicious', 45, 1.2),
    fixture('demo-campus', 'https://campus.test/news', 'No red flags found in the available checks', 'no_red_flags', 8, 3),
    fixture('demo-unknown', 'https://unavailable.test/offer', 'Some required checks could not be completed', null, null, 6, 'qr_image', true),
    fixture('demo-partial', 'https://billing-notice.test/payment', 'Unofficial billing page with limited coverage', 'dangerous', 70, 20, 'url', true),
    { ...fixture('demo-failed', 'https://unreachable.test', 'The page could not be observed', null, null, 28), state: 'failed', checks: [], evidence: [], coverage: { completed: 0, required: 5, missingCheckIds: ['check-1', 'check-2', 'check-3', 'check-4', 'check-5'] }, error: { code: 'PAGE_UNAVAILABLE', message: 'No usable analysis was available for this example.', retryable: true } },
    fixture('demo-library', 'https://library.test/catalog', 'No red flags found in the available checks', 'no_red_flags', 0, 50),
    ...Array.from({ length: 17 }, (_, i) => fixture(`demo-archive-${i}`, `https://example-${i}.test/review`, i % 3 === 0 ? 'Domain mismatch in an archived example' : 'Archived example with no red flags', i % 3 === 0 ? 'suspicious' : 'no_red_flags', i % 3 === 0 ? 38 : 12, 72 + i * 6)),
  ];
}
