// One example report for each verdict, for the card gallery and the card's tests. They start from
// the shared sample report and change only what a different verdict would change.

import { parseReport } from '../contract.ts'
import type { Report } from '../contract.ts'
import sampleJson from './report.sample.json' with { type: 'json' }

const base = parseReport(sampleJson)

export const SAMPLE_REPORTS: Record<Report['verdict'], Report> = {
  dangerous: {
    ...base,
    headline: "Dangerous: The web address uses the name E-ZPass, but it isn't their real website.",
    observations: [
      "The web address uses the name E-ZPass, but it isn't their real website.",
      'This website was only created 2 days ago.',
      'The page asks for card details.',
      "It isn't on any list of known scam websites.",
    ],
    url_defanged: 'hxxps://ezpass-toll-pay[.]example/pay',
  },
  suspicious: {
    ...base,
    id: 'c81d7e30a9f2',
    verdict: 'suspicious',
    score: 45,
    headline: 'Suspicious: This website was only created 5 days ago.',
    observations: ['This website was only created 5 days ago.', 'The page asks for a password.', "It isn't on any list of known scam websites."],
    url_defanged: 'hxxps://parcel-redelivery-fee[.]example/track/9400110200881234567890?ref=sms&step=confirm-address',
    brand_match: null,
  },
  no_red_flags: {
    ...base,
    id: 'e04b6a15d377',
    verdict: 'no_red_flags',
    score: 0,
    headline: 'No red flags found. That is not a guarantee.',
    observations: ["It isn't on any list of known scam websites.", 'This website was created 30 years ago.'],
    url_defanged: 'hxxps://example[.]com/',
    screenshot_url: '/sample/shot-clean.png',
    brand_match: null,
  },
  couldnt_check: {
    ...base,
    id: '7f29b3c8a1d0',
    verdict: 'couldnt_check',
    score: 10,
    headline: "Couldn't get a proper look at this link. Don't enter anything until you verify it another way.",
    observations: ["That web address doesn't exist, or no longer works.", "It isn't on any list of known scam websites."],
    url_defanged: 'hxxps://account-verify-secure[.]example/x',
    screenshot_url: null,
    loaded: false,
    brand_match: null,
  },
}
