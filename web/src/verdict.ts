import type { Verdict } from './contract.ts'

/** How each verdict is worded on screen. The clean verdict never says "safe". */
export const VERDICT_LABEL: Record<Verdict, string> = {
  dangerous: 'Dangerous',
  suspicious: 'Suspicious',
  no_red_flags: 'No red flags found',
  couldnt_check: "Couldn't check",
}

/** One line under the badge for the two verdicts that need a word of explanation. */
export const VERDICT_NOTE: Partial<Record<Verdict, string>> = {
  couldnt_check:
    "We couldn't get a proper look at this page, so this is not a clean result. Don't enter anything until you've checked another way.",
  no_red_flags: "That is not a guarantee. If it asks for a login or payment, go to the official site yourself.",
}
