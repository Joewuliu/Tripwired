import type { Verdict } from './contract.ts'

/** How each verdict is worded on screen. The clean verdict never says "safe". */
export const VERDICT_LABEL: Record<Verdict, string> = {
  dangerous: 'Dangerous',
  suspicious: 'Suspicious',
  no_red_flags: 'No red flags found',
  couldnt_check: "Couldn't check",
  unscored: 'Opened, no verdict yet',
}
