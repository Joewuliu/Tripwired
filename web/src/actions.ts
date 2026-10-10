import type { Verdict } from './contract.ts'

/** A reporting service the person can open. These are fixed here: nothing from a report or a scanned
 *  page ever becomes a link on the page (addresses in reports stay defanged). */
export interface ReportButton {
  label: string
  href: string
}

export interface Guidance {
  /** What to do, in order. Plain sentences. */
  steps: string[]
  /** Where to report it, for the verdicts where reporting is worth the person's time. */
  reportButtons: ReportButton[]
}

const TEXT_7726: ReportButton = { label: 'Forward the text to 7726 (SPAM)', href: 'sms:7726' }
const GOOGLE: ReportButton = {
  label: 'Report the page to Google',
  href: 'https://safebrowsing.google.com/safebrowsing/report_phish/',
}
const FTC: ReportButton = { label: 'Report it to the FTC', href: 'https://reportfraud.ftc.gov' }

/** The official-site step: our own brand list's domain, shown defanged so it cannot be tapped. */
function officialStep(officialDefanged: string | null): string {
  return officialDefanged
    ? `Go to the official site yourself: open your browser and type ${officialDefanged} (without the brackets). Don't use the link or any phone number in the message.`
    : "Go to the official site yourself: open your browser and type the company's address, or use its app. Don't use the link or any phone number in the message."
}

/** What to do for each verdict. The clean verdict never says "safe". */
export function guidance(verdict: Verdict, officialDefanged: string | null = null): Guidance {
  switch (verdict) {
    case 'dangerous':
      return {
        steps: [
          "Don't tap the link, and don't enter anything on that page.",
          officialStep(officialDefanged),
          'If you already typed a password or card number, change that password on the real site now and call your bank or card company.',
          'Report it, then delete the message.',
        ],
        reportButtons: [TEXT_7726, GOOGLE, FTC],
      }
    case 'suspicious':
      return {
        steps: [
          "Don't enter passwords or payment details on that page.",
          officialStep(officialDefanged),
          'Ask the sender through a phone number or site you already trust whether they really sent it.',
          'If it looks like a scam, report it.',
        ],
        reportButtons: [TEXT_7726, GOOGLE],
      }
    case 'couldnt_check':
      return {
        steps: [
          "Don't enter anything on that page. We couldn't get a proper look at it, so this is not a clean result.",
          'Contact the sender or company through a phone number or site you already trust.',
          'You can paste the link again in a minute: some pages are slow or only load for a moment.',
        ],
        reportButtons: [TEXT_7726],
      }
    case 'no_red_flags':
      return {
        steps: [
          'That is not a guarantee. If the page asks for a login or payment, go to the official site yourself instead.',
          "If the message pressured you to act quickly, that's a reason to check with the sender another way.",
        ],
        reportButtons: [],
      }
  }
}
