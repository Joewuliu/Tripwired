import { useEffect, useState } from 'react'
import '../card.css'
import { fetchReport } from '../api.ts'
import { CARD_STATES, cardFor, scanningCard } from '../card.ts'
import type { CardModel, CardState } from '../card.ts'
import { SAMPLE_REPORTS } from '../sample/cards.ts'
import { setShareTags } from '../share.ts'
import { VERDICT_LABEL } from '../verdict.ts'
import { Brand } from './Brand.tsx'

type Scheme = 'light' | 'dark' | undefined // undefined: follow the device

function Thumb({ card }: { card: CardModel }) {
  const [broken, setBroken] = useState(false)
  if (card.state === 'scanning') return <div className="vcard-thumb vcard-shimmer" aria-hidden="true" />
  if (card.screenshotUrl && !broken) {
    return (
      <div className="vcard-thumb">
        <img src={card.screenshotUrl} alt="What the page looked like" onError={() => setBroken(true)} />
      </div>
    )
  }
  return <div className="vcard-thumb empty">No picture of this page</div>
}

/** The card itself: one link to the full report. The scanned address inside it is text, never a link. */
export function VerdictCard({ card, scheme }: { card: CardModel; scheme?: Scheme }) {
  const scanning = card.state === 'scanning'
  return (
    <a className={`vcard vcard-${card.state}`} href={card.href} data-scheme={scheme} aria-label={`${card.badge}: ${card.headline}. Open the full report.`}>
      {scanning && (
        <div className="vcard-bubbles" aria-hidden="true">
          <i />
          <i />
          <i />
          <i />
        </div>
      )}
      <div className="vcard-top">
        <span className="wordmark">Phish Finder</span>
        <span className="vcard-badge" role={scanning ? 'status' : undefined}>
          {card.badge}
        </span>
      </div>
      <div className="vcard-headline">{card.headline}</div>
      <div className="vcard-body">
        <Thumb card={card} />
        {scanning ? (
          <div className="vcard-reasons" aria-hidden="true">
            <div className="vcard-line vcard-shimmer" />
            <div className="vcard-line vcard-shimmer" />
            <div className="vcard-line vcard-shimmer" />
          </div>
        ) : (
          <ul className="vcard-reasons">
            {card.reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        )}
      </div>
      {card.link && <code className="vcard-link">{card.link}</code>}
      <div className="vcard-action">{card.action}</div>
    </a>
  )
}

const POLL_MS = 2000
const POLL_TRIES = 45 // a report that has not appeared in 90 seconds is not coming

/** /r/<id>/card: the card for one report. Until the report exists it shows the scanning state. */
export function CardPage({ id }: { id: string }) {
  const [card, setCard] = useState<CardModel | null>(() => (id === 'sample' ? cardFor(SAMPLE_REPORTS.dangerous, 'sample') : scanningCard(id)))
  useEffect(() => {
    if (id === 'sample') return
    let stopped = false
    let timer: number | undefined
    const look = async (attempt: number) => {
      const result = await fetchReport(id)
      if (stopped) return
      if (result.kind === 'ok') {
        setCard(cardFor(result.report, id))
        setShareTags({
          title: `Phish Finder: ${VERDICT_LABEL[result.report.verdict]}`,
          description: result.report.headline,
          image: `/og/${id}.png`,
          path: `/r/${id}`,
        })
      } else if (attempt < POLL_TRIES) {
        timer = window.setTimeout(() => look(attempt + 1), POLL_MS)
      } else {
        setCard(null)
      }
    }
    look(1)
    return () => {
      stopped = true
      window.clearTimeout(timer)
    }
  }, [id])

  return (
    <main className="card-page">
      {card ? (
        <VerdictCard card={card} />
      ) : (
        <p className="glass">
          That report isn&apos;t available. <a href="/">Check a link</a>
        </p>
      )}
    </main>
  )
}

const STATE_NAME: Record<CardState, string> = {
  scanning: 'Scanning',
  dangerous: 'Dangerous',
  suspicious: 'Suspicious',
  no_red_flags: 'No red flags found',
  couldnt_check: "Couldn't check",
}

/** /card-gallery: all five states at once, in light and in dark, from sample data. */
export function CardGallery() {
  const [dark, setDark] = useState(() => new URLSearchParams(window.location.search).get('scheme') === 'dark')
  const scheme: Scheme = dark ? 'dark' : 'light'
  const cards: Record<CardState, CardModel> = {
    scanning: scanningCard('sample'),
    dangerous: cardFor(SAMPLE_REPORTS.dangerous, 'sample'),
    suspicious: cardFor(SAMPLE_REPORTS.suspicious, 'sample'),
    no_red_flags: cardFor(SAMPLE_REPORTS.no_red_flags, 'sample'),
    couldnt_check: cardFor(SAMPLE_REPORTS.couldnt_check, 'sample'),
  }
  return (
    <main className="card-gallery">
      <div className="card-gallery-head">
        <Brand />
        <div className="view-toggle" role="group" aria-label="Light or dark cards">
          <button type="button" className="button small" aria-pressed={!dark} onClick={() => setDark(false)}>
            Light
          </button>
          <button type="button" className="button small" aria-pressed={dark} onClick={() => setDark(true)}>
            Dark
          </button>
        </div>
      </div>
      <p className="glass card-gallery-note">
        The verdict card in its five states, at {390} px wide, from made-up sample data. Each card opens the example
        report. The scanned address is text, never a link.
      </p>
      <div className="card-gallery-grid">
        {CARD_STATES.map((state) => (
          <section key={state} className="card-gallery-item">
            <h2>{STATE_NAME[state]}</h2>
            <VerdictCard card={cards[state]} scheme={scheme} />
          </section>
        ))}
      </div>
    </main>
  )
}
