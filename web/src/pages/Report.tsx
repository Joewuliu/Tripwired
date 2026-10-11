import { useEffect, useState } from 'react'
import { guidance } from '../actions.ts'
import { fetchReport } from '../api.ts'
import { parseReport } from '../contract.ts'
import type { Report } from '../contract.ts'
import { remember } from '../history.ts'
import { setShareTags } from '../share.ts'
import sampleJson from '../sample/report.sample.json'
import { VERDICT_LABEL, VERDICT_NOTE } from '../verdict.ts'
import { Brand } from './Brand.tsx'
import { CheckBox } from './CheckBox.tsx'
import { NotFound } from './NotFound.tsx'

type Load = { kind: 'loading' } | { kind: 'ready'; report: Report } | { kind: 'missing' } | { kind: 'error'; message: string }

/** /r/sample is the bundled example; every other id is fetched from the report API on this host. */
function useReport(id: string): Load {
  const [load, setLoad] = useState<Load>(() =>
    id === 'sample' ? { kind: 'ready', report: parseReport(sampleJson) } : { kind: 'loading' },
  )
  useEffect(() => {
    if (id === 'sample') return
    const controller = new AbortController()
    fetchReport(id, fetch, controller.signal).then((result) => {
      if (controller.signal.aborted) return
      if (result.kind === 'ok') {
        remember(result.report)
        setShareTags({
          title: 'Phish Finder: ' + VERDICT_LABEL[result.report.verdict],
          description: result.report.headline,
          image: '/og/' + id + '.png',
          path: '/r/' + id,
        })
        setLoad({ kind: 'ready', report: result.report })
      } else {
        setLoad(result)
      }
    })
    return () => controller.abort()
  }, [id])
  return load
}

function signed(points: number): string {
  return points > 0 ? `+${points}` : String(points)
}

/** The rules that moved this scan's score, by id. A rule that fired with 0 points is not "applied". */
function appliedRules(report: Report): Set<string> {
  const applied = new Set<string>()
  for (const item of report.evidence) {
    if (item.points === 0) continue
    applied.add(item.id.split(':')[0])
  }
  return applied
}

function CopyLink() {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(window.location.href)
      setCopied(true)
    } catch {
      setCopied(false) // clipboard blocked: the address bar still has the link
    }
  }
  return (
    <button type="button" className="button" onClick={copy}>
      {copied ? 'Copied' : 'Copy this report link'}
    </button>
  )
}

function WhatToDo({ report }: { report: Report }) {
  const { steps, reportButtons } = guidance(report.verdict, report.brand_match?.official_domain_defanged ?? null)
  return (
    <section className="glass what-to-do">
      <h2>What to do</h2>
      <ol>
        {steps.map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ol>
      <div className="buttons">
        {reportButtons.map((button) => (
          <a key={button.href} className="button" href={button.href} rel="noreferrer noopener" target={button.href.startsWith('sms:') ? undefined : '_blank'}>
            {button.label}
          </a>
        ))}
        <CopyLink />
        <a className="button" href="/">
          Check another link
        </a>
      </div>
    </section>
  )
}

export function ReportPage({ id }: { id: string }) {
  const load = useReport(id)
  if (load.kind === 'loading') {
    return (
      <main className="page">
        <Brand />
        <p role="status" className="glass">
          Loading the report&hellip;
        </p>
      </main>
    )
  }
  if (load.kind === 'missing') {
    return <NotFound message="That report isn't available. It may be old, or the link may be mistyped." />
  }
  if (load.kind === 'error') {
    return (
      <main className="page">
        <Brand />
        <section className="glass">
          <h1>We couldn&apos;t load this report.</h1>
          <p className="notice error" role="alert">
            {load.message}
          </p>
          <p>
            <a href="">Try again</a> &middot; <a href="/">Back to the start</a>
          </p>
        </section>
      </main>
    )
  }

  const { report } = load
  const applied = appliedRules(report)
  const note = VERDICT_NOTE[report.verdict]
  const why = report.verdict === 'couldnt_check' ? report.evidence[0] : undefined
  // Dangerous and suspicious headlines already lead with the top observation.
  const lines = report.observations.filter((line) => !report.headline.endsWith(line) && line !== why?.label).slice(0, 3)

  return (
    <main className="page">
      <Brand />
      <header className={`glass report-header verdict-${report.verdict}`}>
        <p className="eyebrow">Phish Finder report</p>
        {id === 'sample' && (
          <p className="notice">Example report. The page is made up; the findings and points are what Phish Finder&apos;s scorer produces for it.</p>
        )}
        <p className={`badge badge-${report.verdict}`}>{VERDICT_LABEL[report.verdict]}</p>
        <h1>{report.headline}</h1>
        {why && (
          <p className="why">
            <strong>Why we couldn&apos;t check:</strong> {why.label}
          </p>
        )}
        {note && <p className="verdict-note">{note}</p>}
        {lines.length > 0 && (
          <ul className="lines">
            {lines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        )}
        <p className="link-line">
          Link: <code>{report.url_defanged}</code>
        </p>
        {report.explained_by === 'gemini' && (
          <p className="fineprint">
            The wording above was written by an AI model from the findings below. The verdict comes from the
            points, not from the AI.
          </p>
        )}
      </header>

      <WhatToDo report={report} />

      {report.screenshot_url && (
        <figure className="shot glass">
          <img src={report.screenshot_url} alt="What the sandbox saw when it opened the link, as a phone" />
          <figcaption>What the sandbox saw, in a phone-sized browser.</figcaption>
        </figure>
      )}

      {report.brand_match && (
        <section className="glass">
          <h2>Who it looks like</h2>
          <p>
            The address imitates <strong>{report.brand_match.brand}</strong>. The real site is{' '}
            <code>{report.brand_match.official_domain_defanged}</code>.
          </p>
        </section>
      )}

      <section className="glass">
        <h2>What we found</h2>
        {report.evidence.length === 0 ? (
          <p>No evidence recorded for this scan.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Finding</th>
                  <th>Source</th>
                  <th className="num">Points</th>
                </tr>
              </thead>
              <tbody>
                {report.evidence.map((item) => (
                  <tr key={item.id}>
                    <td>{item.label}</td>
                    <td>{item.source}</td>
                    <td className="num">{signed(item.points)}</td>
                  </tr>
                ))}
              </tbody>
              <tfoot>
                <tr>
                  <th colSpan={2}>Score</th>
                  <td className="num">{report.score}</td>
                </tr>
              </tfoot>
            </table>
          </div>
        )}
        <p className="fineprint">
          60 or more is dangerous; 30 to 59 is suspicious; under 30 is &ldquo;no red flags found&rdquo; &mdash; unless we
          couldn&apos;t get a proper look at the page, which is always &ldquo;couldn&apos;t check&rdquo;. The verdict
          comes from these points, not from an AI model.
        </p>
      </section>

      <section className="glass">
        <h2>How the score is worked out</h2>
        <p>This is the whole table Phish Finder uses. The rows in bold are the ones that applied to this scan.</p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Rule</th>
                <th className="num">Points</th>
              </tr>
            </thead>
            <tbody>
              {report.points_table.map((rule) => {
                const did = applied.has(rule.id)
                return (
                  <tr key={rule.id} className={did ? 'applied' : 'not-applied'}>
                    <td>
                      {did && <span className="mark" aria-label="applied">&#9679; </span>}
                      {rule.label}
                    </td>
                    <td className="num">{signed(rule.points)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section className="glass">
        <h2>Where the link went</h2>
        <ol className="hops">
          {report.redirects_defanged.map((hop, i) => (
            <li key={`${i}-${hop.url}`}>
              <span className="status">{hop.status}</span> <code>{hop.url}</code>
            </li>
          ))}
        </ol>
        {report.redirects_defanged.length === 0 && <p>The link was not opened.</p>}
        <p className="fineprint">Addresses are shown defanged (hxxps, [.]) so they cannot be tapped by accident.</p>
      </section>

      <CheckBox label="Check another link" />
    </main>
  )
}
