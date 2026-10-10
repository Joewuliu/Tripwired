import { parseReport } from '../contract.ts'
import type { Report } from '../contract.ts'
import sampleJson from '../sample/report.sample.json'
import { VERDICT_LABEL, VERDICT_NOTE } from '../verdict.ts'
import { NotFound } from './NotFound.tsx'

/** Reports of live scans arrive with the report API; until then only the bundled sample exists. */
function loadReport(id: string): Report | null {
  return id === 'sample' ? parseReport(sampleJson) : null
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

export function ReportPage({ id }: { id: string }) {
  const report = loadReport(id)
  if (!report) {
    return <NotFound message="That report isn't available." />
  }
  const applied = appliedRules(report)
  const note = VERDICT_NOTE[report.verdict]

  return (
    <main className="page">
      <header className="report-header">
        <p className="eyebrow">Tripwire report</p>
        {id === 'sample' && (
          <p className="sample-note">Example report. The page is made up; the findings and points are what Tripwire's scorer produces for it.</p>
        )}
        <p className={`badge badge-${report.verdict}`}>{VERDICT_LABEL[report.verdict]}</p>
        <h1>{report.headline}</h1>
        {note && <p className="verdict-note">{note}</p>}
      </header>

      {report.screenshot_url && (
        <figure className="shot">
          <img src={report.screenshot_url} alt="What the sandbox saw when it opened the link, as a phone" />
          <figcaption>What the sandbox saw, in a phone-sized browser.</figcaption>
        </figure>
      )}

      <section>
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

      <section>
        <h2>How the score is worked out</h2>
        <p>This is the whole table Tripwire uses. The rows in bold are the ones that applied to this scan.</p>
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

      <section>
        <h2>Where the link went</h2>
        <ol className="hops">
          {report.redirects_defanged.map((hop, i) => (
            <li key={`${i}-${hop.url}`}>
              <span className="status">{hop.status}</span> <code>{hop.url}</code>
            </li>
          ))}
        </ol>
        {report.redirects_defanged.length === 0 && <p>The link was not opened.</p>}
      </section>

      <p className="fineprint">Addresses are shown defanged (hxxps, [.]) so they cannot be tapped by accident.</p>
    </main>
  )
}
