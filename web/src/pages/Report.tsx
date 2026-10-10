import { parseReport } from '../contract.ts'
import sampleJson from '../sample/report.sample.json'
import { VERDICT_LABEL } from '../verdict.ts'
import { NotFound } from './NotFound.tsx'

/** Reports of live scans arrive with the report API; until then only the bundled sample exists. */
function loadReport(id: string) {
  return id === 'sample' ? parseReport(sampleJson) : null
}

export function ReportPage({ id }: { id: string }) {
  const report = loadReport(id)
  if (!report) {
    return <NotFound message="That report isn't available." />
  }

  return (
    <main className="page">
      <header className="report-header">
        <p className="eyebrow">Tripwire report</p>
        {id === 'sample' && (
          <p className="sample-note">Example report. The page and the findings are made up for illustration.</p>
        )}
        <p className={`badge badge-${report.verdict}`}>{VERDICT_LABEL[report.verdict]}</p>
        <h1>{report.headline}</h1>
      </header>

      {report.screenshot_url && (
        <figure className="shot">
          <img src={report.screenshot_url} alt="What the sandbox saw when it opened the link, as a phone" />
          <figcaption>What the sandbox saw, in a phone-sized browser.</figcaption>
        </figure>
      )}

      {report.observations.length > 0 && (
        <section>
          <h2>What we found</h2>
          <ul>
            {report.observations.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>
      )}

      <section>
        <h2>Evidence</h2>
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
                    <td className="num">{item.points > 0 ? `+${item.points}` : item.points}</td>
                  </tr>
                ))}
              </tbody>
              {report.score !== null && (
                <tfoot>
                  <tr>
                    <th colSpan={2}>Score</th>
                    <td className="num">{report.score}</td>
                  </tr>
                </tfoot>
              )}
            </table>
          </div>
        )}
        <p className="fineprint">60 or more is dangerous; 30 to 59 is suspicious. The verdict comes from these points, not from an AI model.</p>
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
