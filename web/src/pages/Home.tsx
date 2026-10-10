import { VERDICT_LABEL } from '../verdict.ts'
import { readHistory } from '../history.ts'
import { CheckBox } from './CheckBox.tsx'

export function Home() {
  const recent = readHistory()
  return (
    <main className="page">
      <p className="eyebrow">Tripwire</p>
      <h1>Forward a suspicious text. Get a screenshot and a verdict.</h1>
      <p className="lead">
        Tripwire opens the link in a sandbox so you don&apos;t have to, collects evidence, and texts back what it found
        in about 20 seconds.
      </p>

      <CheckBox />

      {recent.length > 0 && (
        <section className="glass">
          <h2>Recent checks on this device</h2>
          <ul className="history">
            {recent.map((entry) => (
              <li key={entry.id}>
                <a href={`/r/${entry.id}`}>
                  <span className={`badge small badge-${entry.verdict}`}>{VERDICT_LABEL[entry.verdict]}</span>
                  <code>{entry.url}</code>
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}

      <p>
        <a href="/r/sample">See an example report</a>
      </p>
    </main>
  )
}
