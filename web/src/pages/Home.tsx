import { VERDICT_LABEL } from '../verdict.ts'
import { readHistory } from '../history.ts'
import { Brand } from './Brand.tsx'
import { CheckBox } from './CheckBox.tsx'

export function Home() {
  const recent = readHistory()
  return (
    <main className="page">
      <Brand />
      <section className="glass">
        <h1>Forward a suspicious text. Get a screenshot and a verdict.</h1>
        <p className="lead">
          Phish Finder opens the link in a sandbox so you don&apos;t have to, collects evidence, and texts back what it
          found in about 20 seconds.
        </p>
        <p>
          <a href="/r/sample">See an example report</a> &middot; <a href="/dashboard">Watch scans live</a>
        </p>
      </section>

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
    </main>
  )
}
