import { useEffect, useReducer, useState } from 'react'
import type { CSSProperties } from 'react'
import '../dashboard.css'
import { CHECKS_PER_SCAN, EMPTY, averageSeconds, focused, inProgress, isDone, position, reduce, shortHost } from '../dashboardState.ts'
import type { DashState, ScanView } from '../dashboardState.ts'
import { connect, parseReplay, replay } from '../events.ts'
import type { ScanEvent } from '../events.ts'
import recording from '../sample/events.sample.json'
import { VERDICT_LABEL } from '../verdict.ts'
import { Brand } from './Brand.tsx'

const CHECK_NAME: Record<string, string> = {
  page_opened: 'Page',
  threat_feeds: 'Threat feeds',
  domain_age: 'Domain age',
  brand_match: 'Brand check',
  sensitive_form: 'Form scan',
  platform_warning: 'Host warning',
}
const OUTCOME_MARK = { flagged: '!', clear: '✓', unavailable: '?' } as const
const REPLAY_PAUSE_MS = 7000 // how long the finished recording stays up before it plays again

type Action = ScanEvent | 'reset'

function step(state: DashState, action: Action): DashState {
  return action === 'reset' ? EMPTY : reduce(state, action)
}

/** ?replay=1 plays the bundled recording on a loop instead of the live stream; ?speed=2 plays it faster. */
function readMode(): { replaying: boolean; speed: number } {
  const params = new URLSearchParams(window.location.search)
  const speed = Number(params.get('speed'))
  return { replaying: params.get('replay') === '1', speed: speed >= 0.25 && speed <= 8 ? speed : 1 }
}

function bubbleKind(scan: ScanView): string {
  return scan.verdict ?? (scan.failed ? 'failed' : 'scanning')
}

function bubbleLabel(scan: ScanView): string {
  if (scan.verdict) return VERDICT_LABEL[scan.verdict]
  if (scan.failed) return "Didn't finish"
  return `Checking ${scan.checks.length}/${CHECKS_PER_SCAN}`
}

function Bubble({ scan, selected, onPick }: { scan: ScanView; selected: boolean; onPick: () => void }) {
  const { left, bottom } = position(scan)
  const kind = bubbleKind(scan)
  return (
    <button
      type="button"
      className={`bubble bubble-${kind}${scan.leaving ? ' leaving' : ''}${selected ? ' selected' : ''}`}
      style={{ left: `${left}%`, bottom: `${bottom}%`, '--delay': `${-(scan.lane * 0.9)}s` } as CSSProperties}
      onClick={onPick}
      aria-pressed={selected}
      aria-label={`${scan.url ?? 'A link'}: ${bubbleLabel(scan)}`}
      tabIndex={scan.leaving ? -1 : 0}
    >
      {scan.verdict === 'dangerous' && (
        <span className="storm" aria-hidden="true">
          <i />
          <i />
          <i />
        </span>
      )}
      <span className="bubble-body">
        <span className="bubble-host">{shortHost(scan.url)}</span>
        <span className="bubble-state">{bubbleLabel(scan)}</span>
        <span className="pips" aria-hidden="true">
          {Array.from({ length: CHECKS_PER_SCAN }, (_, i) => (
            <i key={i} className={scan.checks[i] ? `pip pip-${scan.checks[i].outcome}` : 'pip'} />
          ))}
        </span>
      </span>
      {scan.checks.map((check, i) => (
        <span key={check.check} className="sparkle" style={{ '--turn': `${i * 60 - 30}deg` } as CSSProperties} aria-hidden="true" />
      ))}
    </button>
  )
}

function Screenshot({ scan }: { scan: ScanView }) {
  const [broken, setBroken] = useState<string | null>(null)
  if (scan.screenshotUrl && broken !== scan.screenshotUrl) {
    return (
      <img
        src={scan.screenshotUrl}
        alt="What the sandbox saw when it opened the link, as a phone"
        onError={() => setBroken(scan.screenshotUrl)}
      />
    )
  }
  const waiting = !isDone(scan) && scan.checks.length === 0
  return <p className="shot-empty">{waiting ? 'Opening the page in the sandbox…' : 'No picture of this page.'}</p>
}

function ReplyLine({ scan }: { scan: ScanView }) {
  if (scan.failed && !scan.verdict) return <p className="reply-line">This scan did not finish.</p>
  if (!scan.verdict) return null
  if (scan.replied) return <p className="reply-line sent">Reply sent to {scan.sender ?? 'the sender'}</p>
  if (scan.source === 'web') return <p className="reply-line sent">Shown on the website</p>
  return <p className="reply-line">Sending the reply…</p>
}

function SandboxView({ scan, replaying, pinned, onFollow }: { scan: ScanView | null; replaying: boolean; pinned: boolean; onFollow: () => void }) {
  if (!scan) {
    return (
      <aside className="glass sandbox">
        <h2>Sandbox view</h2>
        <p className="sandbox-empty">
          Waiting for a scan. Text a link to Tripwire, or paste one on the <a href="/">home page</a>, and it will
          appear here step by step.
        </p>
      </aside>
    )
  }
  return (
    <aside className="glass sandbox">
      <div className="sandbox-head">
        <h2>Sandbox view</h2>
        {pinned && (
          <button type="button" className="button small" onClick={onFollow}>
            Follow the latest
          </button>
        )}
      </div>
      <p className="sandbox-link">
        <code>{scan.url ?? 'link'}</code>
      </p>
      <p className="sandbox-from">
        {scan.source === 'web' ? 'From the website' : `From ${scan.sender ?? 'a phone'} over iMessage`}
      </p>

      <div className="sandbox-live">
        <div className="shot-frame">
          <Screenshot scan={scan} />
        </div>

        <ol className="ticker" role="log" aria-live="polite" aria-label="Evidence as it arrives">
          {scan.checks.map((line) => (
            <li key={line.check} className={`tick tick-${line.outcome}`}>
              <span className="tick-mark" aria-hidden="true">
                {OUTCOME_MARK[line.outcome]}
              </span>
              <span className="tick-name">{CHECK_NAME[line.check] ?? line.check}</span>
              <span className="tick-detail">{line.detail}</span>
            </li>
          ))}
          {!isDone(scan) && <li className="tick tick-waiting">Checking…</li>}
        </ol>
      </div>

      {scan.verdict && (
        <div className="sandbox-verdict">
          <p className={`badge badge-${scan.verdict}`}>{VERDICT_LABEL[scan.verdict]}</p>
          {scan.headline && <p className="sandbox-headline">{scan.headline}</p>}
          {scan.reportPath && !replaying && (
            <p>
              <a href={scan.reportPath}>Full report</a>
            </p>
          )}
        </div>
      )}
      <ReplyLine scan={scan} />
    </aside>
  )
}

function Stat({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className={`stat${tone ? ` stat-${tone}` : ''}`}>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  )
}

export function Dashboard() {
  const [{ replaying, speed }] = useState(readMode)
  const [state, dispatch] = useReducer(step, EMPTY)
  const [online, setOnline] = useState(false)
  const [pinned, setPinned] = useState<string | null>(null)

  useEffect(() => {
    if (!replaying) return connect(dispatch, setOnline)
    const items = parseReplay(recording)
    const length = items.length > 0 ? items[items.length - 1].t_ms : 0
    let stop = () => {}
    let again: number | undefined
    const run = () => {
      dispatch('reset')
      stop = replay(items, dispatch, { speed })
      again = window.setTimeout(run, (length + REPLAY_PAUSE_MS) / speed)
    }
    run()
    return () => {
      stop()
      window.clearTimeout(again)
    }
  }, [replaying, speed])

  const shown = focused(state, pinned)
  const average = averageSeconds(state.stats)
  const status = replaying ? 'Replay of a recording' : online ? 'Live' : 'Connecting…'

  return (
    <div className="dash">
      <header className="dash-top">
        <Brand />
        <p className={`dash-status ${replaying ? 'replay' : online ? 'live' : 'waiting'}`} role="status">
          <span className="dash-dot" aria-hidden="true" />
          {status}
        </p>
        <dl className="dash-stats" aria-label="Running totals">
          <Stat label="Scans" value={state.stats.total} />
          <Stat label="In progress" value={inProgress(state)} />
          <Stat label="Dangerous" value={state.stats.dangerous} tone="dangerous" />
          <Stat label="Suspicious" value={state.stats.suspicious} tone="suspicious" />
          <Stat label="No red flags" value={state.stats.no_red_flags} tone="no_red_flags" />
          <Stat label="Couldn't check" value={state.stats.couldnt_check} tone="couldnt_check" />
          <Stat label="Time to verdict" value={average === null ? '–' : `${average} s`} />
        </dl>
      </header>

      <section className="sky" aria-label="Scans, newest rising from the grass">
        {state.scans.map((scan) => (
          <Bubble
            key={scan.id}
            scan={scan}
            selected={shown?.id === scan.id}
            onPick={() => setPinned(pinned === scan.id ? null : scan.id)}
          />
        ))}
      </section>

      <SandboxView scan={shown} replaying={replaying} pinned={pinned !== null && shown?.id === pinned} onFollow={() => setPinned(null)} />
    </div>
  )
}
