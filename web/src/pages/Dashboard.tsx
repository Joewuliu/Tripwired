import { useEffect, useReducer, useRef, useState } from 'react'
import type { CSSProperties, PointerEvent as ReactPointerEvent } from 'react'
import '../dashboard.css'
import {
  CHECKS_PER_SCAN, EMPTY, bubbles, focused, isDone, loadHidden, position, reduce, saveHidden, shortHost, shown, tally,
} from '../dashboardState.ts'
import type { ScanView } from '../dashboardState.ts'
import { connect, parseReplay, replay } from '../events.ts'
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
const UNDO_MS = 6000
const DRAG_STARTS_AT_PX = 6 // less movement than this is a click, not a drag

type Spot = { left: number; bottom: number } // percent of the sky

/**
 * ?replay=1 plays the bundled recording instead of the live stream, over and over; &speed=2 plays
 * it faster and &loop=0 plays it once and leaves the result up.
 */
function readMode(): { replaying: boolean; speed: number; loop: boolean } {
  const params = new URLSearchParams(window.location.search)
  const speed = Number(params.get('speed'))
  return {
    replaying: params.get('replay') === '1',
    speed: speed >= 0.25 && speed <= 8 ? speed : 1,
    loop: params.get('loop') !== '0',
  }
}

function statusLabel(scan: ScanView): string {
  if (scan.verdict) return VERDICT_LABEL[scan.verdict]
  if (scan.failed) return "Didn't finish"
  return 'Checking…'
}

/** The verdict in its colour, or a plain pill while there is none yet. */
function StatusBadge({ scan, small = false }: { scan: ScanView; small?: boolean }) {
  return <span className={`badge${small ? ' small' : ''} badge-${scan.verdict ?? 'pending'}`}>{statusLabel(scan)}</span>
}

function sourceLabel(scan: ScanView): string {
  if (scan.source === 'web') return 'Website'
  return scan.sender ? `iMessage ${scan.sender}` : 'iMessage'
}

function timeLabel(scan: ScanView): string {
  if (!scan.startedAt) return '–'
  return new Date(scan.startedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

interface BubbleProps {
  scan: ScanView
  spot: Spot
  selected: boolean
  dragging: boolean
  onPick: () => void
  onPointerDown: (event: ReactPointerEvent<HTMLButtonElement>) => void
  onPointerMove: (event: ReactPointerEvent<HTMLButtonElement>) => void
  onPointerEnd: (event: ReactPointerEvent<HTMLButtonElement>) => void
}

function Bubble({ scan, spot, selected, dragging, onPick, onPointerDown, onPointerMove, onPointerEnd }: BubbleProps) {
  const kind = scan.verdict ?? (scan.failed ? 'failed' : 'scanning')
  const label = scan.verdict || scan.failed ? statusLabel(scan) : `Checking ${scan.checks.length}/${CHECKS_PER_SCAN}`
  return (
    <button
      type="button"
      className={`bubble bubble-${kind}${scan.leaving ? ' leaving' : ''}${selected ? ' selected' : ''}${dragging ? ' dragging' : ''}`}
      style={{ left: `${spot.left}%`, bottom: `${spot.bottom}%`, '--delay': `${-(scan.lane * 0.9)}s` } as CSSProperties}
      onClick={onPick}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerEnd}
      onPointerCancel={onPointerEnd}
      aria-pressed={selected}
      aria-label={`${scan.url ?? 'A link'}: ${label}`}
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
        <span className="bubble-state">{label}</span>
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

function TrashIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M4 7h16M9.5 7V4.5h5V7M6.5 7l1 12.5h9l1-12.5M10 10.5v6M14 10.5v6" />
    </svg>
  )
}

function Screenshot({ scan }: { scan: ScanView }) {
  const [broken, setBroken] = useState<string | null>(null)
  if (scan.screenshotUrl && broken !== scan.screenshotUrl) {
    return (
      <div className="shot-frame">
        <img
          src={scan.screenshotUrl}
          alt="What the sandbox saw when it opened the link, as a phone"
          onError={() => setBroken(scan.screenshotUrl)}
        />
      </div>
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

function ReportSummary({ scan, replaying, onRemove }: { scan: ScanView | null; replaying: boolean; onRemove: (scan: ScanView) => void }) {
  if (!scan) {
    return (
      <aside className="glass summary">
        <h2>Report Summary</h2>
        <p className="summary-empty">
          Waiting for a scan. Text a link to the phone line, or paste one on the <a href="/">home page</a>, and it
          will appear here step by step.
        </p>
      </aside>
    )
  }
  return (
    <aside className="glass summary">
      <div className="summary-head">
        <h2>Report Summary</h2>
        <StatusBadge scan={scan} />
      </div>
      <p className="summary-link">
        <code>{scan.url ?? 'link'}</code>
      </p>
      <p className="summary-from">
        {scan.source === 'web' ? 'From the website' : `From ${scan.sender ?? 'a phone'} over iMessage`}
      </p>

      <div className="summary-live">
        <Screenshot scan={scan} />
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

      <div className="summary-foot">
        {scan.headline && <p className="summary-headline">{scan.headline}</p>}
        {scan.reportPath && !replaying && (
          <p>
            <a href={scan.reportPath}>Full report</a>
          </p>
        )}
        <ReplyLine scan={scan} />
        {scan.guardians.map((guardian) => (
          <p key={guardian} className="reply-line sent">
            Guardian {guardian} alerted
          </p>
        ))}
        <button type="button" className="button small remove" onClick={() => onRemove(scan)}>
          <TrashIcon /> Remove from this dashboard
        </button>
      </div>
    </aside>
  )
}

function ScanList({ scans, selectedId, onPick, onRemove }: { scans: ScanView[]; selectedId: string | null; onPick: (id: string) => void; onRemove: (scan: ScanView) => void }) {
  if (scans.length === 0) return <p className="glass scan-list scan-list-empty">No scans to show yet.</p>
  return (
    <div className="glass scan-list">
      <table>
        <thead>
          <tr>
            <th>Verdict</th>
            <th>Link</th>
            <th>From</th>
            <th>Time</th>
            <th>
              <span className="visually-hidden">Remove</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id} className={scan.id === selectedId ? 'selected' : undefined} onClick={() => onPick(scan.id)}>
              <td>
                <StatusBadge scan={scan} small />
              </td>
              <td>
                <button
                  type="button"
                  className="row-link"
                  aria-pressed={scan.id === selectedId}
                  onClick={(event) => {
                    event.stopPropagation()
                    onPick(scan.id)
                  }}
                >
                  <code>{scan.url ?? 'link'}</code>
                </button>
              </td>
              <td>{sourceLabel(scan)}</td>
              <td>{timeLabel(scan)}</td>
              <td>
                <button
                  type="button"
                  className="row-remove"
                  aria-label={`Remove ${shortHost(scan.url)} from this dashboard`}
                  onClick={(event) => {
                    event.stopPropagation()
                    onRemove(scan)
                  }}
                >
                  <TrashIcon />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className={`stat${tone ? ` stat-${tone}` : ''}`}>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  )
}

export function Dashboard() {
  const [{ replaying, speed, loop }] = useState(readMode)
  // A recording's ids are the same every time, so what is removed from a replay is not remembered.
  const [state, dispatch] = useReducer(reduce, undefined, () => ({ ...EMPTY, hidden: replaying ? [] : loadHidden() }))
  const [online, setOnline] = useState(false)
  const [pinned, setPinned] = useState<string | null>(null)
  const [view, setView] = useState<'bubbles' | 'list'>('bubbles')
  const [placed, setPlaced] = useState<Record<string, Spot>>({}) // where the viewer dragged a bubble to
  const [dragging, setDragging] = useState<string | null>(null)
  const [overTrash, setOverTrash] = useState(false)
  const [undo, setUndo] = useState<{ id: string; name: string } | null>(null)

  const sky = useRef<HTMLElement>(null)
  const trash = useRef<HTMLDivElement>(null)
  const drag = useRef<{ id: string; x: number; y: number; dx: number; dy: number; moved: boolean } | null>(null)
  const justDragged = useRef<string | null>(null)
  const undoTimer = useRef<number | undefined>(undefined)

  useEffect(() => {
    if (!replaying) return connect(dispatch, setOnline)
    const items = parseReplay(recording)
    const length = items.length > 0 ? items[items.length - 1].t_ms : 0
    let stop = () => {}
    let again: number | undefined
    const run = () => {
      dispatch({ type: 'reset' })
      stop = replay(items, dispatch, { speed })
      if (loop) again = window.setTimeout(run, (length + REPLAY_PAUSE_MS) / speed)
    }
    run()
    return () => {
      stop()
      window.clearTimeout(again)
    }
  }, [replaying, speed, loop])

  useEffect(() => {
    if (!replaying) saveHidden(state.hidden)
  }, [replaying, state.hidden])

  useEffect(() => () => window.clearTimeout(undoTimer.current), [])

  const all = shown(state)
  const selected = focused(state, pinned)
  const counts = tally(state)

  function pick(id: string) {
    setPinned(pinned === id ? null : id)
  }

  function remove(scan: ScanView) {
    dispatch({ type: 'hide', id: scan.id })
    if (pinned === scan.id) setPinned(null)
    setUndo({ id: scan.id, name: shortHost(scan.url) })
    window.clearTimeout(undoTimer.current)
    undoTimer.current = window.setTimeout(() => setUndo(null), UNDO_MS)
  }

  function restore() {
    if (undo) dispatch({ type: 'unhide', id: undo.id })
    window.clearTimeout(undoTimer.current)
    setUndo(null)
  }

  function isOverTrash(x: number, y: number): boolean {
    const box = trash.current?.getBoundingClientRect()
    return !!box && x >= box.left && x <= box.right && y >= box.top && y <= box.bottom
  }

  function startDrag(scan: ScanView, event: ReactPointerEvent<HTMLButtonElement>) {
    if (scan.leaving || (event.pointerType === 'mouse' && event.button !== 0)) return
    const box = event.currentTarget.getBoundingClientRect()
    // Remember where inside the bubble it was grabbed, so it does not jump to the pointer.
    drag.current = {
      id: scan.id, x: event.clientX, y: event.clientY, moved: false,
      dx: event.clientX - (box.left + box.width / 2), dy: event.clientY - (box.top + box.height / 2),
    }
    event.currentTarget.setPointerCapture(event.pointerId)
  }

  function moveDrag(event: ReactPointerEvent<HTMLButtonElement>) {
    const held = drag.current
    const area = sky.current?.getBoundingClientRect()
    if (!held || !area) return
    if (!held.moved && Math.hypot(event.clientX - held.x, event.clientY - held.y) < DRAG_STARTS_AT_PX) return
    held.moved = true
    const clamp = (value: number) => Math.min(97, Math.max(3, value))
    const centreX = event.clientX - held.dx
    const centreY = event.clientY - held.dy
    const half = event.currentTarget.offsetHeight / 2
    setPlaced((spots) => ({
      ...spots,
      [held.id]: {
        left: clamp(((centreX - area.left) / area.width) * 100),
        bottom: Math.min(97, Math.max(-6, ((area.bottom - centreY - half) / area.height) * 100)),
      },
    }))
    setDragging(held.id)
    setOverTrash(isOverTrash(event.clientX, event.clientY))
  }

  function endDrag(scan: ScanView, event: ReactPointerEvent<HTMLButtonElement>) {
    const held = drag.current
    drag.current = null
    if (!held?.moved) return
    justDragged.current = held.id // the click that follows a drag is not a pick
    window.setTimeout(() => (justDragged.current = null), 0)
    if (event.type === 'pointerup' && isOverTrash(event.clientX, event.clientY)) remove(scan)
    setDragging(null)
    setOverTrash(false)
  }

  const status = replaying ? 'Replay of a recording' : online ? 'Live' : 'Connecting…'

  return (
    <div className="dash">
      <header className="dash-top">
        <Brand name="Phish Finder" />
        <p className={`dash-status ${replaying ? 'replay' : online ? 'live' : 'waiting'}`} role="status">
          <span className="dash-dot" aria-hidden="true" />
          {status}
        </p>
        <div className="view-toggle" role="group" aria-label="How scans are shown">
          <button type="button" className="button small" aria-pressed={view === 'bubbles'} onClick={() => setView('bubbles')}>
            Bubbles
          </button>
          <button type="button" className="button small" aria-pressed={view === 'list'} onClick={() => setView('list')}>
            List
          </button>
        </div>
      </header>

      <section className="sky" ref={sky} aria-label={view === 'list' ? 'All scans, newest first' : 'Scans, newest rising from the grass'}>
        <dl className="dash-stats" aria-label="Counts of the scans shown">
          <Stat label="Scans" value={counts.total} />
          <Stat label="Dangerous" value={counts.dangerous} tone="dangerous" />
          <Stat label="Suspicious" value={counts.suspicious} tone="suspicious" />
          <Stat label="No red flags found" value={counts.no_red_flags} tone="no_red_flags" />
          <Stat label="Couldn't check" value={counts.couldnt_check} tone="couldnt_check" />
        </dl>

        {view === 'list' ? (
          <ScanList scans={[...all].reverse()} selectedId={selected?.id ?? null} onPick={pick} onRemove={remove} />
        ) : (
          <>
            {bubbles(state).map((scan) => (
              <Bubble
                key={scan.id}
                scan={scan}
                spot={scan.leaving ? position(scan) : (placed[scan.id] ?? position(scan))}
                selected={selected?.id === scan.id}
                dragging={dragging === scan.id}
                onPick={() => {
                  if (justDragged.current !== scan.id) pick(scan.id)
                }}
                onPointerDown={(event) => startDrag(scan, event)}
                onPointerMove={moveDrag}
                onPointerEnd={(event) => endDrag(scan, event)}
              />
            ))}
            <div ref={trash} className={`trash${dragging ? ' armed' : ''}${overTrash ? ' over' : ''}`} aria-hidden="true">
              <TrashIcon />
              <span>{dragging ? 'Drop to remove' : 'Drag here to remove'}</span>
            </div>
          </>
        )}

        {undo && (
          <p className="toast" role="status">
            Removed {undo.name} from this dashboard.
            <button type="button" className="button small" onClick={restore}>
              Undo
            </button>
          </p>
        )}
      </section>

      <ReportSummary scan={selected} replaying={replaying} onRemove={remove} />
    </div>
  )
}
