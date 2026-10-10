import { useState } from 'react'
import type { FormEvent } from 'react'
import { submitLink } from '../api.ts'

type State = { kind: 'idle' } | { kind: 'busy' } | { kind: 'problem'; message: string }

/** Paste a link, wait about 20 seconds in a sandbox, land on its report. For phones that can't text us. */
export function CheckBox({ label = 'Paste a link to check' }: { label?: string }) {
  const [text, setText] = useState('')
  const [state, setState] = useState<State>({ kind: 'idle' })
  const busy = state.kind === 'busy'

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    if (busy || text.trim() === '') return
    setState({ kind: 'busy' })
    const result = await submitLink(text.trim())
    switch (result.kind) {
      case 'ok':
        window.location.assign(`/r/${result.id}`)
        return
      case 'invalid':
        setState({ kind: 'problem', message: "That doesn't look like a web address. Paste just the link, like example.com/page." })
        return
      case 'limited':
        setState({
          kind: 'problem',
          message: `That's a lot of checks from one place. Try again in about ${result.retryMinutes} minute${result.retryMinutes === 1 ? '' : 's'}.`,
        })
        return
      default:
        setState({ kind: 'problem', message: "We couldn't check that right now. Don't open the link until you can verify it another way." })
    }
  }

  return (
    <form className="glass check-box" onSubmit={onSubmit}>
      <label htmlFor="check-url">{label}</label>
      <div className="check-row">
        <input
          id="check-url"
          type="text"
          inputMode="url"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          placeholder="example.com/login"
          value={text}
          disabled={busy}
          onChange={(event) => setText(event.target.value)}
        />
        <button type="submit" className="button primary" disabled={busy || text.trim() === ''}>
          {busy ? 'Checking…' : 'Check it'}
        </button>
      </div>
      <p className="check-help" role="status">
        {busy
          ? 'Opening it in a sandbox. About 20 seconds. Keep this page open.'
          : "We open it in a sandbox, not on your phone. Don't tap suspicious links to test them."}
      </p>
      {state.kind === 'problem' && (
        <p className="notice error" role="alert">
          {state.message}
        </p>
      )}
    </form>
  )
}
