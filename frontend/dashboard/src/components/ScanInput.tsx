import { useState, type FormEvent } from 'react';
import { ArrowUpRight, Link2, LockKeyhole, LoaderCircle } from 'lucide-react';
import type { Mode } from '../types/scan';
import { normalizeInput } from '../utils/defang';

export function ScanInput({ mode, submit, starting, disabled, retentionDays, retrySeconds }: { mode: Mode; submit: (url: string) => Promise<void>; starting: boolean; disabled: boolean; retentionDays: number | null; retrySeconds: number }) {
  const [value, setValue] = useState(''); const [error, setError] = useState('');
  async function onSubmit(event: FormEvent) {
    event.preventDefault(); if (starting || disabled || retrySeconds > 0) return;
    setError('');
    try { await submit(normalizeInput(value)); } catch (e) { setError(e instanceof Error ? e.message : 'The scan could not be started. Try again.'); }
  }
  return <section className="scan-input-panel glass-panel" aria-label="Check a link">
    <form onSubmit={onSubmit} noValidate>
      <label id="scan-input-title" htmlFor="suspicious-url">Suspicious URL</label>
      <div className="input-line"><div className="url-input-wrap"><Link2 size={19} aria-hidden="true" /><input id="suspicious-url" value={value} onChange={e => { setValue(e.target.value); setError(''); }} placeholder="Paste a link, such as example.test/payment" type="text" inputMode="url" autoComplete="off" autoCapitalize="none" spellCheck={false} maxLength={4096} aria-invalid={Boolean(error)} aria-describedby={`url-helper url-disclosure${error ? ' url-error' : ''}`} /></div>
        <button className="button button-primary scan-submit" disabled={starting || disabled || retrySeconds > 0} type="submit">{starting ? <><LoaderCircle size={17} className="spin" />Starting scan…</> : retrySeconds > 0 ? `Try again in ${retrySeconds}s` : <>Scan link<ArrowUpRight size={18} aria-hidden="true" /></>}</button>
      </div>
      {error && <p className="inline-error" id="url-error" role="alert">{error}</p>}
      <p id="url-helper" className="input-helper"><LockKeyhole size={13} aria-hidden="true" />PhishFinder opens the link on its scanning server. Results cannot guarantee a site is safe.</p>
      <p id="url-disclosure" className="disclosure">{mode === 'demo' ? 'Demo submissions play illustrative findings only. No link is visited or sent to providers. Display values stay in this browser until you reset the demo.' : `The server visit may notify the site operator. URL or domain data may be shared with configured threat-intelligence providers.${retentionDays ? ` Reports and captures are retained for ${retentionDays} days.` : ' Retention is provided when the analyzer connects.'}`}</p>
    </form>
  </section>;
}
