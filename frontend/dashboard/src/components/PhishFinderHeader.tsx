import { Radio, FlaskConical } from 'lucide-react';
import type { Mode } from '../types/scan';

export function PhishFinderHeader({ mode, connected }: { mode: Mode; connected: boolean }) {
  return <header className="phishfinder-header">
    <div className="brand"><img className="brand-logo" src="/icons/clownfish.png" width={66} height={66} alt="" aria-hidden="true" />
      <div><h1 className="brand-title">PhishFinder</h1><p className="subtitle">Check suspicious links without opening them on your device.</p></div>
    </div>
    <div className="header-meta"><span className="creator-bubble">Created by Joseph, Peter, Srijith.</span>
      <span className="connection-status">{mode === 'demo' ? <FlaskConical size={14} /> : <Radio size={14} />} {mode === 'demo' ? 'Recorded demo' : connected ? 'Analyzer connected' : 'Analyzer not connected'}</span>
    </div>
  </header>;
}
