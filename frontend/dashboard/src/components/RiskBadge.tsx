import { LoaderCircle, CircleX } from 'lucide-react';
import type { JobState, Verdict } from '../types/scan';
import { isActive } from '../types/scan';
import { verdictLabels } from '../utils/reportText';

export function riskLabel(verdict: Verdict | null, state: JobState) {
  return isActive(state) ? verdict === 'dangerous' ? 'Potential threat' : 'Analyzing' : state === 'failed' ? 'Failed' : verdict ? verdictLabels[verdict] : 'Unknown';
}
export function RiskBadge({ verdict, state, provisional = false }: { verdict: Verdict | null; state: JobState; provisional?: boolean }) {
  const active = isActive(state);
  const color = verdict === 'dangerous' ? 'dangerous' : active ? 'running' : state === 'failed' ? 'unknown' : verdict || 'unknown';
  const iconPath = verdict === 'dangerous' ? 'vista_firewall_status_2.ico' : verdict === 'suspicious' ? 'vista_firewall_status_3.ico' : verdict === 'no_red_flags' ? 'vista_firewall_status_1.ico' : 'vista_warning.ico';
  return <span className={`risk-badge risk-${color}`}>
    {active && verdict !== 'dangerous' ? <LoaderCircle size={16} className="spin" aria-hidden="true" /> : state === 'failed' ? <CircleX size={16} aria-hidden="true" /> : <img className="risk-icon" src={`/icons/${iconPath}`} width={18} height={18} alt="" aria-hidden="true" />}
    {provisional && verdict === 'dangerous' ? 'Potential threat' : riskLabel(verdict, state)}</span>;
}
