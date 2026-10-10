import type { Filters, ScanDetail } from '../types/scan';
import { detailSchema } from '../api/schema';
import { filterRecords } from '../utils/filters';
import { redactAndDefang } from '../utils/defang';
import { fixture, seedFixtures } from './fixtures';

const storageKey = 'tripwire.recorded-demo.v1';
let memory: ScanDetail[] | undefined;
function read(): ScanDetail[] {
  if (memory) return memory;
  try {
    const raw: unknown = JSON.parse(localStorage.getItem(storageKey) || 'null');
    if (Array.isArray(raw)) {
      const parsed = raw.map(item => detailSchema.safeParse(item));
      if (parsed.every(item => item.success && item.data.isRecorded)) return memory = parsed.map(item => item.data!);
    }
  } catch { /* Storage can be disabled; the current tab remains functional. */ }
  memory = seedFixtures(); save(); return memory;
}
function save() { try { localStorage.setItem(storageKey, JSON.stringify(memory)); } catch { /* Memory-only fallback is disclosed in documentation. */ } }
function snapshot(scan: ScanDetail): ScanDetail {
  if (!scan.id.startsWith('demo-playback-')) return scan;
  const elapsed = Date.now() - Date.parse(scan.submittedAt);
  if (elapsed >= 10000) return scan;
  const done = Math.min(5, Math.max(0, Math.floor((elapsed - 1000) / 1500)));
  return {
    ...scan, revision: done + 1, state: elapsed < 1000 ? 'queued' : 'running', headline: 'Checking this link · recorded playback',
    verdict: done >= 3 ? 'dangerous' : null, score: null, completedAt: null,
    checks: scan.checks.map((c, i) => i < done || i === 5 ? c : { ...c, status: i === done ? 'running' : 'pending', finding: null, outcome: null, evidenceIds: [], finishedAt: null }),
    coverage: { ...scan.coverage, completed: done }, evidence: scan.evidence.slice(0, done), explanation: { lines: [], source: null },
    screenshot: done > 3 ? scan.screenshot : { ...scan.screenshot, state: elapsed < 1000 ? 'pending' : 'capturing', path: null, capturedAt: null },
  };
}
export function demoHistory(filters: Filters, cursor: string | null) {
  const records = filterRecords(read().map(snapshot), filters);
  const offset = cursor ? Number(cursor) : 0;
  return { items: records.slice(offset, offset + 20), totalMatching: records.length, nextCursor: offset + 20 < records.length ? String(offset + 20) : null, serverTime: new Date().toISOString() };
}
export function demoDetail(id: string) {
  const scan = read().find(s => s.id === id);
  if (!scan) throw new Error('This recorded report is unavailable.');
  return snapshot(scan);
}
export function demoCreate(url: string, key: string) {
  const id = `demo-playback-${key}`;
  const existing = read().find(s => s.id === id); if (existing) return existing.id;
  const scan = fixture(id, 'https://toll-payment.test/claim', 'Illustrative scan playback', 'dangerous', 87, 0);
  const display = redactAndDefang(url);
  scan.submittedUrlDisplay = display; scan.finalUrlDisplay = display;
  scan.registeredDomainDisplay = null;
  scan.limitations.unshift('This submission plays the same illustrative findings for every URL; it does not assess your link.');
  memory!.unshift(scan); save(); return id;
}
export function resetDemo() { memory = seedFixtures(); save(); }
