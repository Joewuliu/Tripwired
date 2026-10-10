import { describe, expect, it } from 'vitest';
import { defangUrl, defangText, normalizeInput, redactAndDefang } from '../src/utils/defang';
import { defaultFilters, filterRecords, readFilters, serializeFilters } from '../src/utils/filters';
import { approvedScreenshot, detailSchema } from '../src/api/schema';
import { getScanDetail, getHistory, keepNewest } from '../src/api/scans';
import { vi } from 'vitest';
import { fixture, seedFixtures } from '../src/demo/fixtures';
import { reportText } from '../src/utils/reportText';

describe('URL boundaries', () => {
  it('defangs once and strips directional controls', () => {
    const result = defangUrl('https://example.test/path');
    expect(result).toBe('hxxps://example[.]test/path'); expect(defangUrl(result)).toBe(result);
    expect(defangUrl('https://ex\u202eample.test')).not.toContain('\u202e');
  });
  it('normalizes a single scheme-less URL without visiting it', () => expect(normalizeInput(' example.test/path ')).toBe('https://example.test/path'));
  it('preserves punctuation in prose while defanging embedded links', () => expect(defangText('Check https://example.test/path. Coverage is limited.')).toBe('Check hxxps://example[.]test/path. Coverage is limited.'));
  it.each(['javascript:alert(1)', 'https://user:password@example.test', 'http://127.0.0.1', 'http://192.168.1.3', 'https://one.test https://two.test', '', 'ftp://example.test'])('rejects %s', value => expect(() => normalizeInput(value)).toThrow());
  it('redacts demo query values and email paths', () => {
    const value = redactAndDefang('https://example.test/jane@example.test?token=private#secret');
    expect(value).not.toContain('private'); expect(value).not.toContain('jane'); expect(value).not.toContain('secret');
  });
});
describe('filter semantics', () => {
  const records = seedFixtures();
  it('round-trips URL filters and rejects unsupported enum values', () => {
    const filter = { ...defaultFilters, risk: 'dangerous', q: 'toll', sort: 'risk_desc' };
    expect(readFilters(serializeFilters(filter))).toEqual(filter);
    expect(readFilters(new URLSearchParams('risk=arbitrary')).risk).toBe('all');
  });
  it('combines risk, type, status and text with AND', () => {
    expect(filterRecords(records, { ...defaultFilters, risk: 'dangerous', input: 'url', status: 'complete', q: 'toll' }).map(s => s.id)).toEqual(['demo-toll']);
  });
  it('sorts null scores after all known scores in both risk directions', () => {
    for (const sort of ['risk_asc', 'risk_desc']) {
      const sorted = filterRecords(records, { ...defaultFilters, sort });
      const firstNull = sorted.findIndex(s => s.score === null);
      expect(sorted.slice(firstNull).every(s => s.score === null)).toBe(true);
    }
  });
  it('unknown risk excludes currently running records', () => {
    const running = { ...records[0], id: 'running', verdict: null, score: null, state: 'running' as const };
    expect(filterRecords([...records, running], { ...defaultFilters, risk: 'unknown' }).some(s => s.id === 'running')).toBe(false);
  });
});
describe('reports and transport', () => {
  it('rejects recorded reports and histories returned by the live adapter', async () => {
    const scan = seedFixtures()[0];
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(scan), { status: 200 })));
    await expect(getScanDetail(scan.id)).rejects.toThrow('Recorded demo data');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [scan], nextCursor: null, totalMatching: 1, serverTime: new Date().toISOString() }), { status: 200 })));
    await expect(getHistory(defaultFilters, null)).rejects.toThrow('Recorded demo data');
    vi.unstubAllGlobals();
  });
  it('accepts fixture combinations including partial, null score and failure', () => {
    seedFixtures().forEach(scan => expect(detailSchema.safeParse(scan).success).toBe(true));
  });
  it('rejects invalid scores and timestamps', () => {
    const scan = seedFixtures()[0];
    expect(detailSchema.safeParse({ ...scan, score: 101 }).success).toBe(false);
    expect(detailSchema.safeParse({ ...scan, submittedAt: 'yesterday' }).success).toBe(false);
  });
  it('cannot render third-party or arbitrary screenshots', () => {
    expect(approvedScreenshot('abc', 'https://suspect.test/capture.png')).toBeNull();
    expect(approvedScreenshot('abc', '/api/scans/another/screenshot')).toBeNull();
    expect(approvedScreenshot('abc', '/api/scans/abc/screenshot')).toBe('/api/scans/abc/screenshot');
  });
  it('never replaces a newer report with stale evidence', () => {
    const scan = seedFixtures()[0]; expect(keepNewest(scan, { ...scan, revision: 2 })).toBe(scan);
  });
  it('copy summary preserves Unknown and explicitly marks demos', () => {
    const scan = fixture('demo-null', 'https://example.test', 'Unknown', null, null, 2);
    const text = reportText(scan); expect(text).toContain('Verdict: Unknown'); expect(text).toContain('Evidence score: Unavailable'); expect(text).toContain('Recorded demo'); expect(text).not.toContain('https://example');
  });
});
