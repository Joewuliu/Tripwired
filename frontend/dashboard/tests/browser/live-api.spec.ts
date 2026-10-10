import { test, expect, type Page } from '@playwright/test';
import { fixture } from '../../src/demo/fixtures';

const session = { scopeKey: 'test-scope', csrfToken: 'test-csrf', retentionDays: 7, inputTypes: ['url'], scanTimeoutSeconds: 45 };
function liveFixture(id = 'live-example') {
  const result = fixture(id, 'https://public-example.test/payment', 'Potential billing impersonation', 'dangerous', 87, 0.05);
  return { ...result, isRecorded: false, screenshot: { ...result.screenshot, state: 'unavailable' as const, path: null, capturedAt: null, source: null }, limitations: ['Visual matching is not configured.'] };
}
async function setup(page: Page) {
  await page.route('**/api/session', route => route.fulfill({ json: session }));
  await page.route('**/api/scans?*', route => route.fulfill({ json: { items: [liveFixture()], totalMatching: 1, nextCursor: null, serverTime: new Date().toISOString() } }));
}
test('live submission uses same-origin API, CSRF and idempotency; analyzer controls progress', async ({ page }) => {
  await setup(page);
  let reads = 0; let submissions = 0;
  await page.route('**/api/scans', async route => {
    submissions++; const request = route.request();
    expect(request.method()).toBe('POST'); expect(request.headers()['x-csrf-token']).toBe('test-csrf');
    expect(request.headers()['idempotency-key']).toMatch(/^[\da-f-]{36}$/);
    expect(request.postDataJSON()).toEqual({ url: 'https://public-example.test/payment', inputType: 'url' });
    await route.fulfill({ status: 202, json: { id: 'live-new', state: 'queued', revision: 1, reportPath: '/r/live-new', detailPath: '/api/scans/live-new' } });
  });
  await page.route('**/api/scans/live-new', route => {
    reads++; const scan = liveFixture('live-new');
    return route.fulfill({ json: reads < 3 ? { ...scan, state: 'running', completedAt: null, score: null, revision: reads, checks: scan.checks.map(c => ({ ...c, status: 'running', finding: null, outcome: null })), coverage: { completed: 0, required: 5, missingCheckIds: [] }, explanation: { lines: [], source: null } } : { ...scan, revision: 3 } });
  });
  await page.goto('/?mode=live'); await expect(page.getByRole('button', { name: 'Scan link', exact: true })).toBeEnabled();
  await page.getByLabel('Suspicious URL', { exact: true }).fill('public-example.test/payment');
  await page.getByRole('button', { name: 'Scan link', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('Potential threat identified');
  await expect(page.locator('.report-summary')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Report summary', exact: true })).toBeVisible({ timeout: 10000 });
  await expect(page.locator('.report-intro .risk-badge')).toHaveCount(0);
  expect(await page.locator('.report-summary').evaluate(element => Boolean(element.compareDocumentPosition(document.querySelector('.checks-section')!) & Node.DOCUMENT_POSITION_FOLLOWING))).toBe(true);
  expect(submissions).toBe(1); await expect(page.getByRole('dialog')).not.toContainText('Recorded demo');
});
test('429 honors Retry-After and preserves the input', async ({ page }) => {
  await setup(page);
  await page.route('**/api/scans', route => route.fulfill({ status: 429, headers: { 'Retry-After': '5' }, json: { error: { message: 'Too many scans.', retryable: true } } }));
  await page.goto('/?mode=live'); await expect(page.getByRole('button', { name: 'Scan link', exact: true })).toBeEnabled();
  await page.getByLabel('Suspicious URL', { exact: true }).fill('public-example.test');
  await page.getByRole('button', { name: 'Scan link', exact: true }).click();
  await expect(page.getByLabel('Suspicious URL', { exact: true })).toHaveValue('public-example.test');
  await expect(page.locator('.scan-submit')).toBeDisabled();
  await expect(page.locator('#url-error')).toContainText('Too many scans');
});
test('clipboard denial reveals a selectable summary without claiming FTC submission', async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(navigator, 'clipboard', { value: { writeText: () => Promise.reject(new Error('denied')) } }));
  await setup(page);
  await page.route('**/api/scans/live-example', route => route.fulfill({ json: liveFixture() }));
  await page.goto('/r/live-example');
  await page.getByRole('button', { name: 'Copy report summary', exact: true }).click();
  await expect(page.getByLabel('Prepared report summary')).toBeVisible();
  await expect(page.getByLabel('Prepared report summary')).toBeFocused();
  await expect(page.locator('.copy-feedback')).toContainText('Copy could not be completed automatically');
  await expect(page.getByRole('dialog')).not.toContainText('Reported successfully');
});
test('report capabilities are exchanged and removed, without leaking into history requests', async ({ page }) => {
  await setup(page);
  const historyUrls: string[] = [];
  page.on('request', request => { if (request.url().includes('/api/scans?')) historyUrls.push(request.url()); });
  await page.route('**/api/report-access', route => {
    expect(route.request().postDataJSON()).toEqual({ scanId: 'live-example', capability: 'test-private-capability' });
    return route.fulfill({ status: 204 });
  });
  await page.route('**/api/scans/live-example', route => route.fulfill({ json: liveFixture() }));
  await page.goto('/r/live-example?mode=live&cap=test-private-capability');
  await expect(page.getByRole('heading', { name: 'Potential billing impersonation' })).toBeVisible();
  await expect(page).not.toHaveURL(/cap=/);
  expect(historyUrls.every(url => !url.includes('capability') && !url.includes('cap='))).toBe(true);
});
test('provider text stays escaped and foreign screenshot URLs never load', async ({ page }) => {
  await setup(page);
  const attempted: string[] = []; page.on('request', request => attempted.push(request.url()));
  const scan = liveFixture(); scan.checks[0].finding = '<img src="https://suspect.test/steal" onerror="alert(1)">';
  await page.route('**/api/scans/live-example', route => route.fulfill({ json: { ...scan, screenshot: { ...scan.screenshot, state: 'available', path: 'https://suspect.test/image.png' } } }));
  await page.goto('/r/live-example?mode=live');
  await expect(page.locator('.check-finding').first()).toContainText('<img');
  await expect(page.locator('.screenshot-placeholder')).toContainText('No screenshot available');
  expect(attempted.some(url => url.includes('suspect.test'))).toBe(false);
});
test('scan again asks the server to reuse the protected URL rather than sending redacted text', async ({ page }) => {
  await setup(page);
  await page.route('**/api/scans/live-example', route => route.fulfill({ json: liveFixture() }));
  await page.route('**/api/scans/live-example/rescan', route => {
    expect(route.request().postDataJSON()).toEqual({});
    expect(route.request().headers()['x-csrf-token']).toBe('test-csrf');
    return route.fulfill({ status: 202, json: { id: 'live-rescan', state: 'queued', revision: 1, reportPath: '/r/live-rescan', detailPath: '/api/scans/live-rescan' } });
  });
  await page.route('**/api/scans/live-rescan', route => route.fulfill({ json: liveFixture('live-rescan') }));
  await page.goto('/r/live-example?mode=live');
  await page.getByRole('button', { name: 'Scan again', exact: true }).click();
  await expect(page).toHaveURL(/r\/live-rescan/);
});
test('session expiration removes private history and disables submission', async ({ page }) => {
  await setup(page);
  await page.route('**/api/scans/live-example', route => route.fulfill({ status: 401, json: { error: { code: 'SESSION_EXPIRED' } } }));
  await page.goto('/r/live-example?mode=live');
  await expect(page.getByRole('dialog')).toContainText('Your session has expired');
  await page.getByRole('button', { name: 'Close report' }).click();
  await expect(page.locator('.scan-bubble')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Scan link', exact: true })).toBeDisabled();
});

test('missing analyzer leaves history empty and submission disabled, including obsolete demo URLs', async ({ page }) => {
  await page.route('**/api/session', route => route.fulfill({status:503}));
  await page.goto('/?mode=demo');
  await expect(page.getByRole('button', {name:'Retry connection', exact:true})).toBeVisible({timeout:15000});
  await expect(page.locator('.scan-bubble')).toHaveCount(0);
  await expect(page.getByRole('button', {name:'Scan link', exact:true})).toBeDisabled();
  await expect(page.locator('body')).not.toContainText(/demo|fictional/i);
  await expect(page).not.toHaveURL(/mode=/);
});
