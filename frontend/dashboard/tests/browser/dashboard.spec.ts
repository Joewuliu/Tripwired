import { test, expect, type Page } from '@playwright/test';
import { seedFixtures } from '../../src/demo/fixtures';
import { filterRecords, readFilters } from '../../src/utils/filters';
import { readFileSync } from 'node:fs';

async function setupApi(page: Page) {
  const records = seedFixtures().map(scan => ({...scan, isRecorded: false, limitations: ['Visual comparison is not configured.'], screenshot: {...scan.screenshot, description: null, path: scan.screenshot.path ? `/api/scans/${scan.id}/screenshot` : null}}));
  await page.route('**/api/session', route => route.fulfill({json: {scopeKey: 'browser-test', csrfToken: 'test-csrf', retentionDays: 7, inputTypes: ['url','message_screenshot','qr_image'], scanTimeoutSeconds: 45}}));
  await page.route('**/api/scans?*', route => {
    const params = new URL(route.request().url()).searchParams; const filtered = filterRecords(records, readFilters(params)); const offset = Number(params.get('cursor') || 0);
    return route.fulfill({json: {items: filtered.slice(offset, offset+20), totalMatching: filtered.length, nextCursor: offset+20 < filtered.length ? String(offset+20) : null, serverTime: new Date().toISOString()}});
  });
  await page.route('**/api/scans/*', route => {
    const scan = records.find(scan => route.request().url().endsWith(`/api/scans/${scan.id}`));
    return route.fulfill(scan ? {json: scan} : {status:404});
  });
  await page.route('**/api/scans/*/screenshot', route => route.fulfill({contentType: 'image/png', body: readFileSync('public/demo/toll-capture.png')}));
}

test.beforeEach(async ({ page }) => { await setupApi(page); await page.goto('/'); });
test('renders the specified homepage and paginated history', async ({ page }) => {
  await expect(page.getByRole('heading', { name: 'PhishFinder', exact: true })).toBeVisible();
  await expect(page.getByText('Created by Joseph, Peter, Srijith.')).toBeVisible();
  await expect(page.locator('.scan-bubble')).toHaveCount(20);
  await expect(page.locator('.scan-bubble .row-icon')).toHaveCount(0);
  expect(await page.locator('.scan-bubble').first().evaluate(el => el.firstElementChild?.classList.contains('scan-bubble-risk'))).toBe(true);
  await page.getByRole('button', { name: 'Load more', exact: true }).click();
  await expect(page.locator('.scan-bubble')).toHaveCount(25);
});
test('filters combine, persist in the route and reset', async ({ page }) => {
  await page.getByLabel('Risk', { exact: true }).click();
  await page.getByRole('menuitemradio', { name: 'Dangerous', exact: true }).click();
  await page.getByLabel('Input type', { exact: true }).click();
  await page.getByRole('menuitemradio', { name: 'URL', exact: true }).click();
  await expect(page.locator('.scan-bubble')).toHaveCount(2);
  await page.getByLabel('Search URL or summary').fill('toll');
  await expect(page.locator('.scan-bubble')).toHaveCount(1);
  await expect(page).toHaveURL(/risk=dangerous/);
  await page.reload(); await expect(page.locator('.scan-bubble')).toHaveCount(1);
  await page.getByRole('button', { name: 'Reset filters', exact: true }).click();
  await expect(page.locator('.scan-bubble')).toHaveCount(20);
});
test('report contains inert URLs, screenshot, checks, FTC handoff and focus restoration', async ({ page }) => {
  const first = page.locator('.scan-bubble').first();
  await first.focus(); await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog'); await expect(dialog).toBeVisible();
  await expect(dialog.locator('.report-url')).toContainText('hxxps://toll-payment[.]test/claim');
  await expect(dialog.locator('.check-card')).toHaveCount(6);
  await expect(dialog.locator('.report-intro .risk-badge')).toHaveCount(0);
  await expect(dialog.getByText('Evidence score: 87/100', { exact: true })).toHaveCount(1);
  expect(await dialog.locator('.report-summary').evaluate(element => Boolean(element.compareDocumentPosition(document.querySelector('.checks-section')!) & Node.DOCUMENT_POSITION_FOLLOWING))).toBe(true);
  await expect(dialog.locator('a[href*="toll"]')).toHaveCount(0);
  await expect(dialog.getByRole('img', { name: 'Captured landing page associated with this scan' })).toBeVisible();
  await dialog.getByRole('button', { name: 'Report to the FTC', exact: true }).click();
  await expect(dialog.getByLabel('Prepared report summary')).toContainText('PhishFinder scan report');
  await expect(dialog).not.toContainText(/demo/i);
  await expect(dialog.getByRole('link', { name: 'Continue to FTC' })).toHaveAttribute('href', 'https://reportfraud.ftc.gov/');
  await page.keyboard.press('Escape'); await expect(dialog).not.toBeVisible();
  await expect(first).toBeFocused();
});
test('Back and Forward navigate reports; a direct report survives refresh', async ({ page }) => {
  await page.locator('.scan-bubble').first().click(); await expect(page.getByRole('dialog')).toBeVisible();
  await page.goBack(); await expect(page.getByRole('dialog')).not.toBeVisible();
  await page.goForward(); await expect(page.getByRole('dialog')).toBeVisible();
  await page.reload(); await expect(page.getByRole('dialog')).toBeVisible();
  await page.getByRole('button', { name: 'Close report' }).click(); await expect(page).toHaveURL(/\/$/);
});
test('invalid submission retains input and old preview URLs use the API without demo controls', async ({ page }) => {
  await page.goto('/?mode=demo');
  await expect(page).not.toHaveURL(/mode=/);
  await expect(page.locator('.scan-bubble')).toHaveCount(20);
  await expect(page.locator('.mode-bar, .subtitle, .connection-status, .reset-demo, .page-footer')).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText(/demo|fictional|Check suspicious links without opening/i);
  await page.getByLabel('Suspicious URL', { exact: true }).fill('javascript:alert(1)');
  await page.getByRole('button', { name: 'Scan link', exact: true }).click();
  await expect(page.locator('#url-error')).toBeVisible();
});
test('320px layout has no horizontal overflow and modal keyboard stays contained', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 740 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.locator('.scan-bubble').first().click();
  await expect(page.getByRole('dialog')).toBeVisible();
  expect(await page.evaluate(() => document.querySelector('dialog')!.scrollWidth <= document.querySelector('dialog')!.clientWidth)).toBe(true);
  for (let i = 0; i < 25; i++) { await page.keyboard.press('Tab'); expect(await page.evaluate(() => Boolean(document.activeElement?.closest('dialog')))).toBe(true); }
});
test('reduced motion and historical unknown reports show available evidence immediately', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.getByLabel('Risk', { exact: true }).click();
  await page.getByRole('menuitemradio', { name: 'Unknown', exact: true }).click();
  await page.locator('.scan-bubble').first().click();
  await expect(page.getByRole('dialog').getByText('Evidence score unavailable', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('There is not enough usable evidence for a reassuring verdict.')).toBeVisible();
  await expect(page.locator('.check-placeholder')).toHaveCount(0);
});

test('glass dropdowns select by keyboard, close outside, and fit a narrow screen', async ({ page }) => {
  const risk = page.getByRole('button', { name: 'Risk', exact: true });
  await risk.focus(); await page.keyboard.press('ArrowDown');
  await expect(page.getByRole('menuitemradio', { name: 'All levels', exact: true })).toBeFocused();
  await page.keyboard.press('ArrowDown'); await page.keyboard.press('Enter');
  await expect(risk).toBeFocused(); await expect(page).toHaveURL(/risk=dangerous/);
  await risk.click(); await page.keyboard.press('Escape'); await expect(risk).toBeFocused();
  await risk.click(); await page.getByRole('button', { name: 'Status', exact: true }).click();
  await expect(page.getByRole('menu')).toHaveCount(1);
  await page.getByRole('heading', { name: 'Recent scans', exact: false }).click();
  await expect(page.getByRole('menu')).toHaveCount(0);
  await page.setViewportSize({ width: 320, height: 740 });
  for (const label of ['Time window', 'Risk', 'Input type', 'Status', 'Sort scans']) {
    await page.getByRole('button', { name: label, exact: true }).click();
    const box = await page.getByRole('menu').boundingBox();
    expect(box!.x).toBeGreaterThanOrEqual(0); expect(box!.x + box!.width).toBeLessThanOrEqual(320);
    await page.keyboard.press('Escape');
  }
});
