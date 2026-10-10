# Tripwire dashboard

The separate frontend MVP for Tripwire. All frontend files live in this `dashboard` folder. It follows the official specification's `frontend/src` structure with the user-requested root name `dashboard`, and excludes the removed redirect-chain UI.

## Start

Requires Node.js 22.14+ and npm. In VS Code, open `dashboard.code-workspace` or the `dashboard` folder.

```sh
npm ci
npm run dev
```

Open **http://127.0.0.1:5173/**. VS Code also includes build, preview, unit-test, and browser-test tasks. F5 starts a Chrome debugging session after the development server is running.

```sh
npm run build          # TypeScript check and production static bundle
npm run preview        # Preview the built bundle locally
npm test               # Domain and API-boundary tests
npx playwright install chromium
npm run test:browser   # Browser behavior and mocked live API tests
```

If using an existing Chrome installation rather than Playwright's downloaded browser, set `PLAYWRIGHT_CHROMIUM_EXECUTABLE` to its executable path before running browser tests. Example for PowerShell:

```powershell
$env:PLAYWRIGHT_CHROMIUM_EXECUTABLE='C:\Program Files\Google\Chrome\Application\chrome.exe'
npm run test:browser
```

## What works

- Original `wallpaper2.jpg` background, `globe.png` logo, and Vista risk icons from `Joewuliu/Tripwired` on `main`, with glossy scan rows, glass controls, and exact creator credit. The wallpaper fills the frame proportionally without stretching. Decorative sky overlays and added slogans are removed.
- Compact URL submission with validation and inline errors. Suspect websites are never visited by this frontend.
- History search, time/risk/input/status filters combined with AND, five sort orders, 20-item pagination, URL-persisted filters, and first-page refresh while the tab is visible.
- Report routes at `/r/:scanId`, browser Back/Forward, hard refresh, native modal background isolation, explicit keyboard focus containment, Escape, and focus/scroll restoration. Reports use a distinct sea-glass green tint with a 16px blurred backdrop and an opaque fallback when blur is unsupported.
- Screenshot rail, enlarged raster view, capture timestamps and source, unavailable/expired states, non-clickable full defanged URLs, ordered check findings, evidence disclosures, partial/unknown/failed results, and score/coverage provenance.
- Parallel analyzer results presented in order, up to 1.5 seconds of educational pacing, reduced-motion bypass, and immediate provisional danger warnings.
- Final summary, recommended actions, copy-to-clipboard with manual fallback, FTC handoff to the fixed official destination, and server-backed rescan adapter.
- Clear live/demo separation, session-scoped caching, request cancellation, monotonic report revisions, bounded transport retries, CSRF and idempotency headers, Retry-After, and expired-session cache clearing.

## Demo and live modes

Completed reports show the summary above the evidence checks in both modes. The verdict and score appear once, within the summary. When a running job finishes, the report returns to the top without moving keyboard focus. Rounded filters retain a glass focus rim, scan rows lift on hover, and local pixel hand cursors change over interactive controls on desktop. Text fields retain their text cursor. The footer contains only the storage/privacy notice.

The default is **Recorded demo — no live scan**. History fixtures use fictional `.test` domains. The screenshot is a locally drawn, labeled illustration, not a real capture. Every demo submission plays the same sample findings regardless of its URL; it does not evaluate that URL. Display values are defanged and queries redacted before browser storage. Demo playback resumes after refresh because the recorded start is stored. Reset demo removes those local example submissions. If storage is blocked, fixtures work in memory for the current tab.

Demo and live modes have separate cache keys. Live requests never fall back to fixtures. Switching to Live requires the real analyzer endpoints described in [docs/API-INTEGRATION.md](docs/API-INTEGRATION.md). No Python analyzer, Gemini call, threat lookup, sandbox, messaging service, or authentication server is implemented inside this standalone UI folder. Those remain the existing project's server responsibilities.

Copy `.env.example` to `.env.local` to configure the development proxy. `ANALYZER_PROXY_TARGET` is used by Vite's development server only. `VITE_DEFAULT_MODE` can be set to `live` for a connected installation. Never put provider credentials or signing secrets in a `VITE_*` variable.

## Organization

```text
dashboard/
  src/
    app/App.tsx, router.tsx
    pages/HomePage.tsx
    components/
      TripwireHeader.tsx, ScanInput.tsx, ScanFilters.tsx
      ScanList.tsx, ScanBubble.tsx, RiskBadge.tsx
      ReportDialog.tsx, CheckTimeline.tsx, CheckCard.tsx
      ScreenshotPanel.tsx, ReportSummary.tsx, FtcHandoff.tsx
    api/scans.ts, schema.ts
    types/scan.ts
    utils/defang.ts, filters.ts, reportText.ts, time.ts
    styles/tokens.css, glass.css, layout.css
    demo/fixtures.ts, store.ts
  public/demo/toll-capture.png
  tests/domain.test.ts
  tests/browser/dashboard.spec.ts, live-api.spec.ts
  docs/API-INTEGRATION.md, ACCEPTANCE.md
  integration/report.html
  .vscode/
  dashboard.code-workspace
  package.json, package-lock.json
  vite.config.ts, vitest.config.ts, playwright.config.ts
```

API requests and response validation stay in `src/api`. Components never calculate live risk scores. Fixed illustrative demo scores stay in `src/demo`. Styling is separated into tokens, reusable glass primitives, and page/responsive layout. All assets are local; no font, favicon, or image requests are made to scanned websites.

## Production serving

`npm run build` creates `dist/index.html`, hashed files in `dist/assets`, `dist/demo`, and `dist/.vite/manifest.json`. Serve the bundle through the analyzer at `/` and `/r/{id}`, preserving its existing `/analyze` endpoint. Read the manifest to insert hashed filenames into the provided Jinja shell. Mount the demo image only if the deployment supports demo mode. The detailed route, header, session, and screenshot requirements are in [docs/API-INTEGRATION.md](docs/API-INTEGRATION.md).

Vite's development proxy does not exist in production. The analyzer/Caddy must serve same-origin `/api` endpoints and explicit report HTML routes. Unknown `/api` paths must return JSON 404, rather than the frontend HTML fallback.

## Verification and remaining integration

See [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md) for checks and scope. The production build and browser tests validate the frontend, using real browser interactions and mocked server responses. They do not prove analyzer security, detector accuracy, durable job recovery, or deployed authorization. A manual screen-reader review and verification against the actual analyzer should precede production use.

Assets were retrieved from `Joewuliu/Tripwired` on `main`. They are stored unchanged in `public/icons` and copied to `dist/icons` by the build; serve `/icons` alongside `/assets`, `/cursors`, and the optional `/demo` files. This folder is ready to copy into the repository as `dashboard/`; these edits are local and no remote commit, pull request, or deployment is claimed.
