# MVP acceptance and verification

## Frontend delivery

The official component names and `src` grouping are preserved. The outer `frontend` folder is renamed `dashboard` as requested. The user-removed redirect-chain UI is absent. No gateway or analyzer files have been changed.

| Specification area | Implemented frontend behavior | Verification |
| --- | --- | --- |
| Header and Aero theme | Local glossy shield/globe, sky and horizon, glass surfaces, exact creator credit | Desktop and phone visual review |
| URL form | Single HTTP(S) URL, normalization, credentials/private-host rejection, inline errors, retained input | Unit and browser tests |
| History | Twenty records per page, server filters, all required sort/filter choices, query parameters, load more | Domain and browser tests |
| Report route | `/r/:id`, direct loading, refresh, Back/Forward, retained filters | Browser tests |
| Modal | Desktop 80vw/80dvh, responsive rim, native background isolation, focus containment/restoration, Escape | Browser keyboard tests at 320px; visual review |
| URL safety | Defanged selectable text, no suspect anchors/frames/images, no destination validation fetch | URL unit tests and request interception tests |
| Screenshots | Authorized raster path whitelist, contain fitting, inline enlarge, source/date, missing/expired states | Browser and schema tests; visual review |
| Check presentation | Truthful statuses, ordered reveals, show-all, reduced motion, provisional danger | Demo playback and mocked live API tests |
| Evidence and verdict | Nullable Unknown, partial coverage, attributed disclosures, template/Gemini metadata, score not probability | Runtime schemas and report tests |
| Final actions | Recommendations, 7726 for image inputs, safe copy, manual clipboard fallback, fixed FTC continuation | Browser tests |
| Rescan | Fresh job via server-held original URL, no replay of redacted private values | Mocked live API browser test |
| Transport | Scoped keys, session cache clearing, abort signals, bounded retries, revision guard, CSRF/idempotency, 429 | Unit and mocked live API tests |
| Demo honesty | Visible recorded labels, local illustrative raster, fixture-only playback, separate caches | Browser tests |
| Production assets | TypeScript build, hashed Vite files and manifest, Jinja shell example | Production build |
| VS Code | One folder, workspace, tasks, Chrome debugging configuration | Files inspected |

The initial desktop composition was inspected at 1440×900. The October 10 design refinement was visually inspected at the in-app browser's native desktop size and at 390×844; updated screenshots are in `docs/previews`. The compact input keeps five complete scan rows in the desktop initial view. Browser overflow and modal focus were tested at 320×740. Reduced motion removes animation and result pacing. Text is on mostly opaque surfaces; risk labels always include text and icons. A complete manual screen-reader pass remains a pre-production check.

The latest user request overrides the original recognizable-homepage backdrop: the report now uses 16px blur, dimming, and desaturation. Its pale blue glass and glossy toolbar distinguish it from the homepage without changing semantic risk colors. Scan rows and decorative bubbles have stronger rims, reflections, and depth. The slogan above the title is removed. Mode controls, reset, and evidence disclosure targets have a 44px minimum height; placeholder and input-edge contrast were strengthened.

## Server responsibilities remain outside this UI delivery

The frontend is wired for the specified live JSON API. Tests of this contract use mocked responses; there was no analyzer repository or live analyzer service available here. Actual live scanning requires configuring and verifying the existing server.

The analyzer must implement scoped sessions and access, capability exchange, durable queue acknowledgment, restart recovery, SQLite history, scoring and coverage, real provider checks, screenshot capture/authorization/retention, rate limiting, rescan of the protected original, and JSON errors. These are documented in `API-INTEGRATION.md`. They are not simulated as live features.

No remote GitHub push, pull request, or hosted deployment has been performed. The repository URL is required to place the standalone folder in the intended repository. All local changes are accessible in the supplied VS Code workspace.

## Commands

Latest refinement: the production build and all 14 browser tests passed. Demo and mocked-live tests explicitly verify that the completed summary precedes the checks, the running report has no final summary, and the introductory verdict is absent. Desktop and 390px phone views were inspected; cursor assets and rounded filter styling were confirmed through computed browser styles. Translucent glass retains opaque fallbacks, reduced motion, keyboard focus rims, and forced-color treatment. Actual live scanning is still unconnected.

Final verification: production build passed, 21 unit tests passed, and 14 browser tests passed. Browser coverage includes a mocked live analyzer; it does not claim a connection to a real deployed backend.

```sh
npm run build
npm test
npm run test:browser
```

Browser tests require installed Playwright Chromium or `PLAYWRIGHT_CHROMIUM_EXECUTABLE`. The test suite intentionally covers user flows, privacy boundaries, error behavior, and API interactions rather than merely mirroring component markup.

Current refinement: pale blue translucent reports replace the green tint. All five filters now open rounded glass menus with selected states, arrow-key navigation, Escape, outside-click dismissal, and viewport clamping. The header uses the original clownfish.png from frontend/icons on the dashboard branch.

Validation for the current refinement: production build and all 15 browser tests passed. Desktop and 390px phone report/menu views were inspected; the menu test also verifies all five popups stay within 320px viewport bounds.

Brand update: every customer-facing name is PhishFinder, including the browser title, error pages, provider labels and exported reports. The rounded Fredoka wordmark uses a blue glossy tint. History rows begin with the existing risk badge; input-type icons are removed. The shared row component applies to both demo and live data. Existing API source identifiers and the demo storage key remain compatible.

Latest presentation update: removed the header subtitle, connection label under the creator credit, mode-switch bar, recorded report banner, reset control and storage footer. The UI always requests real analyzer data and strips obsolete mode query parameters; browser fixtures are used only through test API mocks. No automatic sample-data fallback is enabled.
Validation: production build, 21 unit tests, and 16 browser tests pass. Desktop and phone views were inspected; removed labels are absent and no horizontal overflow was observed. The development server runs from this repository folder. The real analyzer is currently unavailable at the configured address.
