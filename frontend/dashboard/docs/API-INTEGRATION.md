# Analyzer integration contract

This is a standalone UI. Keep the TypeScript messaging gateway and Python analyzer in their existing folders. Use the same analyzer pipeline for web and messaging scans. Do not move server libraries or secrets into `dashboard`.

## Session bootstrap (explicit integration addition)

`GET /api/session` returns JSON:

```json
{
  "scopeKey": "opaque-cache-scope",
  "csrfToken": "session-bound-csrf-token",
  "retentionDays": 7,
  "inputTypes": ["url", "message_screenshot", "qr_image"],
  "scanTimeoutSeconds": 45
}
```

Establish a cryptographically random anonymous web session using a Secure, HttpOnly, SameSite cookie. `scopeKey` separates browser caches; it is not authentication and must not contain a sender hash or personal information. Authenticate every history, report, screenshot, and mutation on the server. Rotate scope when the user's session changes. The retention value must reflect actual cleanup behavior. Only return input types your gateway can generate. The web form submits URL inputs only.

The specification requires CSRF, scoped access, and retention metadata but does not prescribe their bootstrap transport. `/api/session` is this UI's explicit adapter contract, not an assertion that the existing analyzer already implements it.

## Create

`POST /api/scans`, same-origin credentials, headers `X-CSRF-Token` and `Idempotency-Key`:

```json
{"url":"https://example.test/payment","inputType":"url"}
```

Persist the job before acknowledging with `202`:

```json
{"id":"r_example","state":"queued","revision":1,"reportPath":"/r/r_example","detailPath":"/api/scans/r_example"}
```

`Idempotency-Key` is a random UUID. Failed requests before acknowledgment preserve the key for the same URL. Acknowledged jobs and intentional new scans get new keys. The server must enforce key/body/scope consistency, queue admission, rate limits, and network validation. `.test` links in examples are inert and do not resolve for real scans.

## History

`GET /api/scans?window=7d&risk=dangerous&input=url&status=partial&sort=newest&q=toll&limit=20&cursor=...`

Return `{ "items": ScanSummary[], "nextCursor": string|null, "totalMatching": number, "serverTime": ISO8601 }`. Fields and enums are in `src/types/scan.ts`; runtime validators are in `src/api/schema.ts`.

Apply filters and ordering to the **entire authorized dataset** before pagination. Time/risk/input/status/search combine with AND. Risk sorts put known numeric scores first and null/running scores last in either direction. Ties sort by submitted time descending, then stable ID. Unknown includes terminal null-verdict records, not active scans. Input order is URL, message screenshot, QR image. Cursor fingerprints must include the filters and owner scope.

The client checks the first page about every 10 seconds while visible. When new records would shift someone reading farther down, it provides a “new scans — show” action. Active report polling is independent and stops after completion or bounded transport failures, with an explicit retry control.

## Details and screenshot

`GET /api/scans/{id}` returns `ScanDetail`, camelCase JSON, ISO 8601 timestamps, integer score 0–100 or null, and increasing `revision`. Only the server assigns verdict and score. `null` is displayed as Unknown for terminal records. Partial coverage is independent of verdict. Findings, evidence, explanation, sources, limitations, and errors are plain strings and are escaped by React.

The serializer must redact private query values, email-like values, original message bodies, and identifiers before exposing any field. Send URLs in defanged display form; the frontend also defangs as a rendering safeguard. When Unicode and punycode hostnames differ, supply the optional `hostnameDisplay: { "unicode": "...", "ascii": "..." }` field; the UI displays both as separately labeled text. Strip bidirectional controls at the serializer boundary. The frontend never has to decode or revisit a suspect site to establish a domain. Live API responses containing `isRecorded: true` are rejected instead of being presented as real results.

`screenshot.path` must be exactly `/api/scans/{id}/screenshot`. The frontend rejects foreign origins, arbitrary paths, queries, and executable image alternatives. This endpoint returns authorized, validated **PNG or JPEG bytes**, with `Content-Type`, `X-Content-Type-Options: nosniff`, private/no-store headers, and bounded image dimensions/size. Do not return provider URLs or SVG. Missing and expired captures return 404/410 and a matching JSON screenshot state. A missing capture does not block the report.

Snapshots with older revisions cannot replace newer active report data. Closing the dialog stops its polling, not the server job. The analyzer must persist revisions, deadlines, queue state, leases, and restart outcomes independently of the browser. Keep scoring deterministic and Gemini limited to evidence-grounded explanation with a template fallback.

## Report capability exchange (explicit integration addition)

Incoming `/r/{id}?mode=live&cap=...` links first call `POST /api/report-access` with `{ "scanId": "...", "capability": "..." }`, session credentials and CSRF header. Grant scoped server-side access to that single report and return 204. The client removes `cap` from the visible route before fetching the report. Make exchange retry-safe and limit expiration/use appropriately.

This route cannot grant access to a sender's full history. Capabilities must not enter analytics, cache keys, screenshot paths, history filters, or referrers. A fixed no-referrer policy is already included in HTML. Use consistent errors for unknown and unauthorized reports. The original specification requires capability access; this endpoint supplies a concrete exchange transport.

## Rescan (explicit integration addition)

`POST /api/scans/{id}/rescan`, with `{}`, session cookie, CSRF and a fresh idempotency key, creates a new persisted job from the **protected original URL** stored server-side. Return the same 202 shape as create. Authorize the old report and reject expired originals consistently.

This addition is necessary because the displayed URL is redacted: the frontend must not guess hidden query values or rescan the string `REDACTED`. If the server cannot support rescan yet, return a clear 503/404 rather than pretending the old report was rescanned.

## Errors

Use `{ "error": { "code": "RATE_LIMITED", "message": "Plain-language explanation", "retryable": true, "retryAfterSeconds": 180 } }`. Handle 400/422 validation, 401 expired session, 403 access/CSRF, 404/410 unavailable report, 409 idempotency conflict, 429 throttling, and 503 analyzer unavailability. Include `Retry-After` for 429. Do not leak credentials, stack traces, or another sender's record existence.

The frontend retries network/5xx reads at most three times with bounded exponential delay. It does not treat a transport interruption as analyzer failure. A 401 clears private caches and disables submission until a new session is requested. It does not silently switch to recorded data.

## Serving the bundle

Build `dashboard` and copy `dist/assets` to the analyzer's static asset mount. Load `dist/.vite/manifest.json`, find `index.html`, and pass its `file` and `css` array into `integration/report.html`. Copy the local demo raster separately if demo mode is supported. The Jinja shell is an integration example, not a replacement analyzer implementation.

Serve explicit `/` and `/r/{id}` routes through FastAPI before any HTML fallback. Mount `/assets`. Preserve the gateway's existing `POST /analyze` synchronous 200 response. Do not redirect API errors to the React shell. Report routes and JSON use private/no-store; hashed assets can use immutable caching. Enforce HTTPS and the server's access strategy behind Caddy.

Set production response headers, including `Content-Security-Policy` (`default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`), `Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff`. The standalone HTML includes a meta CSP with inline styles allowed; the stricter server header works for the static build because UI styling uses stylesheet files. Vite's development refresh may produce a CSP diagnostic for its injected inline preamble; this affects hot-refresh tooling, not static production rendering.

The sandbox still needs request-by-request SSRF controls, DNS-rebinding defense, isolated networking, no service workers/form submissions/downloads, deadlines, and server-only provider credentials. These are analyzer requirements; the UI cannot enforce or prove them.

## Documentation consulted

- [TanStack Query v5 migration and cache behavior](https://tanstack.com/query/v5/docs/framework/react/guides/migrating-to-v5)
- [React Router BrowserRouter](https://reactrouter.com/api/declarative-routers/BrowserRouter)
- [Vite backend integration and manifest](https://vite.dev/guide/backend-integration)
