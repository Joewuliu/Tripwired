# Recommended live demo connection

Recommendation: use urlscan.io behind the existing Tripwire analyzer, with a small server adapter matching `API-INTEGRATION.md`. This fits the UI's job polling and screenshot workflow. It is a recommendation, not an implemented connection.

## Minimal flow

1. Configure a urlscan API key on the server only. Check the account's private-scan quota before enabling submissions.
2. On Tripwire `POST /api/scans`, validate the URL and session, persist a queued job, and return a Tripwire scan ID with HTTP 202.
3. A server worker submits to urlscan's submission API with explicit `visibility: private`. Do not silently fall back to public or unlisted submissions.
4. Poll the provider result with backoff, a timeout, and quota handling. Its documentation suggests an initial 10–30 second wait and then polling; this is asynchronous live processing, not an instant answer.
5. Translate the result into Tripwire's existing check/evidence schema. Preserve attribution. Unsupported checks stay unavailable; do not populate them with demo findings. Add separate RDAP and official-domain checks if those observations are needed.
6. Retrieve available PNG screenshots through the server and serve them on Tripwire's authorized raster route. The frontend's existing safety policy rejects arbitrary remote screenshot URLs.
7. Set a terminal state and coverage, calculate the evidence verdict server-side, and optionally use Gemini to explain the collected evidence. The current UI polls the Tripwire job and displays its completed summary first.

urlscan alone does not supply every check from the full MVP. For threat-list coverage, Google's Safe Browsing API is for noncommercial use; Google's Web Risk is the commercial option. Keep provider observations separate from Tripwire's evidence score and never treat a negative list result as proof of safety.

Private scans are visible to the account holder or people with whom the scan ID is shared. Unlisted scans are also visible to vetted security researchers and security companies. Provider availability, latency and quotas can affect results.

## Official references (checked October 10, 2026)

- [urlscan API: submission, polling, screenshots and quotas](https://urlscan.io/docs/api/)
- [urlscan visibility levels](https://docs.urlscan.io/pages/visibility)
- [Google Safe Browsing use restrictions](https://developers.google.com/safe-browsing/)
- [Google Web Risk lookup](https://docs.cloud.google.com/web-risk/docs/detect-malicious-urls)
