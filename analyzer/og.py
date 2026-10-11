"""The picture a shared report link shows (og:image), and the small page that points preview
programs at it.

The picture is the verdict card at 1200 x 630: the wordmark, the verdict in words on its colour, the
headline, what to do, and the sandbox screenshot as a phone. It is drawn here, by a browser that is
given one self-contained page and no network at all: the analyzer cannot reach the web app (the
egress firewall forbids it), so the card's colours are repeated below. Every word that goes into the
page is escaped, and every address in a report is already defanged.

It is made once per report and kept in <data>/og/<id>.png.
"""
import asyncio
import base64
import html
import logging
import os
import re
import secrets
from pathlib import Path

from playwright.async_api import async_playwright

from contract import AnalysisResult

log = logging.getLogger("tripwire.og")

WIDTH, HEIGHT = 1200, 630
RENDER_TIMEOUT_S = 20.0
FONT_PATH = Path(__file__).resolve().parent / "assets" / "fonts" / "Fredoka.ttf"

LABEL = {
    "dangerous": "Dangerous",
    "suspicious": "Suspicious",
    "no_red_flags": "No red flags found",
    "couldnt_check": "Couldn't check",
}
# One line of what to do, the same as the card's. None of them says a link is safe.
ACTION = {
    "dangerous": "Don't tap it or enter anything.",
    "suspicious": "Don't type anything in; check with the sender another way.",
    "no_red_flags": "Still go to the company's own website yourself.",
    "couldnt_check": "Don't type anything until you've checked another way.",
}
# Text colour and badge fill for each verdict (the card's light set). "Clear" is aqua, never green.
TONE = {
    "dangerous": ("#8a1832", "#fde8ee"),
    "suspicious": ("#754500", "#fff1cf"),
    "no_red_flags": ("#0b5e77", "#e0f3fd"),
    "couldnt_check": ("#465264", "#edf1f5"),
}

_one_at_a_time = asyncio.Lock()  # drawing is cheap, but a browser each is not: one picture at a time
_REPORT_ID = re.compile(r"[a-f0-9]{12}")
_HOST = re.compile(r"[A-Za-z0-9.-]{1,253}(:\d{1,5})?")


def headline_body(report: AnalysisResult) -> str:
    """The headline without its leading verdict word: the badge already says it. A couldn't-check
    leads with its reason instead (the analyzer puts it first among the plain lines)."""
    if report.verdict == "couldnt_check" and report.observations:
        return report.observations[0]
    return re.sub(r"^(Dangerous|Suspicious):\s*", "", report.headline, flags=re.IGNORECASE).strip() or LABEL[report.verdict]


def _data_uri(path: Path, mime: str) -> str | None:
    try:
        return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode('ascii')}"
    except OSError:
        return None


def og_html(report: AnalysisResult, screenshot: Path | None = None, font: Path | None = FONT_PATH) -> str:
    """The whole picture as one page: no links out, no scripts, every word escaped."""
    tone, fill = TONE[report.verdict]
    shot = _data_uri(screenshot, "image/png") if screenshot else None
    font_uri = _data_uri(font, "font/ttf") if font else None
    font_face = (
        f"@font-face {{ font-family: 'Fredoka'; src: url('{font_uri}') format('truetype'); font-weight: 300 700; }}"
        if font_uri else ""
    )
    phone = (
        f'<div class="phone"><img src="{shot}" alt=""></div>'
        if shot else '<div class="phone empty">No picture of this page</div>'
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<style>
{font_face}
* {{ box-sizing: border-box; margin: 0; }}
html, body {{ width: {WIDTH}px; height: {HEIGHT}px; overflow: hidden; }}
body {{
  font-family: 'Segoe UI', 'Helvetica Neue', Arial, 'Liberation Sans', 'DejaVu Sans', sans-serif;
  color: #123447;
  background:
    radial-gradient(ellipse at 45% -10%, #ffffff 0, rgba(255,255,255,.5) 30%, transparent 68%),
    linear-gradient(180deg, #7cc7ee 0%, #b9e8f8 55%, #d6efcb 100%);
}}
.bubble {{ position: absolute; border-radius: 50%; border: 2px solid rgba(92,166,188,.5);
  background: radial-gradient(ellipse at 27% 18%, #fff 0%, rgba(255,255,255,.6) 8%, rgba(255,255,255,.1) 35%, rgba(75,175,198,.3) 84%, rgba(224,251,255,.7) 100%); }}
.card {{
  position: absolute; left: 44px; top: 40px; width: 1112px; height: 550px; padding: 40px 44px 40px 60px;
  display: grid; grid-template-columns: minmax(0, 1fr) 270px; gap: 44px; overflow: hidden;
  border: 2px solid #83b6c8; border-radius: 40px; background: rgba(244,252,255,.95);
  box-shadow: inset 0 4px 0 #fff, 0 20px 50px rgba(55,113,133,.25);
}}
.card::before {{ content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 18px; background: {tone}; }}
.words {{ display: flex; flex-direction: column; min-width: 0; }}
.mark {{ font-family: 'Fredoka', 'Arial Rounded MT Bold', sans-serif; font-weight: 650; font-size: 54px; letter-spacing: -.02em;
  color: #17658c; line-height: 1.1; }}
.badge {{ align-self: flex-start; margin-top: 22px; padding: 10px 34px; border: 4px solid {tone}; border-radius: 60px;
  color: {tone}; background: {fill}; font-size: 58px; font-weight: 700; line-height: 1.15; white-space: nowrap; }}
.headline {{ margin-top: 26px; font-size: 40px; font-weight: 650; line-height: 1.22; letter-spacing: -.01em;
  display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 3; overflow: hidden; }}
.action {{ margin-top: auto; color: {tone}; font-size: 32px; font-weight: 700; line-height: 1.25; }}
.phone {{ align-self: center; width: 270px; height: 468px; overflow: hidden; border: 6px solid #83b6c8; border-radius: 34px;
  background: {fill}; }}
.phone img {{ display: block; width: 100%; height: auto; }}
.phone.empty {{ display: grid; place-items: center; padding: 24px; color: #36576a; font-size: 26px; text-align: center; }}
</style></head>
<body>
<div class="bubble" style="left:-40px;top:380px;width:170px;height:170px"></div>
<div class="bubble" style="right:-60px;top:-50px;width:230px;height:230px"></div>
<div class="card">
  <div class="words">
    <div class="mark">Phish Finder</div>
    <div class="badge">{html.escape(LABEL[report.verdict])}</div>
    <div class="headline">{html.escape(headline_body(report))}</div>
    <div class="action">{html.escape(ACTION[report.verdict])}</div>
  </div>
  {phone}
</div>
</body></html>"""


async def render_png(page_html: str) -> bytes:
    """Draw a page to a 1200 x 630 PNG in a browser that may not load anything from anywhere."""
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        try:
            ctx = await browser.new_context(
                viewport={"width": WIDTH, "height": HEIGHT}, device_scale_factor=1, offline=True,
                accept_downloads=False, service_workers="block",
            )
            await ctx.route("**/*", lambda route: route.abort())  # data: URIs never reach this; nothing else may load
            page = await ctx.new_page()
            await page.set_content(page_html, wait_until="load")
            await page.evaluate("document.fonts.ready")
            return await page.screenshot(type="png", clip={"x": 0, "y": 0, "width": WIDTH, "height": HEIGHT})
        finally:
            await browser.close()


def og_path(data_dir: Path, report_id: str) -> Path:
    return data_dir / "og" / f"{report_id}.png"


async def ensure_og(report: AnalysisResult, data_dir: Path) -> Path | None:
    """The report's picture, made now if it has not been yet. None if it cannot be made: a preview
    picture is a nicety, and its failure must never touch a scan or a reply."""
    if not _REPORT_ID.fullmatch(report.id):
        return None
    path = og_path(data_dir, report.id)
    if path.is_file():
        return path
    async with _one_at_a_time:
        if path.is_file():  # made while we waited
            return path
        shot = data_dir / f"{report.id}.png"
        try:
            page = og_html(report, shot if report.screenshot_url and shot.is_file() else None)
            png = await asyncio.wait_for(render_png(page), RENDER_TIMEOUT_S)
            path.parent.mkdir(parents=True, exist_ok=True)
            temp = path.with_name(f".{report.id}.{secrets.token_hex(4)}.tmp")
            try:
                temp.write_bytes(png)
                os.replace(temp, path)
            finally:
                temp.unlink(missing_ok=True)
            return path
        except Exception as exc:
            log.warning("preview picture for %s was not made: %s", report.id, type(exc).__name__)
            return None


def public_origin(host: str | None, scheme: str | None) -> str:
    """https://<host> from the request, or "" (relative addresses) if the host looks wrong."""
    if not host or not _HOST.fullmatch(host):
        return ""
    return f"{'http' if scheme == 'http' else 'https'}://{host}"


def share_html(report: AnalysisResult, origin: str) -> str:
    """The page a preview program is given for /r/<id>: the tags it reads, and a way on for a person."""
    title = html.escape(f"Phish Finder: {LABEL[report.verdict]}", quote=True)
    description = html.escape(headline_body(report), quote=True)
    page = html.escape(f"{origin}/r/{report.id}", quote=True)
    image = html.escape(f"{origin}/og/{report.id}.png", quote=True)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{title}</title>
<meta name="description" content="{description}">
<meta property="og:site_name" content="Phish Finder">
<meta property="og:type" content="article">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{description}">
<meta property="og:url" content="{page}">
<meta property="og:image" content="{image}">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="{WIDTH}">
<meta property="og:image:height" content="{HEIGHT}">
<meta property="og:image:alt" content="{title}. {description}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{title}">
<meta name="twitter:description" content="{description}">
<meta name="twitter:image" content="{image}">
</head>
<body><p>{title}. {description}</p><p><a href="{page}">Open the report</a></p></body></html>"""
