# Click2Shell Checker

Non-invasive WordPress version detector and exposure checker for the
**Click2Shell** chain (WordPress < 7.1.1).

**CronUp Cybersecurity**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Authorized use only.** Run this tool only against systems you own or have
> written authorization to test.

## Overview

Click2Shell is a pre-authentication RCE chain in WordPress Core (fixed in
7.1.1). A crafted `/wp-admin/theme-install.php?theme=…` URL forces the
installation of an attacker-selected theme from the WordPress.org catalog, and
the chain completes to remote code execution via a pre-activation flaw in the
`mobile-repair-zone` catalog theme (and 40+ other third-party themes).

This tool detects WordPress version **passively** (no exploitation, no writes,
no login attempts) and reports whether a target is exposed to the chain.

## Features

- Passive version detection via public metadata endpoints
- WordPress confirmation to avoid false positives (jQuery/plugin versions are excluded)
- Subdirectory install detection (`/global/`, `/blog/`, `/wp/`, …)
- Click2Shell core exposure check (WordPress < 7.1.1)
- RCE-chain theme detection (`mobile-repair-zone` present on disk)
- WAF / offline state detection (`BLOCKED` / `OFFLINE`) instead of a false "not WordPress"
- Optional Cloudflare evasion via `curl_cffi` (`--impersonate`)
- Colored console output with a live progress bar
- JSON, CSV, and minimalist HTML reports (sortable table, summary cards)

## Installation

```bash
pip install requests colorama

# Optional: Cloudflare evasion (TLS/HTTP2 browser impersonation)
pip install curl_cffi
```

`curl_cffi` is only required for the `--impersonate` flag. Without it, the
checker falls back to plain `requests` automatically.

## Usage

```bash
# Single target
python click2shell_checker.py -t https://client1.com

# List of targets (one per line)
python click2shell_checker.py -l targets.txt

# Reports + concurrency
python click2shell_checker.py -l targets.txt --threads 20 \
    --json out.json --csv out.csv --html report.html

# Ignore TLS certificate errors
python click2shell_checker.py -l targets.txt --insecure

# Cloudflare evasion (impersonate a Chrome browser)
python click2shell_checker.py -l targets.txt --impersonate
```

Targets are cleaned automatically: schemes, uppercase, trailing slashes,
paths, quotes, IPv4/IPv6, ports and IDN domains are normalized; blank lines
and `#` comments are ignored; invalid entries are reported and skipped;
duplicates are removed by hostname.

## Command-line options

| Flag | Description |
|---|---|
| `-t, --target URL` | Single target |
| `-l, --list FILE` | File with one target per line |
| `--threads N` | Concurrent workers (default 10) |
| `--timeout N` | HTTP timeout in seconds (default 20) |
| `--delay N` | Per-request courtesy delay in seconds |
| `--insecure` | Ignore TLS certificate errors |
| `--impersonate` | Impersonate a Chrome browser via `curl_cffi` to reduce Cloudflare bot challenges |
| `--no-chain` | Skip chain-theme detection (version only) |
| `--prefer-https` | Keep the https entry when a host appears with both schemes |
| `--no-color` | Disable ANSI colors |
| `--json FILE` | Write results as JSON |
| `--csv FILE` | Write results as CSV |
| `--html FILE` | Write a minimalist HTML report |
| `--poc TARGET` | Generate the PoC HTML page (active mode) |
| `--poc-out FILE` | PoC output path |
| `--poc-delay N` | PoC stage-2 delay in ms (default 60000) |
| `--poc-theme SLUG` | PoC theme slug (default `mobile-repair-zone`) |

## Output columns

| Column | Meaning |
|---|---|
| `TARGET` | Normalized target URL |
| `WP` | Whether WordPress is confirmed |
| `VERSION` | Detected WordPress version |
| `RISK` | `VULNERABLE` (core < 7.1.1) / `patched` / `BLOCKED` / `OFFLINE` / `-` |
| `MRZ-THEME` | `installed` if `mobile-repair-zone` is on disk, else `-` |
| `SETUP` | `OPEN` if WordPress is not installed yet |
| `SOURCE` | Where the version was detected |

**RISK = VULNERABLE** means the target runs WordPress < 7.1.1 and is exposed to
the forced theme-install primitive, which chains to RCE. **MRZ-THEME =
installed** indicates the chain theme is already present (chain ready locally),
but its absence does not make a vulnerable site safe: the core bug installs the
theme from the catalog by itself.

**SETUP = OPEN** means `/wp-admin/install.php` exposes the installer, i.e.
WordPress is not yet configured and anyone could complete the installation.

**BLOCKED** means a bot/WAF challenge (Cloudflare and similar) hid the site from
the passive scanner; **OFFLINE** means the target was unreachable. Both are
reported separately (with a `?` in the `WP` column) instead of being mislabeled
as "not WordPress". If a site is `BLOCKED`, retry with `--impersonate` (requires
`curl_cffi`) to bypass the Cloudflare TLS/HTTP2 fingerprinting.

### Detection order (OpSec-friendly)

The checker is polite by design:

1. **Source code first** — a single clean request to the homepage is analyzed
   (generator meta, `wp-*` asset versions, base-path detection).
2. **Safe public endpoints** — `/feed/`, `/wp-links-opml.php`, `/wp-json/`.
3. **Sensitive files last** — `readme.html`, `/xmlrpc.php`, `/wp-login.php`,
   `/wp-admin/install.php` are only touched if version/confirmation is still
   missing, since these can trigger a WAF and get the scanner IP blocked.

## Detection methods

| Method | Endpoint(s) |
|---|---|
| Meta generator | `/` |
| readme.html | `/readme.html` |
| RSS generator | `/feed/` |
| OPML generator | `/wp-links-opml.php` |
| Installer | `/wp-admin/install.php` |
| Core assets (`?ver=`) | `/wp-login.php`, `/` |
| REST API | `/wp-json/` |
| XML-RPC | `/xmlrpc.php` |

Version and vulnerability are reported only after WordPress is confirmed
(generator meta, readme, feed/opml, login form, REST API, XML-RPC, or
installer). The `?ver=` heuristic is restricted to `wp-includes`, `wp-admin`
and `wp-content` paths, and bundled third-party libraries (jQuery, React,
etc.) are excluded because they carry their own version numbers, not the
WordPress version.

If WordPress lives in a subdirectory (e.g. `/global/`, `/blog/`), the base
path is detected from asset URLs in the homepage and every endpoint is probed
relative to it.

## PoC (authorized testing only)

```bash
python click2shell_checker.py --poc https://client1.com --poc-out poc.html
```

Generates a self-contained HTML page implementing the two-stage chain. The
full chain requires an **already-authenticated administrator** to open the
page (client-side "one click" attack).

## Disclaimer

This tool is intended for security professionals conducting authorized
assessments. The authors assume no liability for misuse. Always obtain
explicit written authorization before testing.

## License

[MIT](LICENSE) © 2026 CronUp Cybersecurity
# Click2Shell Checker

Non-invasive WordPress version detector and exposure checker for the
**Click2Shell** chain (WordPress < 7.1.1).

**CronUp Cybersecurity**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Authorized use only.** Run this tool only against systems you own or have
> written authorization to test.

## Overview

Click2Shell is a pre-authentication RCE chain in WordPress Core (fixed in
7.1.1). A crafted `/wp-admin/theme-install.php?theme=…` URL forces the
installation of an attacker-selected theme from the WordPress.org catalog, and
the chain completes to remote code execution via a pre-activation flaw in the
`mobile-repair-zone` catalog theme (and 40+ other third-party themes).

This tool detects WordPress version **passively** (no exploitation, no writes,
no login attempts) and reports whether a target is exposed to the chain.

## Features

- Passive version detection via public metadata endpoints
- WordPress confirmation to avoid false positives
- Click2Shell core exposure check (WordPress < 7.1.1)
- RCE-chain theme detection (`mobile-repair-zone` present on disk)
- Colored console output with a live progress bar
- JSON, CSV, and minimalist HTML reports

## Installation

```bash
pip install requests colorama
```

## Usage

```bash
# Single target
python click2shell_checker.py -t https://client1.com

# List of targets (one per line)
python click2shell_checker.py -l targets.txt

# Reports + concurrency
python click2shell_checker.py -l targets.txt --threads 20 \
    --json out.json --csv out.csv --html report.html

# Ignore TLS certificate errors
python click2shell_checker.py -l targets.txt --insecure
```

Targets are cleaned automatically: schemes, uppercase, trailing slashes,
paths, quotes, IPv4/IPv6, ports and IDN domains are normalized; blank lines
and `#` comments are ignored; invalid entries are reported and skipped;
duplicates are removed by hostname.

## Command-line options

| Flag | Description |
|---|---|
| `-t, --target URL` | Single target |
| `-l, --list FILE` | File with one target per line |
| `--threads N` | Concurrent workers (default 10) |
| `--timeout N` | HTTP timeout in seconds (default 20) |
| `--delay N` | Per-request courtesy delay in seconds |
| `--insecure` | Ignore TLS certificate errors |
| `--no-chain` | Skip chain-theme detection (version only) |
| `--prefer-https` | Keep the https entry when a host appears with both schemes |
| `--no-color` | Disable ANSI colors |
| `--json FILE` | Write results as JSON |
| `--csv FILE` | Write results as CSV |
| `--html FILE` | Write a minimalist HTML report |
| `--poc TARGET` | Generate the PoC HTML page (active mode) |
| `--poc-out FILE` | PoC output path |
| `--poc-delay N` | PoC stage-2 delay in ms (default 60000) |
| `--poc-theme SLUG` | PoC theme slug (default `mobile-repair-zone`) |

## Output columns

| Column | Meaning |
|---|---|
| `TARGET` | Normalized target URL |
| `WP` | Whether WordPress is confirmed |
| `VERSION` | Detected WordPress version |
| `RISK` | `VULNERABLE` (core < 7.1.1) / `patched` / `-` |
| `MRZ-THEME` | `installed` if `mobile-repair-zone` is on disk, else `-` |
| `SETUP` | `OPEN` if WordPress is not installed yet |
| `SOURCE` | Where the version was detected |

**RISK = VULNERABLE** means the target runs WordPress < 7.1.1 and is exposed to
the forced theme-install primitive, which chains to RCE. **MRZ-THEME =
installed** indicates the chain theme is already present (chain ready locally),
but its absence does not make a vulnerable site safe: the core bug installs the
theme from the catalog by itself.

**SETUP = OPEN** means `/wp-admin/install.php` exposes the installer, i.e.
WordPress is not yet configured and anyone could complete the installation.

## Detection methods

| Method | Endpoint(s) |
|---|---|
| Meta generator | `/` |
| readme.html | `/readme.html` |
| RSS generator | `/feed/` |
| OPML generator | `/wp-links-opml.php` |
| Installer | `/wp-admin/install.php` |
| Core assets (`?ver=`) | `/wp-login.php`, `/` |
| REST API | `/wp-json/` |
| XML-RPC | `/xmlrpc.php` |

Version and vulnerability are reported only after WordPress is confirmed
(generator meta, readme, feed/opml, login form, REST API, XML-RPC, or
installer). The `?ver=` heuristic is restricted to `wp-includes`, `wp-admin`
and `wp-content` paths to avoid false positives from non-WordPress assets.

## PoC (authorized testing only)

```bash
python click2shell_checker.py --poc https://client1.com --poc-out poc.html
```

Generates a self-contained HTML page implementing the two-stage chain. The
full chain requires an **already-authenticated administrator** to open the
page (client-side "one click" attack).

## Disclaimer

This tool is intended for security professionals conducting authorized
assessments. The authors assume no liability for misuse. Always obtain
explicit written authorization before testing.

## License

[MIT](LICENSE) © 2026 CronUp Cybersecurity
