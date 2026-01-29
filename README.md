# Recon 🥷

A command-line tool written in Rust that analyzes websites for cookies and trackers.

[![Rust](https://img.shields.io/badge/Rust-1.83+-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](https://github.com/jconvery1/recon/blob/master/LICENSE)

## Installation

### Pre-built Binaries (Recommended)

Download the latest release for your platform from the [Releases page](https://github.com/jconvery1/recon/releases).

**macOS (Apple Silicon):**
```bash
curl -LO https://github.com/jconvery1/recon/releases/latest/download/recon-macos-aarch64.tar.gz
tar -xzf recon-macos-aarch64.tar.gz
chmod +x recon
sudo mv recon /usr/local/bin/
```

**macOS (Intel):**
```bash
curl -LO https://github.com/jconvery1/recon/releases/latest/download/recon-macos-x86_64.tar.gz
tar -xzf recon-macos-x86_64.tar.gz
chmod +x recon
sudo mv recon /usr/local/bin/
```

**Linux (x86_64):**
```bash
curl -LO https://github.com/jconvery1/recon/releases/latest/download/recon-linux-x86_64.tar.gz
tar -xzf recon-linux-x86_64.tar.gz
chmod +x recon
sudo mv recon /usr/local/bin/
```

**Windows:**
Download `recon-windows-x86_64.zip` from the releases page, extract it, and add the folder to your PATH.

## Usage

```
recon [OPTIONS] <URL>

Arguments:
  <URL>  The URL to analyze (e.g., https://example.com)

Options:
  -v, --verbose  Show detailed information about each cookie
  -h, --help     Print help
  -V, --version  Print version
```

## Example Output

```
  Recon 🥷
  Website Cookie & Tracker Analyzer

  Analyzing: https://example.com

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Analysis Complete: https://example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ╭─────────────────────────────────────────────────────────────────────────╮
  │  Cookies: 5             Trackers: 3            3rd Party: 12           │
  ╰─────────────────────────────────────────────────────────────────────────╯

  ╭─────────────────────────────────────────────────────────────────────────╮
  │  PRIVACY SCORE: 65/100 - MODERATE                                      │
  │  [██████████████████████████░░░░░░░░░░░░░░]                             │
  ╰─────────────────────────────────────────────────────────────────────────╯

  COOKIES DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ├─ Essential (2 cookies)
  │   • session_id
  │   • csrf_token
  ├─ Analytics (2 cookies)
  │   • _ga
  │   • _gid
  ├─ Marketing (1 cookies)
  │   • _fbp

  TRACKERS DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [ANALYTICS] google-analytics - Google Analytics tracking
  [ANALYTICS] gtag - Google Global Site Tag
  [MARKETING] facebook.*pixel - Facebook Pixel
```

## What It Detects

### Cookie Categories
- **Essential** - Session, CSRF, authentication cookies
- **Analytics** - Google Analytics, Mixpanel, Hotjar, etc.
- **Marketing** - Facebook Pixel, Google Ads, Criteo, etc.
- **Social** - Facebook, Twitter, LinkedIn cookies

### Known Trackers
- Google Analytics, Google Tag Manager
- Facebook Pixel, Meta tracking
- Hotjar, Mixpanel, Amplitude
- LinkedIn Insight Tag
- TikTok, Snapchat, Pinterest pixels
- Intercom, Drift, Zendesk
- Sentry, Bugsnag error tracking
- And many more...

## Privacy Score Calculation

The privacy score is calculated based on:
- Number of cookies detected
- Type of cookies (marketing/tracking cookies have higher penalty)
- Number of known trackers
- Number of third-party domains

| Score | Rating |
|-------|--------|
| 90-100 | Excellent |
| 70-89 | Good |
| 50-69 | Moderate |
| 25-49 | Poor |
| 0-24 | Critical |

## Building from Source

If you have Rust installed:

```bash
# Build
cargo build --release

# Run
./target/release/recon https://example.com
```

## License

MIT License - See LICENSE file for details.
