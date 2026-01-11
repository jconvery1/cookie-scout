# Cookie Scout

A powerful command-line tool written in Rust that analyzes websites for cookies and trackers.

![Rust](https://img.shields.io/badge/Rust-1.83+-orange?logo=rust)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

- **Cookie Detection** - Identifies and categorizes cookies (Essential, Analytics, Marketing, Social)
- **Tracker Detection** - Detects 50+ known tracking scripts and pixels
- **Third-Party Analysis** - Lists all third-party domains loaded by the page
- **Privacy Score** - Calculates an overall privacy score (0-100)
- **Beautiful Terminal UI** - Colorful, animated output with progress spinners
- **Dockerized** - No need to install Rust locally

## Quick Start with Docker

### Build the image

```bash
docker build -t cookie-scout .
```

### Analyze a website

```bash
docker run --rm -it cookie-scout https://example.com
```

### With verbose output (shows cookie details)

```bash
docker run --rm -it cookie-scout -v https://example.com
```

### Using docker-compose

```bash
# Build
docker-compose build

# Run
docker-compose run --rm cookie-scout https://example.com
```

## Usage

```
cookie-scout [OPTIONS] <URL>

Arguments:
  <URL>  The URL to analyze (e.g., https://example.com)

Options:
  -v, --verbose  Show detailed information about each cookie
  -h, --help     Print help
  -V, --version  Print version
```

## Example Output

```
   ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗███████╗    ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
  ██╔════╝██╔═══██╗██╔═══██╗██║ ██╔╝██║██╔════╝    ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
  ██║     ██║   ██║██║   ██║█████╔╝ ██║█████╗      ███████╗██║     ██║   ██║██║   ██║   ██║
  ██║     ██║   ██║██║   ██║██╔═██╗ ██║██╔══╝      ╚════██║██║     ██║   ██║██║   ██║   ██║
  ╚██████╗╚██████╔╝╚██████╔╝██║  ██╗██║███████╗    ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║
   ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝

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

## Local Development (without Docker)

If you have Rust installed:

```bash
# Build
cargo build --release

# Run
./target/release/cookie-scout https://example.com
```

## License

MIT License - See LICENSE file for details.
