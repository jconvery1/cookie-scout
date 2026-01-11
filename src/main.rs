use anyhow::{Context, Result};
use clap::Parser;
use console::Term;
use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, SET_COOKIE, USER_AGENT};
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::time::Duration;
use url::Url;

/// Cookie Scout - Website Privacy Analysis Tool
#[derive(Parser, Debug)]
#[command(name = "cookie-scout")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The URL to analyze (e.g., https://example.com)
    url: String,

    /// Show detailed information about each cookie
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone)]
struct CookieInfo {
    name: String,
    domain: Option<String>,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
    category: CookieCategory,
}

#[derive(Debug, Clone, PartialEq)]
enum CookieCategory {
    Essential,
    Analytics,
    Marketing,
    Social,
    Unknown,
}

impl CookieCategory {
    fn as_str(&self) -> &str {
        match self {
            CookieCategory::Essential => "Essential",
            CookieCategory::Analytics => "Analytics",
            CookieCategory::Marketing => "Marketing",
            CookieCategory::Social => "Social",
            CookieCategory::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
struct TrackerInfo {
    name: String,
    category: String,
    description: String,
}

struct AnalysisResult {
    url: String,
    cookies: Vec<CookieInfo>,
    trackers: Vec<TrackerInfo>,
    third_party_requests: Vec<String>,
}

// Known tracker patterns
const TRACKER_PATTERNS: &[(&str, &str, &str)] = &[
    // Analytics
    ("google-analytics", "Analytics", "Google Analytics tracking"),
    ("googletagmanager", "Analytics", "Google Tag Manager"),
    ("gtag", "Analytics", "Google Global Site Tag"),
    ("analytics", "Analytics", "Generic analytics"),
    ("hotjar", "Analytics", "Hotjar behavior analytics"),
    ("mixpanel", "Analytics", "Mixpanel analytics"),
    ("segment", "Analytics", "Segment analytics"),
    ("amplitude", "Analytics", "Amplitude analytics"),
    ("plausible", "Analytics", "Plausible analytics"),
    ("matomo", "Analytics", "Matomo analytics"),
    ("heap", "Analytics", "Heap analytics"),
    ("fullstory", "Analytics", "FullStory session replay"),
    ("clarity", "Analytics", "Microsoft Clarity"),
    // Marketing
    ("doubleclick", "Marketing", "Google DoubleClick advertising"),
    ("facebook.*pixel", "Marketing", "Facebook Pixel"),
    ("fbevents", "Marketing", "Facebook Events"),
    ("ads", "Marketing", "Advertising scripts"),
    ("adsense", "Marketing", "Google AdSense"),
    ("adwords", "Marketing", "Google AdWords"),
    ("criteo", "Marketing", "Criteo retargeting"),
    ("taboola", "Marketing", "Taboola content ads"),
    ("outbrain", "Marketing", "Outbrain content ads"),
    ("pinterest", "Marketing", "Pinterest tracking"),
    ("linkedin.*insight", "Marketing", "LinkedIn Insight Tag"),
    ("twitter.*pixel", "Marketing", "Twitter Pixel"),
    ("tiktok", "Marketing", "TikTok tracking"),
    ("snapchat", "Marketing", "Snapchat tracking"),
    // Social
    ("facebook.com", "Social", "Facebook integration"),
    ("twitter.com", "Social", "Twitter integration"),
    ("linkedin.com", "Social", "LinkedIn integration"),
    ("instagram.com", "Social", "Instagram integration"),
    ("youtube.com", "Social", "YouTube embeds"),
    ("vimeo.com", "Social", "Vimeo embeds"),
    // Other
    ("recaptcha", "Security", "Google reCAPTCHA"),
    ("hcaptcha", "Security", "hCaptcha"),
    ("cloudflare", "CDN/Security", "Cloudflare services"),
    ("sentry", "Error Tracking", "Sentry error tracking"),
    ("bugsnag", "Error Tracking", "Bugsnag error tracking"),
    ("intercom", "Customer Support", "Intercom chat"),
    ("drift", "Customer Support", "Drift chat"),
    ("zendesk", "Customer Support", "Zendesk support"),
    ("hubspot", "Marketing/CRM", "HubSpot tracking"),
    ("marketo", "Marketing", "Marketo tracking"),
    ("pardot", "Marketing", "Pardot tracking"),
    ("optimizely", "A/B Testing", "Optimizely experiments"),
    ("vwo", "A/B Testing", "VWO experiments"),
];

// Known cookie patterns for categorization
const COOKIE_PATTERNS: &[(&str, CookieCategory)] = &[
    // Essential
    ("session", CookieCategory::Essential),
    ("csrf", CookieCategory::Essential),
    ("xsrf", CookieCategory::Essential),
    ("auth", CookieCategory::Essential),
    ("login", CookieCategory::Essential),
    ("token", CookieCategory::Essential),
    ("cart", CookieCategory::Essential),
    ("consent", CookieCategory::Essential),
    // Analytics
    ("_ga", CookieCategory::Analytics),
    ("_gid", CookieCategory::Analytics),
    ("_gat", CookieCategory::Analytics),
    ("_utm", CookieCategory::Analytics),
    ("amplitude", CookieCategory::Analytics),
    ("mixpanel", CookieCategory::Analytics),
    ("mp_", CookieCategory::Analytics),
    ("ajs_", CookieCategory::Analytics),
    ("hubspot", CookieCategory::Analytics),
    ("_hj", CookieCategory::Analytics),
    ("_clck", CookieCategory::Analytics),
    ("_clsk", CookieCategory::Analytics),
    // Marketing
    ("_fbp", CookieCategory::Marketing),
    ("_fbc", CookieCategory::Marketing),
    ("fr", CookieCategory::Marketing),
    ("ads", CookieCategory::Marketing),
    ("_gcl", CookieCategory::Marketing),
    ("gclid", CookieCategory::Marketing),
    ("IDE", CookieCategory::Marketing),
    ("NID", CookieCategory::Marketing),
    ("__gads", CookieCategory::Marketing),
    ("_pin_", CookieCategory::Marketing),
    ("li_", CookieCategory::Marketing),
    ("bcookie", CookieCategory::Marketing),
    // Social
    ("facebook", CookieCategory::Social),
    ("twitter", CookieCategory::Social),
    ("linkedin", CookieCategory::Social),
    ("instagram", CookieCategory::Social),
];

fn categorize_cookie(name: &str) -> CookieCategory {
    let name_lower = name.to_lowercase();
    for (pattern, category) in COOKIE_PATTERNS {
        if name_lower.contains(pattern) {
            return category.clone();
        }
    }
    CookieCategory::Unknown
}

fn parse_cookie(cookie_str: &str) -> CookieInfo {
    let parts: Vec<&str> = cookie_str.split(';').collect();
    let name = parts
        .first()
        .and_then(|p| p.split('=').next())
        .unwrap_or("unknown")
        .trim()
        .to_string();

    let mut domain = None;
    let mut secure = false;
    let mut http_only = false;
    let mut same_site = None;

    for part in parts.iter().skip(1) {
        let part = part.trim().to_lowercase();
        if part.starts_with("domain=") {
            domain = Some(part.replace("domain=", ""));
        } else if part == "secure" {
            secure = true;
        } else if part == "httponly" {
            http_only = true;
        } else if part.starts_with("samesite=") {
            same_site = Some(part.replace("samesite=", ""));
        }
    }

    let category = categorize_cookie(&name);

    CookieInfo {
        name,
        domain,
        secure,
        http_only,
        same_site,
        category,
    }
}

fn detect_trackers(html: &str, base_url: &Url) -> (Vec<TrackerInfo>, Vec<String>) {
    let mut trackers = Vec::new();
    let mut third_party = HashSet::new();
    let mut found_trackers = HashSet::new();

    let document = Html::parse_document(html);
    let script_selector = Selector::parse("script[src]").unwrap();
    let img_selector = Selector::parse("img[src]").unwrap();
    let iframe_selector = Selector::parse("iframe[src]").unwrap();
    let link_selector = Selector::parse("link[href]").unwrap();

    let base_domain = base_url.domain().unwrap_or("");

    // Check script sources
    for element in document.select(&script_selector) {
        if let Some(src) = element.value().attr("src") {
            check_url_for_trackers(src, base_domain, &mut trackers, &mut third_party, &mut found_trackers);
        }
    }

    // Check inline scripts
    let inline_script_selector = Selector::parse("script").unwrap();
    for element in document.select(&inline_script_selector) {
        let script_content = element.inner_html();
        check_content_for_trackers(&script_content, &mut trackers, &mut found_trackers);
    }

    // Check images (tracking pixels)
    for element in document.select(&img_selector) {
        if let Some(src) = element.value().attr("src") {
            check_url_for_trackers(src, base_domain, &mut trackers, &mut third_party, &mut found_trackers);
        }
    }

    // Check iframes
    for element in document.select(&iframe_selector) {
        if let Some(src) = element.value().attr("src") {
            check_url_for_trackers(src, base_domain, &mut trackers, &mut third_party, &mut found_trackers);
        }
    }

    // Check stylesheets and other linked resources
    for element in document.select(&link_selector) {
        if let Some(href) = element.value().attr("href") {
            if let Ok(url) = Url::parse(href) {
                if let Some(domain) = url.domain() {
                    if !domain.contains(base_domain) && !base_domain.contains(domain) {
                        third_party.insert(domain.to_string());
                    }
                }
            }
        }
    }

    (trackers, third_party.into_iter().collect())
}

fn check_url_for_trackers(
    url_str: &str,
    base_domain: &str,
    trackers: &mut Vec<TrackerInfo>,
    third_party: &mut HashSet<String>,
    found_trackers: &mut HashSet<String>,
) {
    let url_lower = url_str.to_lowercase();

    // Check if it's a third-party request
    if let Ok(url) = Url::parse(url_str) {
        if let Some(domain) = url.domain() {
            if !domain.contains(base_domain) && !base_domain.contains(domain) {
                third_party.insert(domain.to_string());
            }
        }
    }

    // Check for known trackers
    for (pattern, category, description) in TRACKER_PATTERNS {
        if let Ok(re) = Regex::new(&format!("(?i){}", pattern)) {
            if re.is_match(&url_lower) && !found_trackers.contains(*pattern) {
                found_trackers.insert(pattern.to_string());
                trackers.push(TrackerInfo {
                    name: pattern.to_string(),
                    category: category.to_string(),
                    description: description.to_string(),
                });
            }
        }
    }
}

fn check_content_for_trackers(
    content: &str,
    trackers: &mut Vec<TrackerInfo>,
    found_trackers: &mut HashSet<String>,
) {
    let content_lower = content.to_lowercase();

    for (pattern, category, description) in TRACKER_PATTERNS {
        if let Ok(re) = Regex::new(&format!("(?i){}", pattern)) {
            if re.is_match(&content_lower) && !found_trackers.contains(*pattern) {
                found_trackers.insert(pattern.to_string());
                trackers.push(TrackerInfo {
                    name: pattern.to_string(),
                    category: category.to_string(),
                    description: description.to_string(),
                });
            }
        }
    }
}

async fn analyze_url(url_str: &str) -> Result<AnalysisResult> {
    let url = Url::parse(url_str).context("Invalid URL format")?;

    // Build HTTP client with custom headers
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ),
    );

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .cookie_store(true)
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(false)
        .build()?;

    // Make the request
    let response = client.get(url_str).send().await?;

    // Extract cookies from headers
    let mut cookies = Vec::new();
    for cookie in response.headers().get_all(SET_COOKIE) {
        if let Ok(cookie_str) = cookie.to_str() {
            cookies.push(parse_cookie(cookie_str));
        }
    }

    // Get HTML content
    let html = response.text().await?;

    // Detect trackers
    let (trackers, third_party_requests) = detect_trackers(&html, &url);

    Ok(AnalysisResult {
        url: url_str.to_string(),
        cookies,
        trackers,
        third_party_requests,
    })
}

fn print_header() {
    use owo_colors::OwoColorize;
    
    let term = Term::stdout();
    let _ = term.clear_screen();

    // Light brown cookie color
    let cookie = owo_colors::Rgb(210, 170, 120);

    println!();
    println!(
        "{}",
        r#"
   ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗███████╗    ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
  ██╔════╝██╔═══██╗██╔═══██╗██║ ██╔╝██║██╔════╝    ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
  ██║     ██║   ██║██║   ██║█████╔╝ ██║█████╗      ███████╗██║     ██║   ██║██║   ██║   ██║   
  ██║     ██║   ██║██║   ██║██╔═██╗ ██║██╔══╝      ╚════██║██║     ██║   ██║██║   ██║   ██║   
  ╚██████╗╚██████╔╝╚██████╔╝██║  ██╗██║███████╗    ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
   ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   
"#
        .color(cookie)
    );
    println!(
        "                              {}",
        "Website Cookie & Tracker Analyzer".bright_yellow()
    );
    println!();
}

fn create_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&[
                "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏",
            ])
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

fn print_divider() {
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bright_black()
    );
}

fn print_section_header(title: &str) {
    println!();
    println!(
        "  {}",
        title.bright_white().bold()
    );
    print_divider();
}

fn print_results(result: &AnalysisResult, verbose: bool) {
    println!();
    print_divider();
    println!(
        "  {} {}",
        "Analysis Complete:".bright_blue(),
        result.url.bright_white().bold()
    );
    print_divider();

    // Summary stats
    println!();
    println!("  ╭─────────────────────────────────────────────────────────────────────────╮");
    println!(
        "  │  {} {:<20} {} {:<20} {} {:<15} │",
        "Cookies:".bright_yellow(),
        result.cookies.len(),
        "Trackers:".bright_red(),
        result.trackers.len(),
        "3rd Party:".bright_blue(),
        result.third_party_requests.len()
    );
    println!("  ╰─────────────────────────────────────────────────────────────────────────╯");

    // Privacy Score
    let privacy_score = calculate_privacy_score(result);
    print_privacy_score(privacy_score);

    // Cookies section
    print_section_header("COOKIES DETECTED");
    
    if result.cookies.is_empty() {
        println!("  {} No cookies detected on initial page load", "[OK]".green());
    } else {
        // Group cookies by category
        let mut essential = Vec::new();
        let mut analytics = Vec::new();
        let mut marketing = Vec::new();
        let mut social = Vec::new();
        let mut unknown = Vec::new();

        for cookie in &result.cookies {
            match cookie.category {
                CookieCategory::Essential => essential.push(cookie),
                CookieCategory::Analytics => analytics.push(cookie),
                CookieCategory::Marketing => marketing.push(cookie),
                CookieCategory::Social => social.push(cookie),
                CookieCategory::Unknown => unknown.push(cookie),
            }
        }

        print_cookie_category("Essential", &essential, "green", verbose);
        print_cookie_category("Analytics", &analytics, "yellow", verbose);
        print_cookie_category("Marketing", &marketing, "red", verbose);
        print_cookie_category("Social", &social, "blue", verbose);
        print_cookie_category("Unknown", &unknown, "white", verbose);
    }

    // Trackers section
    print_section_header("TRACKERS DETECTED");
    
    if result.trackers.is_empty() {
        println!("  {} No known trackers detected", "[OK]".green());
    } else {
        for tracker in &result.trackers {
            let category_color = match tracker.category.as_str() {
                "Analytics" => "yellow",
                "Marketing" => "red",
                "Social" => "blue",
                _ => "white",
            };
            
            let prefix = match tracker.category.as_str() {
                "Analytics" => "[ANALYTICS]",
                "Marketing" => "[MARKETING]",
                "Social" => "[SOCIAL]",
                "Security" => "[SECURITY]",
                "CDN/Security" => "[CDN]",
                "Error Tracking" => "[ERROR]",
                "Customer Support" => "[SUPPORT]",
                "A/B Testing" => "[A/B TEST]",
                _ => "[OTHER]",
            };

            let colored_prefix = match category_color {
                "yellow" => prefix.yellow().to_string(),
                "red" => prefix.red().to_string(),
                "blue" => prefix.blue().to_string(),
                _ => prefix.white().to_string(),
            };

            println!(
                "  {} {} - {}",
                colored_prefix,
                tracker.name.bright_white(),
                tracker.description.bright_black()
            );
        }
    }

    // Third-party domains section
    print_section_header("THIRD-PARTY DOMAINS");
    
    if result.third_party_requests.is_empty() {
        println!("  {} No third-party domains detected", "[OK]".green());
    } else {
        for (i, domain) in result.third_party_requests.iter().take(15).enumerate() {
            println!("  {}. {}", i + 1, domain.bright_cyan());
        }
        if result.third_party_requests.len() > 15 {
            println!(
                "  ... and {} more",
                (result.third_party_requests.len() - 15).to_string().bright_yellow()
            );
        }
    }

    println!();
    print_divider();
    println!(
        "  {} {}",
        "Tip:".bright_yellow(),
        "Use -v for detailed cookie information".bright_black()
    );
    print_divider();
    println!();
}

fn print_cookie_category(name: &str, cookies: &[&CookieInfo], color: &str, verbose: bool) {
    if cookies.is_empty() {
        return;
    }

    let count_str = format!("({} cookies)", cookies.len());
    let header = match color {
        "green" => format!("  ├─ {} {}", name.green(), count_str.bright_black()),
        "yellow" => format!("  ├─ {} {}", name.yellow(), count_str.bright_black()),
        "red" => format!("  ├─ {} {}", name.red(), count_str.bright_black()),
        "blue" => format!("  ├─ {} {}", name.blue(), count_str.bright_black()),
        _ => format!("  ├─ {} {}", name.white(), count_str.bright_black()),
    };
    println!("{}", header);

    for cookie in cookies {
        if verbose {
            let flags = format!(
                "{}{}{}",
                if cookie.secure { "[SEC]" } else { "" },
                if cookie.http_only { "[HTTP]" } else { "" },
                cookie.same_site.as_ref().map(|s| format!(" [{}]", s)).unwrap_or_default()
            );
            println!(
                "  │   • {} {}",
                cookie.name.bright_white(),
                flags.bright_black()
            );
        } else {
            println!(
                "  │   • {}",
                cookie.name.bright_white()
            );
        }
    }
}

fn calculate_privacy_score(result: &AnalysisResult) -> u32 {
    let mut score: i32 = 100;

    // Deduct for cookies
    score -= (result.cookies.len() as i32) * 2;
    
    // Extra deduction for marketing/tracking cookies
    for cookie in &result.cookies {
        match cookie.category {
            CookieCategory::Marketing => score -= 5,
            CookieCategory::Analytics => score -= 3,
            CookieCategory::Social => score -= 2,
            _ => {}
        }
    }

    // Deduct for trackers
    score -= (result.trackers.len() as i32) * 5;

    // Deduct for third-party domains
    score -= (result.third_party_requests.len() as i32) * 1;

    score.max(0).min(100) as u32
}

fn print_privacy_score(score: u32) {
    println!();
    let (color, label) = match score {
        90..=100 => ("green", "EXCELLENT"),
        70..=89 => ("yellow", "GOOD"),
        50..=69 => ("yellow", "MODERATE"),
        25..=49 => ("red", "POOR"),
        _ => ("red", "CRITICAL"),
    };

    let bar_width = 40;
    let filled = (score as usize * bar_width) / 100;
    let empty = bar_width - filled;

    let bar = format!(
        "{}{}",
        "█".repeat(filled),
        "░".repeat(empty)
    );

    println!("  ╭─────────────────────────────────────────────────────────────────────────╮");
    
    let colored_label = match color {
        "green" => label.green().to_string(),
        "yellow" => label.yellow().to_string(),
        "red" => label.red().to_string(),
        _ => label.white().to_string(),
    };

    let colored_bar = match color {
        "green" => bar.green().to_string(),
        "yellow" => bar.yellow().to_string(),
        "red" => bar.red().to_string(),
        _ => bar.white().to_string(),
    };
    
    println!(
        "  │  PRIVACY SCORE: {}/100 - {}",
        score,
        colored_label
    );
    println!("  │  [{}]", colored_bar);
    println!("  ╰─────────────────────────────────────────────────────────────────────────╯");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    print_header();

    // Normalize URL
    let url = if !args.url.starts_with("http://") && !args.url.starts_with("https://") {
        format!("https://{}", args.url)
    } else {
        args.url.clone()
    };

    println!("  {} {}", "Analyzing:".bright_green(), url.bright_cyan());
    println!();

    // Create animated spinner sequence
    let spinner = create_spinner("Connecting to website...");
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    spinner.set_message("Fetching page content...");
    tokio::time::sleep(Duration::from_millis(300)).await;

    spinner.set_message("Analyzing cookies...");
    
    // Perform the actual analysis
    let result = analyze_url(&url).await;

    spinner.set_message("Detecting trackers...");
    tokio::time::sleep(Duration::from_millis(300)).await;

    spinner.set_message("Scanning for third-party requests...");
    tokio::time::sleep(Duration::from_millis(300)).await;

    spinner.finish_and_clear();

    match result {
        Ok(analysis) => {
            print_results(&analysis, args.verbose);
        }
        Err(e) => {
            println!();
            println!(
                "  {} {}",
                "[ERROR]".bright_red(),
                format!("Error analyzing URL: {}", e).red()
            );
            println!();
            println!(
                "  {} Make sure the URL is correct and accessible",
                "Tip:".bright_yellow()
            );
            println!();
        }
    }

    Ok(())
}
