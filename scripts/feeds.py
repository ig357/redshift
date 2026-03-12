"""
RSS feed definitions and fetching logic for threat intelligence sources.
"""

import re
import concurrent.futures
import feedparser
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# Feed list — ~20 high-quality cyber threat intelligence sources
# ---------------------------------------------------------------------------
FEEDS = [
    # Government / National CERTs
    {"name": "CISA News",                  "url": "https://www.cisa.gov/news.xml"},
    {"name": "CISA Current Activity",      "url": "https://www.cisa.gov/uscert/ncas/current-activity.xml"},
    {"name": "NCSC UK",                    "url": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"},
    {"name": "SANS Internet Storm Center", "url": "https://isc.sans.edu/rssfeed_full.xml"},

    # Vendor threat research
    {"name": "Talos Intelligence",         "url": "https://blog.talosintelligence.com/feeds/posts/default"},
    {"name": "Unit 42 (Palo Alto)",        "url": "https://unit42.paloaltonetworks.com/feed/"},
    {"name": "Mandiant Blog",              "url": "https://www.mandiant.com/resources/blog/rss.xml"},
    {"name": "CrowdStrike Blog",           "url": "https://www.crowdstrike.com/blog/feed/"},
    {"name": "Sophos News",                "url": "https://news.sophos.com/en-us/feed/"},
    {"name": "Microsoft Security Blog",    "url": "https://www.microsoft.com/en-us/security/blog/feed/"},
    {"name": "IBM Security Intelligence",  "url": "https://securityintelligence.com/feed/"},
    {"name": "Google Project Zero",        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default"},
    {"name": "Recorded Future",            "url": "https://www.recordedfuture.com/feed"},

    # News & industry
    {"name": "Bleeping Computer",          "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "Krebs on Security",          "url": "https://krebsonsecurity.com/feed/"},
    {"name": "The Hacker News",            "url": "https://thehackernews.com/feeds/posts/default"},
    {"name": "Dark Reading",               "url": "https://www.darkreading.com/rss/all.xml"},
    {"name": "SecurityWeek",               "url": "https://feeds.feedburner.com/securityweek"},
    {"name": "Schneier on Security",       "url": "https://www.schneier.com/feed/atom/"},
    {"name": "Naked Security (Sophos)",    "url": "https://nakedsecurity.sophos.com/feed/"},
]

MAX_ARTICLES_PER_FEED = 10
MAX_AGE_DAYS = 7
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def _strip_html(text: str) -> str:
    text = _HTML_TAG_RE.sub(" ", text)
    return _WHITESPACE_RE.sub(" ", text).strip()


def _parse_date(entry) -> datetime | None:
    for attr in ("published_parsed", "updated_parsed", "created_parsed"):
        t = getattr(entry, attr, None)
        if t:
            try:
                return datetime(*t[:6], tzinfo=timezone.utc)
            except Exception:
                pass
    return None


def _fetch_feed(feed_info: dict) -> tuple[dict, list[dict]]:
    """Fetch and parse a single RSS feed. Returns (feed_info, articles)."""
    import socket
    articles = []
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(10)
        try:
            parsed = feedparser.parse(
                feed_info["url"],
                request_headers={"User-Agent": "ThreatIntelBot/1.0"},
            )
        finally:
            socket.setdefaulttimeout(old_timeout)
        if parsed.bozo and not parsed.entries:
            return feed_info, articles

        cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)

        for entry in parsed.entries[:MAX_ARTICLES_PER_FEED * 2]:
            if len(articles) >= MAX_ARTICLES_PER_FEED:
                break

            pub_date = _parse_date(entry)
            if pub_date and pub_date < cutoff:
                continue

            title = _strip_html(entry.get("title", "")).strip() or "No title"
            link = entry.get("link", "")

            raw_summary = (
                getattr(entry, "summary", None)
                or getattr(entry, "description", None)
                or ""
            )
            summary = _strip_html(raw_summary)[:600]

            date_str = pub_date.strftime("%Y-%m-%d") if pub_date else "Unknown"

            articles.append({
                "source": feed_info["name"],
                "title": title,
                "link": link,
                "summary": summary,
                "date": date_str,
            })

    except Exception as e:
        return feed_info, articles  # silently swallow; caller will report

    return feed_info, articles


def fetch_all_feeds() -> list[dict]:
    """Fetch all feeds in parallel and return a flat list of articles."""
    all_articles: list[dict] = []
    errors: list[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_fetch_feed, feed): feed for feed in FEEDS}
        for future in concurrent.futures.as_completed(futures):
            feed_info = futures[future]
            try:
                _, articles = future.result(timeout=15)
                if articles:
                    print(f"  [+] {feed_info['name']}: {len(articles)} article(s)")
                else:
                    print(f"  [-] {feed_info['name']}: no recent articles")
                all_articles.extend(articles)
            except Exception as e:
                errors.append(f"{feed_info['name']}: {e}")
                print(f"  [!] {feed_info['name']}: fetch error")

    return all_articles
