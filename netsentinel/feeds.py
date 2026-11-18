"""Download IP/CIDR blocklist feeds over HTTPS (Qt-free)."""
from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Iterable, Optional
from urllib.parse import urlsplit

from .addresses import normalize_network
from .config import (FEED_GUARD_MIN, FEED_MAX_BYTES, FEED_MAX_CHANGE, FEED_MAX_ENTRIES, FEED_MIN_PREFIX,
                     FEED_TIMEOUT, FEED_USER_AGENT)

FEED_SOURCE_PREFIX = 'feed:'      # same as store.FEED_PREFIX


def feed_source(url: str) -> str:
    """Blocklist `source` value for entries from this feed."""
    return FEED_SOURCE_PREFIX + url


def validate_feed_url(url: str) -> Optional[str]:
    """Return an error message, or None if `url` is an acceptable feed URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return f'Invalid feed URL: {url}'
    if parts.scheme != 'https' or not parts.hostname:
        return f'Feed URL must be https:// with a host name: {url}'
    if any(c.isspace() for c in url):
        return f'Feed URL must not contain spaces: {url}'
    return None


def parse_feed(text: str) -> tuple[list[tuple[str, str]], int]:
    """Parse feed text into ([(network, reason)], skipped).

    Uses the blocklist file format, also treating lines that start with `;` as comments. Networks
    broader than FEED_MIN_PREFIX are skipped, so one bad line cannot block a large part of the internet.
    """
    from .store import parse_blocklist_line
    entries: list[tuple[str, str]] = []
    skipped = 0
    for raw in text.splitlines():
        if raw.lstrip().startswith(';'):
            continue
        parsed = parse_blocklist_line(raw)
        if parsed is None:
            continue
        target, reason = parsed
        try:
            net = normalize_network(target)
        except ValueError:
            skipped += 1
            continue
        if net.prefixlen < FEED_MIN_PREFIX[net.version] or len(entries) >= FEED_MAX_ENTRIES:
            skipped += 1
            continue
        entries.append((str(net), reason))
    return entries, skipped


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != 'https':
            raise urllib.error.URLError(f'refused redirect to non-HTTPS URL {newurl}')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_feed(url: str, timeout: float = FEED_TIMEOUT, max_bytes: int = FEED_MAX_BYTES) -> str:
    """Download a feed as text. Raises on network errors, non-HTTPS URLs and oversized responses."""
    error = validate_feed_url(url)
    if error:
        raise ValueError(error)
    opener = urllib.request.build_opener(_HttpsOnlyRedirects)
    request = urllib.request.Request(url, headers={'User-Agent': FEED_USER_AGENT})
    with opener.open(request, timeout=timeout) as response:
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f'feed is larger than {max_bytes // (1024 * 1024)} MB')
    return data.decode('utf-8', 'replace')


def feed_change_error(old: set, new: set) -> str:
    """'' if replacing `old` feed entries with `new` looks normal, else why the update is refused.

    A compromised or broken feed could suddenly list thousands of ordinary hosts. Small feeds and the
    first download are always accepted; afterwards, an update that changes more than FEED_MAX_CHANGE of
    the entries is refused and the previous entries are kept.
    """
    if len(old) < FEED_GUARD_MIN:
        return ''
    changed = len(old ^ new)
    share = changed / max(len(old), 1)
    if share <= FEED_MAX_CHANGE:
        return ''
    return (f'refused: the update would change {changed:,} of {len(old):,} entries ({share:.0%}), more than the '
            f'{FEED_MAX_CHANGE:.0%} safety limit. The previous entries are kept; if the change is genuine, '
            'accept it when asked after "Update now" (headless: --accept-feed-change)')


@dataclass
class FeedResult:
    url: str
    stored: int = 0
    removed: int = 0
    skipped: int = 0
    error: str = ''
    guarded: bool = False           # refused by the change guard; update_feeds(force_urls=...) accepts it

    def summary(self) -> str:
        if self.error:
            return f'Feed {self.url} failed: {self.error}'
        return f'Feed {self.url}: {self.stored:,} entries, {self.removed:,} removed, {self.skipped:,} skipped'


def update_feeds(store, urls: Iterable[str], fetch: Callable[[str], str] = fetch_feed,
                 should_stop: Callable[[], bool] = lambda: False,
                 force_urls: Iterable[str] = ()) -> list[FeedResult]:
    """Download each feed and replace its blocklist entries. A failed feed keeps its old entries.

    Feeds in `force_urls` skip the change guard (the user accepted a large change)."""
    urls = list(dict.fromkeys(urls))
    forced = set(force_urls)
    store.remove_feeds_except({feed_source(u) for u in urls})
    results = []
    for url in urls:
        if should_stop():
            break
        result = FeedResult(url)
        try:
            entries, result.skipped = parse_feed(fetch(url))
            if not entries and result.skipped:
                # Probably an error page, not an empty feed: keep the previous entries.
                raise ValueError(f'no valid entries ({result.skipped:,} lines skipped)')
            guard = '' if url in forced else feed_change_error(store.feed_keys(feed_source(url)),
                                                                {net for net, _ in entries})
            if guard:
                result.guarded = True
                raise ValueError(guard)
            stored, result.removed, rejected = store.replace_feed(feed_source(url), entries,
                                                                  default_reason=f'Feed {urlsplit(url).hostname}')
            result.stored, result.skipped = stored, result.skipped + rejected
        except Exception as exc:
            result.error = str(exc) or exc.__class__.__name__
        results.append(result)
    return results
