"""Download and refresh the free ET Open rule set (Qt-free)."""
from __future__ import annotations

import hashlib
import io
import os
import re
import tarfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

from .config import DATA_DIR, FEED_USER_AGENT
from .feeds import _HttpsOnlyRedirects, validate_feed_url

# The rule set for the newest Suricata release IDPS's parser is tested with. Change it with the
# "sig_et_url" setting or --et-open-url; any https .tar.gz of Suricata/Snort rules works.
ET_OPEN_URL = 'https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz'
RULES_DIR = DATA_DIR / 'rules'
ET_OPEN_PATH = RULES_DIR / 'emerging.rules.tar.gz'
RULES_TIMEOUT = 60
RULES_MAX_BYTES = 150 * 1024 * 1024
RULES_UPDATE_SECONDS = 24 * 3600        # "Update daily"
RULES_RETRY_SECONDS = 3600              # after a failed automatic update
MD5_REQUIRED_HOSTS = frozenset({'rules.emergingthreats.net'})
RULES_GUARD_MIN = 100                   # the drop guard only protects rule sets at least this large
RULES_MAX_DROP = 0.5                    # refuse an update that removes more than this share of active rules


@dataclass
class RuleDownload:
    path: str
    size: int
    rule_files: int
    changed: bool
    verified: bool = False          # matched the publisher's .md5

    def summary(self) -> str:
        what = 'updated' if self.changed else 'already up to date'
        check = ('checksum verified (integrity only)' if self.verified
                 else 'no published checksum to verify against')
        return (f'ET Open {what}: {self.rule_files} rule file(s), {self.size / 1_048_576:.1f} MB, {check}; saved '
                f'to {self.path}.')


def fetch_bytes(url: str, timeout: float = RULES_TIMEOUT, max_bytes: int = RULES_MAX_BYTES,
                should_stop: Callable[[], bool] = lambda: False) -> bytes:
    """Download over HTTPS only (redirects too), capped at `max_bytes`."""
    error = validate_feed_url(url)
    if error:
        raise ValueError(error.replace('Feed URL', 'Rule URL'))
    opener = urllib.request.build_opener(_HttpsOnlyRedirects)
    request = urllib.request.Request(url, headers={'User-Agent': FEED_USER_AGENT})
    chunks, total = [], 0
    with opener.open(request, timeout=timeout) as response:
        while True:
            if should_stop():
                raise InterruptedError('download cancelled')
            chunk = response.read(1 << 16)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f'rule download is larger than {max_bytes // 1_048_576} MB')
            chunks.append(chunk)
    return b''.join(chunks)


def check_archive(data: bytes) -> int:
    """Number of .rules files in a .tar.gz. Raises ValueError if it is not a safe rule archive."""
    from .signatures import ArchiveError, check_archive_members
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
            members = [m for m in tar.getmembers() if m.isfile() and m.name.endswith('.rules')]
            links = [m.name for m in tar.getmembers() if m.issym() or m.islnk() or m.isdev()]
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ValueError(f'the download is not a valid .tar.gz rule archive ({exc})') from exc
    if not members:
        raise ValueError('the archive contains no .rules files')
    if links:
        raise ValueError(f'the archive contains links or device files ({links[0][:60]}), which rule sets never do')
    try:
        check_archive_members([(m.name, m.size) for m in members], 'the archive')
    except ArchiveError as exc:
        raise ValueError(str(exc)) from exc
    return len(members)


class RuleCountDropped(ValueError):
    """The new archive has far fewer active rules than the one it would replace."""

    def __init__(self, old: int, new: int):
        self.old, self.new = old, new
        super().__init__(f'the new rule set has {new:,} active rules, down from {old:,} (more than '
                         f'{RULES_MAX_DROP:.0%} fewer); this looks like a broken or tampered download, so the '
                         'previous rules are kept')


_ACTIVE_RULE = re.compile(rb'^[ \t]*(?:alert|drop|reject|rejectsrc|rejectdst|rejectboth|pass|sdrop)[ \t]',
                          re.M | re.I)


def count_rules(data: bytes) -> int:
    """Active (not commented out) rules in a .tar.gz rule archive. Call check_archive first."""
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith('.rules'):
                f = tar.extractfile(member)
                if f is not None:
                    total += len(_ACTIVE_RULE.findall(f.read()))
    return total


def requires_md5(url: str) -> bool:
    """ET publishes a .md5 next to every archive, so for ET downloads a missing checksum is an error."""
    return (urlsplit(url).hostname or '').lower() in MD5_REQUIRED_HOSTS


def published_md5(url: str, fetch: Callable[..., bytes]) -> Optional[str]:
    """The checksum ET publishes next to the archive (<url>.md5), or None if there is none."""
    try:
        text = fetch(url + '.md5', max_bytes=4096).decode('ascii', 'replace').strip()
    except Exception:
        return None
    digest = text.split()[0].lower() if text else ''
    return digest if len(digest) == 32 and all(c in '0123456789abcdef' for c in digest) else None


def download_et_open(url: str = ET_OPEN_URL, dest: Optional[Path] = None,
                     fetch: Callable[..., bytes] = fetch_bytes,
                     should_stop: Callable[[], bool] = lambda: False, force: bool = False) -> RuleDownload:
    """Download the archive, check it, and replace `dest` atomically. A failed download keeps the old file.

    The .md5 check catches corruption and truncation; it is fetched from the same server, so it does not prove
    who published the file. `force` accepts a rule set much smaller than the current one (RuleCountDropped).
    """
    data = fetch(url, should_stop=should_stop)
    expected = published_md5(url, fetch)
    if expected is None and requires_md5(url):
        raise ValueError(f'{urlsplit(url).hostname} publishes a checksum (.md5) for every archive, but it could '
                         'not be downloaded, so this download is not trusted and the previous rules are kept')
    if expected is not None and hashlib.md5(data).hexdigest() != expected:
        raise ValueError('the download does not match the checksum the publisher lists (.md5); it may be '
                         'corrupted or truncated, so the previous rules are kept')
    files = check_archive(data)
    dest = Path(dest) if dest is not None else ET_OPEN_PATH     # looked up now, so tests can redirect it
    old_data = dest.read_bytes() if dest.is_file() else None
    changed = old_data is None or hashlib.sha256(old_data).digest() != hashlib.sha256(data).digest()
    if changed and old_data is not None and not force:
        try:
            old_count = count_rules(old_data)
        except (tarfile.TarError, OSError, EOFError):
            old_count = 0                                       # the old file is unreadable: nothing to protect
        new_count = count_rules(data)
        if old_count >= RULES_GUARD_MIN and new_count < old_count * (1 - RULES_MAX_DROP):
            raise RuleCountDropped(old_count, new_count)
    if changed:
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + '.tmp')
        tmp.write_bytes(data)
        os.replace(tmp, dest)
    return RuleDownload(str(dest), len(data), files, changed, verified=expected is not None)


def update_due(auto: bool, last_success: float, last_attempt: Optional[float], now: float) -> bool:
    """Whether an automatic daily update should start now."""
    if not auto:
        return False
    if last_attempt is not None and now - last_attempt < RULES_RETRY_SECONDS:
        return False
    return now - last_success >= RULES_UPDATE_SECONDS
