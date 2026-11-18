"""Constants, rule seeds and detection patterns."""
from __future__ import annotations

import re
from pathlib import Path

APP_NAME = 'NetSentinel IDPS'
DATA_DIR = Path.home() / '.netsentinel'
DB_PATH = DATA_DIR / 'netsentinel.db'
CRASH_LOG = DATA_DIR / 'netsentinel-crash.log'

# Storage limits
MAX_PACKET_ROWS = 50_000
MAX_ALERT_ROWS = 20_000
PACKET_BUFFER_MAX = 100_000
ALERT_BUFFER_MAX = 20_000
WRITER_INTERVAL = 0.25
CHECKPOINT_INTERVAL = 30

# Worker limits
CAPTURE_QUEUE_MAX = 20_000
UI_EMIT_INTERVAL = 0.1
UI_BATCH_PACKETS = 100
UI_BATCH_ALERTS = 20
WORKER_STOP_TIMEOUT_MS = 4000
GUI_PACKET_ROWS = 150
GUI_ALERT_ROWS = 200
GUI_BLOCK_ROWS = 2000
ERROR_DIALOG_INTERVAL = 30
PROTECTION_REFRESH_INTERVAL = 30
GUI_RECENT_PACKETS = 5000
GUI_RELATED_PACKETS = 50

# Settings and dashboard timeline
SETTINGS_PATH = DATA_DIR / 'settings.json'
TIMELINE_BUCKET_SECONDS = 60
TIMELINE_BUCKETS = 30

# Notifications
NOTIFY_PER_KEY_INTERVAL = 60
NOTIFY_MAX_PER_MINUTE = 30
NOTIFY_QUEUE_MAX = 1000
NOTIFY_TIMEOUT = 5
SYSLOG_DEFAULT_PORT = 514

# Detector limits
MAX_EVENTS_PER_KEY = 1000
MAX_KEYS_PER_TABLE = 5000
MIN_STATE_HORIZON = 120
GC_INTERVAL = 15
COOLDOWN_RETENTION = 300
HTTP_PORTS = frozenset({80, 8080, 8000, 8888})
HTTP_PAYLOAD_MAX = 8192
HTTP_FRAGMENT_SECONDS = 5
HTTP_MAX_FRAGMENTS_PER_FLOW = 32
HTTP_MAX_BYTES_PER_FLOW = 32_768
DNS_MIN_HITS = 8
DNS_MIN_ENTROPY = 3.8
SYN_FLOOD_MIN_SOURCES = 5
SYN_FLOOD_MIN_RATIO = 3.0
TLS_MIN_HITS = 8
# Replies from servers go to ephemeral client ports (Windows 49152+, Linux 32768+), so UDP scans
# only count destination ports up to this value.
UDP_SCAN_MAX_PORT = 32767
LOGIN_PORTS = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 110: 'POP3', 143: 'IMAP', 445: 'SMB', 1433: 'MSSQL',
               3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC'}
IGNORED_MACS = frozenset({'00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'})

# Live capture. ARP is included so ARP-001 can see address claims.
DEFAULT_BPF = 'ip or ip6 or arp'
LEGACY_DEFAULT_BPF = 'ip or ip6'

# Windows inline IPS. WinDivert has its own filter language: IPv6 is "ipv6", not BPF's "ip6".
WINDIVERT_DEFAULT_FILTER = 'ip or ipv6'
LEGACY_WINDIVERT_FILTER = 'ip or ip6'      # earlier default; WinDivert rejects it ("parameter is incorrect")

# PCAP recording of live captures
PCAP_MAX_BYTES = 1 << 30

# Blocklist feeds
FEED_TIMEOUT = 15
FEED_MAX_BYTES = 20 * 1024 * 1024
FEED_MAX_ENTRIES = 200_000
FEED_MIN_PREFIX = {4: 8, 6: 16}
FEED_INTERVAL_MIN, FEED_INTERVAL_MAX, FEED_INTERVAL_DEFAULT = 1, 168, 24
FEED_USER_AGENT = 'NetSentinel-IDPS'
FEED_GUARD_MIN = 50                 # feeds with fewer stored entries are never refused for changing
FEED_MAX_CHANGE = 0.5               # refuse an update that changes more than half of a feed's entries

# Snort/Suricata signatures
SIG_PAYLOAD_MAX = 4096              # payload bytes kept per packet for signature matching
SIG_DEFAULT_HOME_NET = '[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,fe80::/10]'
SIG_MAX_EXAMPLES = 500              # skipped rules listed in the load report
SIG_FLOW_CAP = 50_000               # flows tracked for flowbits
SIG_FLOW_TIMEOUT = 600
SIG_BACKTRACK = 64                  # occurrences tried per content during relative matching
SIG_PCRE_TIMEOUT = 0.02             # seconds one pcre may run on one packet (needs the regex module)
SIG_PCRE_BACKOFF = 60.0             # after a timeout, that rule's pcre is assumed to match for this source
SIG_PCRE_BACKOFF_CAP = 10000        # (rule, source) backoff entries kept
SIG_ARCHIVE_MAX_MEMBERS = 5000      # rule archive limits (zip-bomb and abuse protection)
SIG_ARCHIVE_MAX_BYTES = 300 * 1024 * 1024   # total uncompressed .rules content per archive

# Prevention policy: only a verified, connection-oriented HTTP detection may auto-block,
# and only after repeated hits for the same target.
AUTO_BLOCK_RULES = frozenset({'WEB-001'})
AUTO_BLOCK_CONFIRMATIONS = 2
AUTO_BLOCK_CONFIRM_WINDOW = 60
TTL_MIN, TTL_MAX, TTL_DEFAULT = 10, 86_400, 300

SEVERITIES = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')

# (id, title, severity, enabled, threshold, window seconds, description)
RULE_VERSION = 4
RULE_SEED = [
    ('NET-001', 'TCP SYN port-scan pattern', 'HIGH', 1, 20, 10,
     'Many destination ports from one source to one destination'),
    ('NET-002', 'TCP SYN connection burst', 'MEDIUM', 1, 80, 5,
     'High inbound TCP SYN rate from one source'),
    ('NET-003', 'SYN flood indicator', 'HIGH', 1, 200, 5,
     'High SYN volume with source diversity and a high SYN/ACK imbalance'),
    ('NET-004', 'Horizontal TCP scan', 'HIGH', 1, 40, 15,
     'One source probes many destination hosts on one TCP port; browsing alone is not sufficient for auto-blocking'),
    ('NET-005', 'Stealth TCP scan', 'HIGH', 1, 8, 10,
     'FIN/NULL/Xmas-style TCP probing pattern'),
    ('ICMP-001', 'ICMP flood indicator', 'HIGH', 1, 250, 5,
     'High ICMP packet rate from one source'),
    ('WEB-001', 'Suspicious HTTP request pattern', 'HIGH', 1, 1, 60,
     'Suspicious markers in plaintext HTTP request traffic only'),
    ('DNS-001', 'Possible DNS tunneling / DGA', 'MEDIUM', 1, 40, 60,
     'Repeated long, high-entropy full DNS query names'),
    ('IOC-001', 'Known suspicious indicator', 'CRITICAL', 1, 1, 60,
     'Source is in the local blocklist'),
    ('ARP-001', 'ARP spoofing indicator', 'HIGH', 1, 2, 300,
     'One IP address claimed by several MAC addresses; Threshold = number of MACs'),
    ('AUTH-001', 'Login brute-force pattern', 'HIGH', 1, 15, 60,
     'Many connection attempts from one source to a login port (SSH, RDP, SMB, ...)'),
    ('NET-006', 'UDP port-scan pattern', 'MEDIUM', 1, 20, 10,
     'Many UDP destination ports (up to 32767) from one source to one destination'),
    ('TLS-001', 'Suspicious TLS server names', 'MEDIUM', 1, 40, 60,
     'Repeated long, high-entropy TLS server names (SNI); Threshold = minimum name length'),
    ('SIG-001', 'Snort/Suricata signature match', 'MEDIUM', 1, 1, 60,
     'Matches from loaded Snort/Suricata rules; severity comes from each rule; Window = seconds between '
     'repeated alerts for one signature, source and destination'),
    ('SIG-002', 'Possible regex denial-of-service (pcre timeout)', 'HIGH', 1, 1, 60,
     'A signature pcre ran past its time limit on a packet, which hostile payloads can cause on purpose. The '
     'rule is treated as matched (it still alerts) and, for 60 s, its pcre is not run for that source; '
     'Window = seconds between repeated alerts per source'),
    # Wi-Fi rules check scan results, not packets. Threshold = weakest signal considered, in -dBm.
    ('WIFI-001', 'Open or WEP Wi-Fi network nearby', 'LOW', 1, 70, 3600,
     'An access point with no encryption (or broken WEP) heard at -Threshold dBm or stronger; '
     'Window = seconds between repeats per access point'),
    ('WIFI-002', 'Possible evil twin access point', 'HIGH', 1, 90, 600,
     'An unknown access point uses the name of a trusted or connected network, or a trusted access point '
     'advertises weaker security; Threshold = weakest signal considered, in -dBm'),
    ('WIFI-003', 'Unknown access point nearby', 'MEDIUM', 1, 67, 3600,
     'A strong access point that is not trusted (possible rogue AP); runs once you trust a baseline of access '
     'points; Threshold = weakest signal considered, in -dBm'),
]
WIFI_RULE_PREFIX = 'WIFI-'

# Wi-Fi monitoring and survey
WIFI_INTERVAL_MIN, WIFI_INTERVAL_MAX, WIFI_INTERVAL_DEFAULT = 15, 3600, 60
WIFI_MAX_POINTS = 2000
SIG_RULE_ID = 'SIG-001'
SIG_TIMEOUT_RULE_ID = 'SIG-002'

# Earlier shipped (threshold, window) defaults. A rule is migrated to the current seed only
# while it still holds one of these values, so analyst edits are never overwritten.
PREVIOUS_RULE_DEFAULTS = {
    'NET-001': [(15, 10)],
    'NET-002': [(400, 5)],
    'NET-003': [(100, 5)],
    'NET-004': [(20, 15)],
    'DNS-001': [(50, 60)],
}

# Attack markers searched in the decoded HTTP request target.
PATTERNS = [re.compile(x, re.I) for x in (
    r'\.\.[/\\]',
    r'\bunion\s+(?:all\s+)?select\b',
    r'\b(?:or|and)\s+1\s*=\s*1\b',
    r'<script\b',
    r'\bcmd(?:\.exe)?\s+/[ck]\b|\bpowershell(?:\.exe)?\s+-\w+',
    r'\b(?:wget|curl)\s+https?://',
    r'/etc/(?:passwd|shadow)|\bwin\.ini\b|\bboot\.ini\b',
)]
# Scanner names are only checked in the User-Agent header, never in Host or path text.
SCANNER_UA = re.compile(r'\b(?:sqlmap|nikto|nmap|masscan|zgrab)\b', re.I)
HTTP_REQUEST_LINE = re.compile(
    r'(?im)(?:^|\r?\n)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP/1\.[01]\s*(?:\r?\n|$)')
USER_AGENT_HEADER = re.compile(r'(?im)^User-Agent:\s*([^\r\n]+)')

# TCP flag strings (scapy order) for NULL, FIN, Xmas and related probes; ACK is never set.
STEALTH_FLAGS = frozenset({'', 'F', 'U', 'FU', 'UF', 'FP', 'PF', 'FPU', 'UP', 'PU'})
