# Requirements: IDPS detection upgrades

## Introduction
These upgrades build on the `netsentinel-rewrite`, `netsentinel-enhancements` and
`netsentinel-code-repair` specs, which still apply. They add four detection rules (ARP spoofing,
login brute force, UDP port scan, suspicious TLS server names), recording of live captures to PCAP,
and scheduled blocklist feed downloads. Existing rule semantics and the database schema do not
change. Only GUI and worker code may import PyQt6.

## Requirements

### U1 – ARP spoofing detection (ARP-001)
1. The parser SHALL turn ARP packets into `Packet` records with protocol `ARP`, the sender IP as source, the target IP as destination, the operation (`who-has` or `is-at`) as flags, and the sender MAC address in a new `src_mac` field.
2. The default live capture filter SHALL be `ip or ip6 or arp`. A saved filter equal to the old default `ip or ip6` SHALL be upgraded to the new default when settings load.
3. ARP-001 SHALL alert when one IP address is claimed by at least `threshold` distinct sender MAC addresses (default 2) within `window` seconds (default 300). Probes with sender IP `0.0.0.0`, and all-zero or broadcast MACs, SHALL be ignored.
4. The alert SHALL list the MAC addresses, have confidence `high` when the IP is the gateway or another protected address and `medium` otherwise, and SHALL NOT name a block target.
5. ARP-001 SHALL run even when the claimed IP is trusted, because spoofing a trusted address is the attack. Each IP SHALL alert at most once per 60 s.

### U2 – Login brute-force detection (AUTH-001)
1. AUTH-001 SHALL count distinct TCP connection attempts (SYN without ACK, counted by source port so retransmits count once) from one source to one destination on one login port.
2. Login ports SHALL be FTP 21, SSH 22, Telnet 23, POP3 110, IMAP 143, SMB 445, MSSQL 1433, MySQL 3306, RDP 3389, PostgreSQL 5432 and VNC 5900.
3. It SHALL alert at `threshold` attempts (default 15) within `window` seconds (default 60), naming the service, with the source as block target, at most once per 60 s per source, destination and port.
4. AUTH-001 SHALL NOT be eligible for automatic blocking.

### U3 – UDP port scan detection (NET-006)
1. NET-006 SHALL count distinct UDP destination ports from one source to one destination, and alert at `threshold` ports (default 20) within `window` seconds (default 10).
2. Destination ports above 32767 SHALL be ignored, so server replies to ephemeral client ports (DNS, QUIC) are not mistaken for scans.
3. The alert SHALL have confidence `low` (UDP sources can be spoofed), name the source as block target, and fire at most once per 15 s per source and destination.

### U4 – Suspicious TLS server names (TLS-001)
1. The parser SHALL extract the server name (SNI) from a TLS ClientHello in a TCP segment on any port except DNS and the HTTP ports, and store it in `payload`. Malformed or truncated records SHALL yield an empty name and never raise.
2. TLS-001 SHALL apply the DNS-001 scoring to SNI names: a name counts when it is at least `threshold` characters long (default 40) and its labels, excluding the top-level domain, have entropy of at least 3.8 bits per character.
3. TLS-001 SHALL alert when one source sends at least 8 distinct counting names within `window` seconds (default 60), with the source as block target, at most once per 30 s per source.
4. SNI names follow the payload privacy rule: they are only stored or shown when payload saving is on.

### U5 – Save live captures to PCAP
1. Live capture in the GUI and in headless mode SHALL optionally write every captured packet, before parsing, to a PCAP file chosen by the user (`--save-pcap FILE` in headless mode).
2. Recording SHALL stop, with a message, when the file reaches 1 GiB. Detection SHALL continue.
3. A recording error SHALL be reported once and SHALL NOT stop detection. Failing to open the file SHALL stop the capture from starting.
4. The file SHALL get permissions 0600 where the OS supports it. The GUI and README SHALL warn that the file contains full packet contents.
5. `--save-pcap` with a source other than `live` SHALL be rejected with exit code 2. The headless summary SHALL report how many packets were saved.
6. The GUI SHALL remember the "save capture" choice and path.

### U6 – Blocklist feed updates
1. The user SHALL be able to configure a list of HTTPS feed URLs. Each feed SHALL be downloaded with a 15 s timeout and a 20 MB size limit, refusing redirects to non-HTTPS URLs.
2. Feed lines SHALL be parsed with the existing blocklist line format. Lines starting with `;` SHALL also count as comments. IPv4 networks shorter than /8 and IPv6 networks shorter than /16 SHALL be skipped. At most 200,000 entries per feed SHALL be accepted.
3. Entries SHALL be stored with source `feed:<url>`. An update SHALL replace that feed's previous entries, so addresses removed from the feed are unblocked. Entries for feeds that are no longer configured SHALL be removed on the next update.
4. The existing safety checks SHALL apply: entries covering protected addresses or trusted hosts are skipped, and manual or automatic blocks are never replaced.
5. A failed download SHALL leave that feed's existing entries in place and report the error.
6. The GUI SHALL offer the URL list, an "Update now" button, and automatic updates every N hours (default 24, range 1–168) that are off by default. Downloads SHALL run on a background thread.
7. Headless mode SHALL accept `--feed URL` (repeatable) and `--feed-interval HOURS`, update at startup and then on that interval in the background. Invalid URLs SHALL be rejected with exit code 2.
8. No feed SHALL be downloaded unless the user configured it.

### U7 – Integration
1. The four new rules SHALL be added to the rule seed, so existing databases get them on startup without changing edited rules.
2. Simulated traffic SHALL include patterns that trigger each new rule.
3. Tests SHALL cover each new rule, including the false-positive guards in U1.3, U2.1 and U3.2, SNI parsing, PCAP recording, feed parsing, feed replacement and the new CLI options.
4. README SHALL describe the new rules, PCAP recording and feeds, and list example feeds.
