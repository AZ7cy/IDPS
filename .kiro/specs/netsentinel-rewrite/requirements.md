# Requirements: NetSentinel IDPS rewrite

## Introduction
NetSentinel is a desktop intrusion detection and prevention system (IDPS) built with PyQt6.
It captures or replays network traffic, runs detection rules on each packet, stores alerts
in SQLite, and can optionally drop traffic inline on Windows (WinDivert) or Linux (NFQUEUE).

This spec defines the program so it can be rebuilt from scratch as a modular Python package.
Behavior must match the existing `NetSentinel_IDPS_v5.py` (including the fixes from the
`netsentinel-code-repair` spec) unless a requirement below says otherwise. The existing
database at `~/.netsentinel/netsentinel.db` must keep working.

## Glossary
- **Packet**: normalized metadata for one captured IP packet.
- **Alert**: a rule hit with severity, confidence, evidence and action.
- **Action**: `ALERT`, `WOULD_DROP` (dry-run) or `DROP`.
- **Protected address**: this machine's addresses, loopback, and the detected gateway, DNS and DHCP servers.
- **Trusted source**: an IP/CIDR the analyst marked as never alerted on or blocked.
- **Blocklist**: IP/CIDR entries that are manual, auto (with a TTL) or feed (imported).
- **Dry-run**: inline mode that reports `WOULD_DROP` but never drops or adds auto-blocks.

## Requirements

### R1 – Traffic sources
**User story:** As an analyst, I want to inspect live, simulated or recorded traffic.
1. The system SHALL support live capture on a chosen interface with a BPF filter (default `ip or ip6`).
2. The system SHALL generate simulated traffic covering normal traffic, port scans, horizontal scans, SYN bursts, web attacks, DNS tunneling and ICMP floods.
3. The system SHALL replay PCAP/PCAPNG files using packet capture timestamps.
4. The capture callback SHALL only parse and enqueue packets. Detection SHALL run off the capture callback, using a bounded queue (20,000 packets) that counts packets dropped when the queue is full.
5. The passive IDS and the inline IPS SHALL NOT run at the same time.

### R2 – Packet parsing
1. The system SHALL parse IPv4 and IPv6, and SHALL classify packets as TCP, UDP, ICMP, ICMPv6 or IP.
2. For DNS queries (port 53, UDP or TCP), the payload field SHALL hold the query name.
3. For TCP traffic to an HTTP port (80, 8080, 8000, 8888), the payload field SHALL hold up to 8,192 bytes of decoded text.
4. Parsing errors SHALL drop that packet only and SHALL never stop capture.

### R3 – Detection rules
**User story:** As an analyst, I want configurable rules with thresholds and windows.

| ID | Trigger (within the rule window) | Block target | Cooldown |
|----|----------------------------------|--------------|----------|
| NET-001 | unique destination ports from one source to one destination ≥ threshold (SYN only) | source | 15 s |
| NET-002 | SYNs from one source ≥ threshold | source | 15 s |
| NET-003 | SYNs to one destination ≥ threshold, from ≥ 5 sources, and SYN:SYN/ACK ratio ≥ 3 or no SYN/ACKs | none (confidence low) | 15 s |
| NET-004 | destination hosts from one source on one TCP port ≥ threshold; confidence medium if spread over ≥ 3 /24 (v4) or /64 (v6) scopes, otherwise low | source | 30 s |
| NET-005 | FIN/NULL/Xmas-style TCP packets (no ACK) from one source ≥ threshold | source | 20 s |
| ICMP-001 | ICMP/ICMPv6 packets from one source ≥ threshold | source | 15 s |
| WEB-001 | plaintext HTTP request whose decoded target matches an attack pattern, or whose User-Agent names a scanner | source | 30 s |
| DNS-001 | ≥ 8 unique query names from one source, each ≥ threshold characters long with label entropy ≥ 3.8 | source | 30 s |
| IOC-001 | source or destination is in the blocklist | the blocklisted address | 30 s |

1. Rules SHALL be seeded with the existing IDs, titles, severities, thresholds, windows and descriptions.
2. The analyst SHALL be able to enable or disable each rule and edit its severity, threshold and window. The system SHALL validate all values before saving any of them.
3. Packets from trusted sources SHALL NOT be inspected. SYN/ACKs from trusted sources SHALL still be counted for NET-003.
4. HTTP inspection SHALL reassemble fragments per flow for 5 s, with at most 32 fragments and 32 KB per flow.
5. Each detector table SHALL hold at most 5,000 keys and each key at most `max(1000, threshold + 20)` events. Eviction SHALL remove the least recently updated key and SHALL NEVER remove the key updated by the current packet.
6. Detector state older than the longest rule window (at least 120 s) SHALL be removed at most every 15 s.
7. Event time SHALL be the packet capture time when available, otherwise its timestamp.

### R4 – Inline prevention
**User story:** As an operator, I want opt-in, conservative inline blocking.
1. Inline IPS SHALL require the safety switch to be on. Turning the switch off SHALL stop a running IPS.
2. Dry-run SHALL be on by default.
3. Without dry-run, traffic to or from a blocklisted address SHALL be dropped unless either side is trusted. With dry-run, it SHALL be reported as `WOULD_DROP`.
4. Auto-blocking SHALL only apply to WEB-001 alerts with HIGH/CRITICAL severity and medium/high confidence. It SHALL require 2 hits for the same target within 60 s. The target SHALL NOT be trusted or protected, and the packet's destination SHALL be a local address.
5. Auto-blocks SHALL expire after the configured TTL (10–86,400 s, default 300 s).
6. Changing the policy of a running IPS so that it starts dropping traffic SHALL require confirmation. If the user declines, the system SHALL return to dry-run.
7. Inspection errors SHALL fail open, meaning the packet is accepted.
8. The system SHALL NEVER change firewall rules itself.

### R5 – Blocklist and trusted hosts
1. The analyst SHALL be able to add and remove IPv4/IPv6 addresses and CIDR ranges in the blocklist and the trusted list.
2. The system SHALL reject any block that covers a protected address or overlaps a trusted entry.
3. Addresses SHALL be normalized: IPv4-mapped IPv6 SHALL become IPv4, and a scope ID (`%eth0`) SHALL be removed.
4. A permanent manual block SHALL NOT be downgraded by an auto or feed block.
5. Importing a blocklist file SHALL run in the background. The file has one entry per line, `#` starts a comment, and an optional reason follows `;` or `,`. Import SHALL skip invalid, unsafe, duplicate, manual and auto entries and report how many were added and skipped.
6. Expired blocks SHALL be removed automatically.

### R6 – Storage
1. The system SHALL use the existing schema and migrate older databases by adding missing columns.
2. Rule migration SHALL update only rules whose values still match an earlier default. It SHALL never overwrite analyst changes.
3. Packets and alerts SHALL be written in batches by a dedicated writer thread with its own connection. Buffers SHALL be bounded at 100,000 packets and 20,000 alerts, and overflow SHALL be counted.
4. Retention SHALL keep the newest 50,000 packets and 20,000 alerts.
5. Packet metadata SHALL be stored only when the analyst enables it. Dropped packets SHALL always be stored.
6. Payloads SHALL be stored only when the analyst enables it. Otherwise, matched HTTP markers in alert evidence SHALL be redacted.
7. The database directory SHALL have permissions 0700 and its files 0600, where the OS supports it.
8. The analyst SHALL be able to compact the database (WAL checkpoint and optimize).

### R7 – User interface
1. The window SHALL have these tabs: Dashboard, Packets, Alerts, Detection Rules, IPS / Blocklist.
2. The dashboard SHALL show capture controls, counters (packets, alerts, unique sources, blocks, capture queue drops), engine status, packet rate and a live console limited to 2,000 lines.
3. The Packets tab SHALL show the latest 150 packets. Payloads SHALL NOT be kept in the GUI unless payload saving is enabled.
4. The Alerts tab SHALL show the latest 200 alerts. Its context menu SHALL offer Acknowledge, Close, and Block target. The selected row SHALL stay selected across refreshes.
5. The File menu SHALL offer Import blocklist, Compact database, and Export alerts as JSON or CSV.
6. The UI SHALL refresh once per second, and only the views whose data changed.
7. Repeated errors SHALL be shown at most once per 30 s.
8. On close, the system SHALL stop workers. If a worker does not stop, it SHALL ask before force-exiting.

### R8 – Reliability
1. Uncaught exceptions on any thread SHALL be appended to `~/.netsentinel/netsentinel-crash.log`.
2. A worker that does not stop within 4 s SHALL stay referenced and SHALL NOT be destroyed.
3. Discovery of protected addresses SHALL run in a background thread every 30 s and SHALL never run on the packet path.

### R9 – Code structure
1. The code SHALL be a `netsentinel` package with one module per concern. `NetSentinel_IDPS_v5.py` SHALL remain the launcher.
2. Only the GUI and worker modules SHALL import PyQt6, so that detection and storage can be used without a GUI.
3. The code SHALL pass `pyflakes` with no warnings.
