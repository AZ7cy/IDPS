# Requirements: NetSentinel IDPS v5 code repair

## Introduction
`NetSentinel_IDPS_v5.py` compiles and has no encoding damage, but analysis and a headless
detector probe found logic defects. This spec covers repairing them without changing
features, UI, rule semantics, or the database schema.

## Findings
| ID | Location | Defect |
|----|----------|--------|
| F1 | `Detector.inspect` NET-001, NET-004 | `_cap_keys` runs *before* the new event is appended. A brand-new key has an empty deque, sorts as the oldest, and is evicted immediately once the table holds more than 5,000 keys. The companion counter (`pair_port_counts`) is not evicted, so it keeps growing and never decays. The rule then fires on stale counts (confirmed by the probe: the alert fired while the pair key was missing from `pair_ports`). |
| F2 | `Detector._cap_keys` | Evicting a key from `pair_ports` / `syn_by_dst` leaves the matching entry in `pair_port_counts` / `syn_source_counts` out of sync. Event timestamps from PCAP replay can be out of order, so the key currently being updated can also be evicted. |
| F3 | `Detector.inspect` | Unused variable `is_synack` (pyflakes warning). |
| F4 | `Main.reset_counters` | Replaces the `defaultdict` `_last_error_dialog` with a plain `dict`, and resets `dropped_capture` twice. |
| F5 | `Main.add_trusted` / `Store.untrust` | `add_trusted` validates with `ipaddress.ip_network` while storage uses `normalize_network`. `untrust` does not normalize its key, unlike `unblock`. IPv4-mapped IPv6 input is handled inconsistently. |

## Requirements

### R1 – Bounded detector state stays consistent
**User story:** As an analyst, I want scan and flood rules to give correct counts under heavy
traffic, so that alerts are not driven by stale state.

1. WHEN a detector table exceeds its key cap THEN the system SHALL evict the least recently
   updated keys and SHALL NOT evict the key being updated by the current packet.
2. WHEN a key is evicted from a deque table THEN the system SHALL also remove the matching
   key from that table's companion counter table.
3. WHEN the key cap is exceeded THEN NET-001 SHALL alert only when the unique ports observed
   within the rule window reach the threshold.

### R2 – Clean static analysis
1. The file SHALL pass `pyflakes` with no warnings.

### R3 – Consistent counter reset and address handling
1. WHEN counters reset THEN `_last_error_dialog` SHALL remain a `defaultdict`, and each
   counter SHALL be reset once.
2. WHEN a trusted entry is added or removed THEN the system SHALL normalize the target with
   `normalize_network`, the same way the blocklist does.

### R4 – No regressions
1. All nine rules (NET-001..005, ICMP-001, WEB-001, DNS-001, IOC-001) SHALL still fire on
   the same probe traffic as before.
2. The DB schema, rule seeds, UI and public method signatures SHALL stay unchanged. New
   parameters SHALL be optional keyword parameters only.
