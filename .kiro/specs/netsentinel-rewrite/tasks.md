# Implementation Plan

- [x] 1. Package skeleton and configuration
  - Create `netsentinel/__init__.py` and `config.py` with constants, rule seeds, migration defaults and regex patterns.
  - _Requirements: R3.1, R6.2, R9.1_

- [x] 2. Models and address utilities
  - `models.py`: Packet, Alert, utc(), redact_evidence().
  - `addresses.py`: canonical_ip, normalize_network, PrefixIndex, ProtectedAddresses, is_protected, blocks_self.
  - _Requirements: R5.2, R5.3, R6.6, R8.3_

- [x] 3. Storage
  - `store.py`: schema and migrations, writer thread, bounded buffers, retention, rules, blocklist, trusted list, import, expiry, compaction, file permissions.
  - _Requirements: R5, R6_

- [x] 4. Detection engine
  - `detector.py`: EventWindow, FlowBuffer, BoundedMap, the nine rule checks, garbage collection, and the inline/auto-block policy in `process()`.
  - _Requirements: R3, R4.3, R4.4_

- [x] 5. Packet parsing
  - `parsing.py`: scapy → Packet for IPv4/IPv6, plus DNS qname and HTTP payload extraction.
  - _Requirements: R2_

- [x] 6. Workers
  - `workers.py`: base Worker (queue, batching, rate-limited errors), Live, Sim, Pcap, WinIPS, LinuxIPS, BlocklistImportWorker.
  - _Requirements: R1, R4.7, R5.5_

- [x] 7. GUI and entry point
  - `gui.py`: MainWindow with all tabs, menus, policy confirmation and close handling.
  - `app.py`: main() and crash logging. Replace `NetSentinel_IDPS_v5.py` with the launcher.
  - _Requirements: R4.1, R4.2, R4.6, R7, R8_

- [x] 8. Verification
  - pyflakes, headless detector/policy/store probes, v5 database compatibility, offscreen GUI smoke test.
  - _Requirements: R9.3, all_
