# Implementation Plan

- [x] 1. Parsing and models
  - `Packet.src_mac`, ARP records, `tls_sni()`, `DEFAULT_BPF`.
  - _Requirements: U1.1, U1.2, U4.1_

- [x] 2. Detection rules
  - ARP-001, AUTH-001, NET-006, TLS-001; rule seeds; IOC-001 ignores ARP; simulation modes.
  - _Requirements: U1.3–U1.5, U2, U3, U4.2–U4.4, U7.1, U7.2_

- [x] 3. PCAP recording
  - `recording.py`; headless `--save-pcap`; `LiveWorker(save_path)`; GUI row and settings.
  - _Requirements: U5_

- [x] 4. Blocklist feeds
  - `feeds.py`; `Store.replace_feed`, `remove_feeds_except`; `FeedUpdateWorker`; GUI box and settings;
    headless `--feed`, `--feed-interval`.
  - _Requirements: U6_

- [x] 5. Tests and documentation
  - Tests listed in U7.3; README; run the suite and a live capture.
  - _Requirements: U7.3, U7.4_
