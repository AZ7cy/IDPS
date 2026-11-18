# Implementation Plan

## Overview

Make NetSentinel testable on any computer and add Wi-Fi monitoring. Tasks 1 to 8 are implemented and verified. Task 9, the permanent automated tests, is optional and not done yet.

## Tasks

- [x] 1. Automatic adapter selection
  - `interfaces.py`: `Candidate`, `choose_interface()`, `_candidates()`, `auto_interface()`.
  - Use it in `LiveWorker.run` and headless live capture when no interface is set, and report the choice. Update the GUI tooltip.
  - _Requirements: T1.1, T1.2, T1.3_

- [x] 2. Live self-test
  - `selftest.py`: `run_self_test()`, `evaluate()`, `dns_query()`, TEST-NET-1 checks and the no-route error.
  - Headless: `--self-test`, `_SelfTestState`, exit code. GUI: **Run self-test** button, `SelfTestWorker`, result dialog.
  - _Requirements: T2.1, T2.2, T2.3, T2.4, T2.5, T2.6_

- [x] 3. Sample attack recording
  - `samples.py`: deterministic scenarios, `client_hello()`, `write_samples()`, `python -m netsentinel.samples`.
  - Generate `samples/attacks.pcap`, `demo.rules` and `blocklist.txt`. Add the `.gitignore` exception.
  - _Requirements: T3.1, T3.2, T3.3, T3.4_

- [x] 4. Wi-Fi scanner
  - `wifi.py`: `AccessPoint`, `ScanResult`, the Windows Native Wifi API scanner, the `nmcli` scanner, `security_from_ies()`, `channel_from_mhz()` and specific errors.
  - _Requirements: T4.1, T4.2, T4.3, T4.4_

- [x] 5. Wireless rules and storage
  - WIFI-001 to WIFI-003 rule seeds. `WifiDetector`. Exclude WIFI-* windows from the detector horizon.
  - `Store`: `wifi_known`, `wifi_points` and `wifi_readings` tables, and the trust and survey methods.
  - `--wifi-scan`.
  - _Requirements: T4.5, T5.1, T5.2, T5.3, T5.4, T5.5, T5.6, T7.2_

- [x] 6. Wi-Fi tab and signal map
  - `WifiScanWorker`. `wifi_gui.py`: `WifiTab`, `SignalMap` (IDW heat map), trust actions, survey record, delete, clear and CSV export.
  - Settings `wifi_monitor`, `wifi_interval` and `wifi_floor_plan`. Shutdown in `closeEvent`.
  - _Requirements: T6.1, T6.2, T6.3, T6.4, T6.5, T6.6_

- [x] 7. Documentation
  - README: Quick test, Wi-Fi monitoring and signal survey, rule table, headless commands, project layout.
  - _Requirements: T7.1_

- [x] 8. Verify
  - pyflakes clean. Existing tests pass with the rule counts updated to 17.
  - Live self-test (headless and GUI), sample replay, live `--wifi-scan`, and the Wi-Fi probe script.
  - _Requirements: T2.3, T3.2, T4.1, T7.3_

- [ ]* 9. Permanent automated tests (optional)
  - `tests/test_interfaces.py`: `choose_interface` cases, including an unplugged adapter that has the lowest metric.
  - `tests/test_selftest.py`: fake `tcp` and `udp` senders that check every destination is in TEST-NET-1 and that the volume exceeds the thresholds. Also `evaluate()`.
  - `tests/test_samples.py`: build and replay the samples, and check that all 14 packet rules fire.
  - `tests/test_wifi.py`: IE decoding, channel mapping, `parse_nmcli`, the WIFI-* rule cases and cooldowns, survey storage, and an offscreen `WifiTab` run with a fake scanner.
  - _Requirements: T1.2, T2.1, T2.2, T3.2, T4.2, T5.3, T5.4, T5.5, T6.3_

## Notes

- Tasks 1, 3 and 4 are independent.
- Task 2 builds on task 1, because the self-test relies on capture using the right adapter.
- Task 5 needs the scanner types from task 4. Task 6 needs tasks 4 and 5.
- Task 7 documents tasks 1 to 6. Task 8 verifies everything before it.
- Task 9 is optional and can run any time after task 6.
- A copy of the code from before these changes is in `.backup/2026-11-18-before-wifi/`.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1", "3", "4"] },
    { "id": 1, "tasks": ["2", "5"] },
    { "id": 2, "tasks": ["6"] },
    { "id": 3, "tasks": ["7", "9"] },
    { "id": 4, "tasks": ["8"] }
  ]
}
```
