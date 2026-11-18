# Requirements: IDPS enhancements

## Introduction
These enhancements build on the `netsentinel-rewrite` spec. They add documentation, automated
tests, usability features, a headless mode and notifications. Detection behavior, rule
semantics and the database schema do not change. Everything in the rewrite spec still applies,
including R9.2: only GUI and worker code may import PyQt6.

## Requirements

### E1 – Setup documentation
1. `requirements.txt` SHALL list the runtime dependencies (PyQt6, scapy, psutil), the Windows-only `pydivert` (with an environment marker), and the test dependency (pytest).
2. `README.md` SHALL cover installation, and how to run the GUI, each capture source, the inline IPS (Windows and Linux), headless mode and the tests. It SHALL include the admin rights, Npcap and NFQUEUE prerequisites and the safety notes.

### E2 – Automated tests
1. A pytest suite under `tests/` SHALL cover addresses, storage, every detection rule, the inline policy, parsing, blocklist import parsing, settings, the alert timeline, notifications, headless mode and a GUI smoke test.
2. Tests SHALL only use temporary databases and settings files, and SHALL never touch `~/.netsentinel`.
3. Tests that need scapy or PyQt6 SHALL be skipped when those packages are missing.

### E3 – Interface picker
1. The Interface field SHALL be an editable dropdown listing the capture interfaces with a description and IP address where known. Its first entry SHALL be "default".
2. A Refresh button SHALL reload the list. If scapy can't list interfaces, the system SHALL fall back to psutil. Typing a name SHALL still work.
3. `--list-interfaces` SHALL print the interfaces without starting the GUI.

### E4 – Alert filters
1. The Alerts tab SHALL filter by severity, rule, status and IP text. The IP text SHALL match part of the source, destination or block target.
2. Filtering SHALL run in SQL with bound parameters. Changing a filter SHALL refresh the table right away.

### E5 – Remembered settings
1. Capture source, interface, BPF filter, PCAP path, payload and packet persistence options, auto-block, TTL, Windows filter, NFQUEUE number and notification settings SHALL be saved to `~/.netsentinel/settings.json` whenever they change, and restored at startup.
2. For safety, the IPS safety switch SHALL NOT be saved, and dry-run SHALL always be on at startup.
3. Settings with an unknown key, the wrong type or an invalid value SHALL be ignored, and the default used instead. A missing or corrupt file SHALL NOT stop the program from starting.
4. Writes SHALL be atomic (write a temp file, then replace), and the file SHALL have permissions 0600 where the OS supports it.

### E6 – Dashboard chart
1. The dashboard SHALL show a stacked bar chart of alerts per minute for the last 30 minutes, with one color per rule and a legend.
2. The chart SHALL use plain Qt painting, with no extra chart dependency, and SHALL redraw at most once per second.

### E7 – Headless mode
1. `--headless` SHALL run passive detection without importing PyQt6, using `--source sim|live|pcap`, `--iface`, `--bpf`, `--pcap` and an optional `--duration` in seconds.
2. Alerts SHALL be written as JSON Lines to `--json-log` when given, and printed to stdout as one-line summaries.
3. `--db` SHALL select the database file. `--persist-packets` SHALL enable storing packet metadata.
4. Ctrl+C or the end of the duration or PCAP SHALL stop cleanly. The database writer SHALL flush, and a per-rule summary SHALL be printed. The exit code SHALL be 0 on success and 1 on a source error.
5. Headless mode SHALL NOT run the inline IPS.

### E8 – Notifications
1. Alerts at or above a chosen minimum severity (default HIGH) SHALL be sent to every enabled channel: desktop popup (GUI only), HTTP(S) webhook (JSON POST), and syslog over UDP (RFC 5424, facility local0).
2. Notifications SHALL be rate limited to one per rule and source per 60 s, and at most 30 per minute in total.
3. Webhook and syslog delivery SHALL run on a background thread with a bounded queue. Delivery SHALL never block packet processing, and failures SHALL be reported without crashing.
4. Webhook URLs SHALL be http or https with a host. Syslog targets SHALL be `host[:port]` (default port 514). Invalid values SHALL be rejected when saving.
5. Evidence SHALL be redacted in notifications unless payload saving is enabled.
6. The Notifications tab SHALL offer the settings and a "Send test notification" button. Headless mode SHALL accept `--min-severity`, `--webhook` and `--syslog`.

### E9 – Alert detail panel
1. Selecting an alert SHALL show all of its fields and its full evidence in a detail panel below the table.
2. The panel SHALL list up to 50 recent packets involving the alert's source address, taken from the in-memory buffer (last 5,000 packets) and from the database when packet persistence is on. It SHALL show a note when persistence is off.
