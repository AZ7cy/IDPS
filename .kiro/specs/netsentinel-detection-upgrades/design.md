# Design: NetSentinel detection upgrades

## Overview
Four rules are added to the existing `Detector` using the same `BoundedMap` / `EventWindow` state,
cooldowns and garbage collection as the current rules. Two Qt-free modules are added: `recording.py`
for PCAP output and `feeds.py` for feed downloads. The GUI and headless mode gain options for both.

## Architecture
```
netsentinel/
  config.py      CHG  DEFAULT_BPF, LOGIN_PORTS, UDP_SCAN_MAX_PORT, PCAP_MAX_BYTES, FEED_* constants, rule seeds
  models.py      CHG  Packet.src_mac (optional, last field)
  parsing.py     CHG  ARP records, tls_sni()
  detector.py    CHG  ARP-001, AUTH-001, NET-006, TLS-001; IOC-001 ignores ARP
  recording.py   NEW  PcapRecorder (U5, Qt-free)
  feeds.py       NEW  validate_feed_url, parse_feed, fetch_feed, update_feeds (U6, Qt-free)
  store.py       CHG  replace_feed(), remove_feeds_except(), shared safety filter
  settings.py    CHG  save_pcap, save_pcap_path, feed_urls, feed_auto, feed_interval_hours, feed_last_update;
                      bpf migration
  simulation.py  CHG  udpscan, brute, tls, arp modes
  headless.py    CHG  save_pcap, feeds, feed_interval
  workers.py     CHG  LiveWorker(save_path), FeedUpdateWorker
  gui.py         CHG  PCAP recording row, feeds box, rule-tab note
  app.py         CHG  --save-pcap, --feed, --feed-interval
```

## Components and Interfaces

### Parsing
- `scapy_packet` checks for an `ARP` layer before IP. It returns
  `Packet(ts, psrc, pdst, 'ARP', None, None, len, 'who-has'|'is-at', '', source, False, ts, src_mac=hwsrc.lower())`.
- `tls_sni(data: bytes) -> str` walks the record header (type 0x16), the handshake header (type 1), version,
  random, session ID, cipher suites, compression methods and extensions, and returns the first host name
  of the `server_name` extension (type 0). Every length is bounds-checked; any failure returns `''`.
- For TCP payloads not on port 53 or an HTTP port, `payload = tls_sni(raw)` when `raw[0] == 0x16`.
- `load_layers()` imports the scapy Ethernet, IP and DNS layers. PCAP replay calls it before opening the
  file, because `PcapReader` picks its decoder from the link type when it opens the file; without it, a
  fresh process reads Ethernet captures (such as the ones U5 records) as raw bytes.

### Detector
New state tables, all cleaned by `_collect_garbage`:

| Table | Key | Window items |
|-------|-----|--------------|
| `arp` | claimed IP | sender MAC |
| `auth` | (src, dst, port) | source port |
| `udp_scan` | (src, dst) | destination port |
| `tls` | src | SNI name |

- `inspect` sends ARP packets only to `_check_arp` and returns, before the trusted-source early return.
  No other rule, including IOC-001, sees ARP packets.
- `_dga_like(name, min_len)` is shared by DNS-001 and TLS-001, so both use one scoring function.
- TLS-001 only reads `payload` for TCP packets whose destination port is not 53 or an HTTP port, which is
  exactly where the parser stores SNI.
- `AUTO_BLOCK_RULES` stays `{'WEB-001'}`.

### PcapRecorder
```python
class PcapRecorder:
    def __init__(self, path, max_bytes=PCAP_MAX_BYTES)   # opens scapy PcapWriter, chmod 0600; raises on failure
    def write(self, pkt) -> bool                         # False once full, closed or failed
    def close(self)
    packets: int; full: bool; error: str
```
Size is tracked as 24 header bytes plus 16 + `len(pkt)` per packet. `write` is guarded by a lock because the
sniffer thread writes while another thread may close.

The sniffer callback calls `recorder.write(pkt)` before parsing, so non-IP packets are recorded too.

### Feeds
```python
validate_feed_url(url) -> Optional[str]               # error message, or None
parse_feed(text) -> tuple[list[tuple[str, str]], int] # (entries, skipped)
fetch_feed(url, timeout=FEED_TIMEOUT, max_bytes=FEED_MAX_BYTES) -> str
update_feeds(store, urls, fetch=fetch_feed, should_stop=lambda: False) -> list[FeedResult]
```
- `fetch_feed` uses `urllib.request` with an opener whose redirect handler raises for non-HTTPS targets,
  reads at most `max_bytes + 1` bytes and raises if the limit is exceeded.
- `update_feeds` first calls `store.remove_feeds_except({f'feed:{u}' for u in urls})`, then for each URL
  fetches, parses and calls `store.replace_feed(f'feed:{url}', entries)`. A fetch error is recorded in the
  `FeedResult` and that feed is left unchanged.

### Store
- `_accept(entries, source, default_reason)` holds the safety filter shared by `block_many` and
  `replace_feed`: valid network, not covering protected or trusted addresses, not already a manual or
  automatic block, no duplicates.
- `replace_feed(source, entries) -> (stored, removed, skipped)`: in one transaction, deletes this source's
  entries that are not in the new set, then upserts the accepted entries.
- `remove_feeds_except(sources) -> int` deletes entries whose source starts with `feed:` and is not in `sources`.
  Entries from file imports keep the plain `feed` source and are untouched.
- `SOURCE_RANK` lookups treat any `feed:*` source like `feed`.

### GUI
- Dashboard: "Save live capture to PCAP" checkbox, path field and Browse (save dialog). `start_ids`
  requires a path when the box is ticked and asks before overwriting an existing file.
- IPS / Blocklist tab: a "Blocklist feeds" box with a URL list (one per line), "Update automatically
  every N hours", "Save feeds", "Update now" and a status line. `tick()` starts `FeedUpdateWorker` when
  automatic updates are on and the interval has passed since `feed_last_update`.
- `closeEvent` interrupts and waits for the feed worker the same way it does for the import worker.

## Data Models
- `Packet` gains `src_mac: str = ''` as its last field, so positional construction elsewhere keeps working.
  It is not stored in the database.
- New rule seeds (id, title, severity, threshold, window):
  `ARP-001` ARP spoofing indicator, HIGH, 2, 300; `AUTH-001` Login brute-force pattern, HIGH, 15, 60;
  `NET-006` UDP port-scan pattern, MEDIUM, 20, 10; `TLS-001` Suspicious TLS server names, MEDIUM, 40, 60.
  `INSERT OR IGNORE` adds them to existing databases. `RULE_VERSION` is unchanged because no existing
  default changes.
- Blocklist rows from feeds use `source = 'feed:<url>'`. No schema change.
- New settings: `save_pcap` (bool), `save_pcap_path` (str), `feed_urls` (list of str, each must pass
  `validate_feed_url`), `feed_auto` (bool, default False), `feed_interval_hours` (int, 1–168, default 24),
  `feed_last_update` (float, epoch seconds).

## Correctness Properties

### Property 1: One MAC per IP stays quiet
For any sequence of ARP packets in which every claimed IP is only ever sent with one MAC address,
ARP-001 never fires.

**Validates: Requirements 1.3**

### Property 2: Conflicting MACs fire
If an IP is claimed by two different valid MAC addresses within the rule window, ARP-001 fires once
for that IP within the cooldown, and the alert names no block target.

**Validates: Requirements 1.3, 1.4, 1.5**

### Property 3: Retransmits are not attempts
Any number of SYN packets that share one source port count as one AUTH-001 connection attempt.

**Validates: Requirements 2.1**

### Property 4: Ephemeral replies are not UDP scans
For any set of UDP packets whose destination ports are all above 32767, NET-006 never fires,
however many distinct ports there are.

**Validates: Requirements 3.2**

### Property 5: SNI parsing is total
For any byte string, `tls_sni` returns a string and never raises. For a well-formed ClientHello
with a server_name extension, it returns that name.

**Validates: Requirements 4.1**

### Property 6: Recording size limit
After any sequence of writes, the recorder's tracked size never exceeds `max_bytes`.

**Validates: Requirements 5.2**

### Property 7: Feed replacement
After `replace_feed(s, entries)`, the blocklist entries with source `s` are exactly the accepted
subset of `entries`, and entries with any other source are unchanged.

**Validates: Requirements 6.3, 6.4**

### Property 8: Failed fetch keeps entries
If a feed download fails, that feed's entries are the same after the update as before it.

**Validates: Requirements 6.5**

## Error Handling
- ARP parsing errors fall into the existing `scapy_packet` catch-all and return `None`.
- `tls_sni` catches `IndexError`, `ValueError` and decode errors and returns `''`.
- `PcapRecorder.__init__` raises when the file cannot be opened. The GUI shows an error and does not start
  the capture; headless mode exits with code 1. A later write error sets `error`, closes the writer and
  reports once, and detection continues.
- Feed download, size and parse errors are collected per feed in `FeedResult.error`. The GUI logs them;
  headless mode prints them as warnings.

## Testing Strategy
- Detector: each new rule fires on its pattern and stays quiet on the guard cases (one MAC per IP, SYN
  retransmits, ephemeral UDP ports, short or low-entropy SNI names).
- Parsing: scapy-built ARP packets and ClientHellos; truncated and random bytes for `tls_sni`.
- Recording: write a few packets, read them back with `rdpcap`; a tiny `max_bytes` stops recording.
- Feeds: `parse_feed` on Spamhaus and Feodo style text; `update_feeds` with a fake fetcher for
  replacement, removal of unconfigured feeds, protected-address skipping and a failing fetch; URL validation.
- Headless and CLI: `--save-pcap` rejected without live source; `--feed` with an invalid URL returns 2.
- GUI: rule table has 13 rows; PCAP and feed widgets save to settings.
- Real traffic: a live capture with the new default filter on this machine shows ARP packets parsed.
