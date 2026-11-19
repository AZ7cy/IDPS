# IDPS

A desktop intrusion detection and prevention system written in Python and PyQt6. It inspects
live, simulated or recorded traffic using thirteen built-in detection rules plus Snort and Suricata rule files,
checks nearby Wi-Fi networks with three wireless rules, maps Wi-Fi signal strength, stores alerts in SQLite, and can
optionally drop traffic inline on Windows (WinDivert) or Linux (NFQUEUE).

> Use IDPS only on networks and systems you own or are authorized to monitor.

## Features
- **Sources:** live capture (interface picker plus BPF filter), simulated traffic, PCAP/PCAPNG replay.
  Live captures can also be saved to a PCAP file.
- **Rules:** TCP port scan, SYN burst, SYN flood, horizontal scan, stealth scan, UDP port scan, ICMP flood,
  login brute force, ARP spoofing, suspicious HTTP requests, DNS tunneling/DGA, suspicious TLS server names,
  and blocklist hits. Thresholds and windows are editable in the GUI.
- **Snort/Suricata rules:** load rule sets such as ET Open and match them without installing Snort or Suricata.
- **Prevention:** opt-in inline IPS with a safety switch, dry-run by default, and conservative auto-blocking
  with a TTL. Local and infrastructure addresses are never blocked.
- **Blocklist and trusted hosts:** IPv4/IPv6 addresses and CIDR ranges, with background import from a file
  and scheduled downloads of public blocklist feeds.
- **Analysis:** alert filters, an alert detail panel with related packets, an alerts-per-minute chart,
  and JSON/CSV export.
- **Notifications:** desktop popups, HTTP(S) webhooks and syslog (UDP, RFC 5424), all rate limited.
- **Headless mode:** passive detection from the command line, with alerts written as JSON Lines.
- **Wi-Fi:** nearby access point scanning, open/WEP, evil twin and rogue access point alerts, and a
  floor-plan signal survey.
- **Testing:** a sample attack recording and a live self-test that work on any network.

## Installation
Requires Python 3.10 or later.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt     # Windows
.\run                                                             # start it
```
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt  # Linux
./run.sh                                                            # start it
```
- Dependency version ranges are declared in one place, `pyproject.toml`. `requirements.txt` just installs the
  project with its GUI and IPS extras (`-e .[gui,ips]`), and `requirements-dev.txt` adds pytest, pyflakes,
  pip-audit and pip-tools. `requirements-lock.txt` pins the exact versions the tests last passed with, with
  hashes. For a reproducible install:
  ```
  pip install --require-hashes -r requirements-lock.txt
  pip install --no-deps -e .
  ```
  Regenerate the lock with `python tools/make_lock.py` after letting new releases age for a week or two;
  `tests/test_packaging.py` checks that the lock still satisfies the ranges in `pyproject.toml`.
- It is also an installable package: `pip install ".[gui,ips]"` gives a `netsentinel` command (headless only
  needs `pip install .`), and `python -m netsentinel` works from the project folder. Keep the quotes:
  PowerShell and zsh treat the unquoted brackets as special characters.
- `regex` is a required dependency: it puts a time limit on rule `pcre` patterns (see ReDoS protection below).
  If it is missing anyway, every rule load prints a warning in the GUI console and in headless output.
- Headless mode does not import PyQt6, so it runs on servers without Qt or graphics libraries.

Live capture prerequisites:
- **Windows:** install [Npcap](https://npcap.com/) and run as Administrator.
- **Linux:** run as root, or give Python the `cap_net_raw,cap_net_admin` capabilities.

### Running as Administrator
Live capture and the inline IPS need Administrator rights on Windows (or root on Linux). Simulated traffic,
PCAP replay, signature rules and the Wi-Fi tab work without them. On Windows, live capture can work without
Administrator if Npcap was installed without its "Restrict Npcap driver's access to Administrators only"
option; the inline IPS (WinDivert) always needs it.

**Windows:**
1. Open the Start menu, type **PowerShell**, right-click **Windows PowerShell** and choose **Run as
   administrator**. Click **Yes** in the permission prompt.
2. Go to the project folder and start IDPS:
   ```powershell
   cd C:\path\to\idps
   .\run
   ```
   The title bar of an Administrator terminal starts with "Administrator:".

If IDPS was started without these rights, an orange note at the top of the Dashboard says so. Click
**Restart as Administrator** to reopen IDPS with them: Windows asks for permission, then IDPS opens again with
the same options and this window closes. Your settings and database carry over. If you approve the prompt with
a different account's password, IDPS runs as that account and uses that account's `~/.netsentinel` folder.

**Linux:**
```bash
sudo ./run.sh                         # GUI or headless, with root
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f .venv/bin/python)"   # or: capture without sudo
```
With `setcap`, every program run with that Python binary gets these rights, so prefer `sudo` on shared
machines. Linux has no restart button; the Dashboard note shows the command instead.

Headless mode prints a warning when live capture starts without these rights. When capture fails because the
rights or Npcap/libpcap are missing, IDPS says which one and how to fix it, instead of showing the raw error.

## Quick test (any computer, any network)
`run.bat` starts IDPS with the project's virtual environment and passes on any options.
1. **Replay real attack packets.** No network, Npcap or administrator rights needed:
   ```powershell
   .\run --headless --source pcap --pcap samples\attacks.pcap --rules samples\demo.rules
   ```
   This prints alerts from the 12 behaviour rules the recording exercises plus SIG-001 (from the demo rule).
   IOC-001 needs a blocklist: first import `samples\blocklist.txt` with **File > Import IP/CIDR blocklist**.
   In the GUI, choose **PCAP replay** and `samples\attacks.pcap`. On Linux, use `./run.sh` instead of `.\run`.
2. **Live self-test.** Needs Npcap (Windows) or root (Linux):
   ```powershell
   .\run --self-test
   ```
   IDPS starts live capture on a connected adapter, sends harmless test traffic and reports whether
   NET-001, NET-004, NET-006, AUTH-001 and DNS-001 caught it. The exit code is 0 when they all did. In the GUI,
   click **Run self-test** on the Dashboard. The test traffic goes to `192.0.2.0/24` (TEST-NET-1, RFC 5737).
   That range is reserved for documentation and never routed on the internet, so no real host receives it.
   Rules wait between repeated alerts, so wait a minute before running the test again.
3. **Wi-Fi.** List nearby access points and check them with the Wi-Fi rules: `.\run --wifi-scan`.

`samples\attacks.pcap` is generated by `python -m netsentinel.samples`, which also writes `demo.rules` and
`blocklist.txt`. The packets use documentation and private addresses only.
## Running the GUI
```powershell
.\run                                                    # Windows (run.bat)
.\.venv\Scripts\python.exe idps.py --db C:\temp\lab.db    # use a different database
```
```bash
./run.sh                                                 # Linux
sudo ./run.sh                                            # Linux, for live capture
.venv/bin/python idps.py --db /tmp/lab.db                # use a different database
```
While the GUI loads, a splash screen shows the logo from `netsentinel\assets\logo.png` with a progress bar.
The same logo is the window, taskbar and tray icon, and appears at the left of the tab bar. Without the file,
the splash shows a plain title and the default icons are used.

Choose a source on the Dashboard and click **Start IDS**. "Simulated traffic" needs no privileges and
triggers most rules within a few seconds. For live capture, the interface **default** picks a connected
adapter with a network address. Windows keeps routes for unplugged adapters, so this check matters on
laptops with both Wi-Fi and Ethernet.

Data is stored in `~/.netsentinel/`:

| File | Contents |
|------|----------|
| `netsentinel.db` | alerts, rules, blocklist, trusted hosts, and optionally packets |
| `settings.json` | remembered GUI settings |
| `netsentinel-crash.log` | uncaught errors |

The IPS safety switch is never remembered, and dry-run is always on when the program starts.

## Detection rules
| Rule | Detects | Default threshold / window |
|------|---------|----------------------------|
| NET-001 | TCP SYN port scan of one host | 20 ports / 10 s |
| NET-002 | TCP SYN burst from one source | 80 SYNs / 5 s |
| NET-003 | SYN flood against one host | 200 SYNs / 5 s |
| NET-004 | Horizontal scan of one port across hosts | 40 hosts / 15 s |
| NET-005 | FIN/NULL/Xmas stealth probes | 8 probes / 10 s |
| NET-006 | UDP port scan of one host (ports up to 32767) | 20 ports / 10 s |
| ICMP-001 | ICMP flood | 250 packets / 5 s |
| AUTH-001 | Repeated connections to a login port: FTP, SSH, Telnet, POP3, IMAP, SMB, MSSQL, MySQL, RDP, PostgreSQL, VNC | 15 attempts / 60 s |
| ARP-001 | One IP address claimed by several MAC addresses (ARP spoofing) | 2 MACs / 300 s |
| WEB-001 | Attack markers in plaintext HTTP requests | 1 request |
| DNS-001 | Long, random-looking DNS query names | 8 names of 40+ characters / 60 s |
| TLS-001 | Long, random-looking TLS server names (SNI) in HTTPS handshakes | 8 names of 40+ characters / 60 s |
| IOC-001 | Traffic to or from a blocklisted address | 1 packet |
| SIG-001 | A match from a loaded Snort/Suricata rule (see below) | Window = seconds between repeats |
| SIG-002 | A rule's `pcre` exceeded its time limit, possibly a ReDoS attempt (see ReDoS protection) | 1 per source / 60 s |
| WIFI-001 | Open or WEP Wi-Fi network nearby | -70 dBm or stronger / 3600 s |
| WIFI-002 | Possible evil twin: unknown access point using a trusted or connected network's name, or a trusted access point advertising weaker security | -90 dBm / 600 s |
| WIFI-003 | Strong access point that is not trusted (possible rogue AP); runs once you trust a baseline | -67 dBm / 3600 s |

Notes:
- ARP-001 needs ARP in the capture filter. The default filter is `ip or ip6 or arp`; a saved filter that was
  the old default `ip or ip6` is upgraded automatically. ARP-001 has no block target, because the claimed
  address belongs to the victim. It runs even for trusted addresses, since spoofing a trusted address is the
  attack. The inline IPS works on IP packets and never sees ARP.
- AUTH-001 counts connection attempts by source port, so SYN retransmissions count once.
- TLS-001 reads the server name from TCP handshakes. Browsers that use QUIC (HTTP/3 over UDP) encrypt it,
  so those connections are not covered.

## Snort and Suricata rules
IDPS can load Snort 2.9, Snort 3 and Suricata rule files and match them itself. Snort and Suricata do
not need to be installed. On the **Signatures** tab, click **Add files...** or **Add folder...** and choose
`.rules` files, a folder of them, or a `.tar.gz`/`.zip` archive. In headless mode use `--rules PATH`
(repeatable) and optionally `--home-net`:

```powershell
python idps.py --headless --source live --iface "Wi-Fi" --rules emerging.rules.tar.gz
```

**You don't have to choose anything.** IDPS loads 38 built-in starter rules
(`netsentinel\assets\starter.rules`) at every start, in the GUI and in headless mode. They cover what the
behaviour rules can't see: Log4Shell, Shellshock, Spring4Shell and Struts exploits, PHP injection, probes for
`.git`/`.env`/database dumps, attack tools (Nuclei, WPScan, Gobuster, Hydra, Acunetix, Nessus), reverse shells,
PowerShell download cradles, crypto miners, Tor and ngrok lookups, RDP/Telnet/SSH/database ports exposed to the
internet, SMBv1, SNMP with the default `public` community, oversized pings from the internet, outbound IRC,
login-form brute force, outdated browsers (IE6), and cleartext passwords and card numbers. Untick **Built-in
starter rules** (or pass `--no-starter-rules`) to turn them off.

**My rules.** On the Signatures tab, open **My rules** to add your own. Pick what to watch for from the list,
type the value and click **Make rule**:

| Template | You type | Example |
|---|---|---|
| A website is looked up (DNS) | domain | `tiktok.com` |
| An HTTPS site is opened (server name) | part of the name | `bet365` |
| A page on your web server is requested | page path | `/admin` |
| A browser or tool is used (User-Agent) | part of the User-Agent | `curl/` |
| A word or phrase is sent unencrypted | word or phrase | `PROJECT-ORION` |
| Traffic to or from an address | IP address or range | `203.0.113.66` |
| A connection to a port | port(s) | `6667,6697` |
| Block a page on your web server (inline IPS) | page path | `/wp-login.php` |
| Write your own rule | the full rule | |

You can edit the rule before saving it. **Check rule** says whether IDPS can load it and, if not, why.
**Add rule** saves it to `~/.netsentinel/rules/local.rules` with the next free SID (1000001 and up) and reloads.
Your rules are always on, whatever the rule level. **Delete selected** removes them, and **Show rule file**
opens the folder so you can edit or share the file.

Other rule files and HOME_NET are under **Advanced** on the Signatures tab. Most people never need them.

For full coverage, click **Set up automatically** on the Signatures tab. It downloads ET Open, turns on daily
updates and uses the **Balanced** rule level. In headless mode, add `--et-open`.

**Rule level** decides which downloaded rules are on, so you don't have to pick from 42,000:

| Level | On (ET Open + starter) | What it skips |
|-------|------------------------|---------------|
| Balanced (default) | about 29,900 | informational and policy rules (`ET INFO`, `ET POLICY`, `ET DYN_DNS`, `ET HUNTING`, games, chat, P2P, "what is my IP" checks), which fire on ordinary home traffic |
| Essential | about 26,600 | also every rule that is not priority 1 (HIGH) |
| Everything | all 42,211 (42,173 ET Open + 38 starter) | nothing |

The built-in starter rules are always on, at every level. Rules you switch on or off yourself in the rule list
always win over the level. In headless mode use `--rule-level balanced|essential|all`.

**Set up automatically** downloads the free ET Open set for Suricata 7 over HTTPS (about 5 MB) to
`~/.netsentinel/rules/`. The download is checked before it replaces anything:
- it must match the MD5 checksum published next to it (`<url>.md5`). For ET's own server
  (`rules.emergingthreats.net`) the checksum is required: if it cannot be fetched, the update is refused. Other
  URLs are checked when they publish one. The checksum comes from the same server over the same HTTPS
  connection, so it detects corruption and truncated downloads, not a compromised server; HTTPS is what
  authenticates the server;
- it must be a real `.tar.gz` with `.rules` files, no links or device files, no absolute or `..` paths, at
  most 5,000 rule files and 300 MB of rules (archives are read in memory and never extracted to disk);
- it must not have less than half the active rules of the set it replaces (once that set has 100 or more).
  A manual update asks whether to accept such a set anyway; automatic updates never do.

Tick **Update daily** to download it again once a day while the app is open; a failed download keeps the
previous rules. To use a different rule set or Suricata version, set `sig_et_url` in `settings.json` or pass
`--et-open-url URL` in headless mode (any https `.tar.gz` of rules).

The **Loaded rules** view lists every loaded rule. Search by message, SID, `gid:sid`, category or file; filter
by category, by on/off, or by "Fired this session"; and switch rules off with the checkbox, **Disable
selected** or **Disable shown** (for example a whole category). Switched-off rules are remembered across
restarts and rule updates. The **Hits** column counts SIG-001 alerts per rule.

Each SIG-001 alert also records **why it matched**: the rule, the header and options that matched, each
buffer it checked (such as `http.uri`) with the byte offset where each `content` was found, and the rule text.
This shows in the alert detail panel. The packet bytes around each match are only included when "Save packet
payloads" is on, because they can contain user data.

To download a rule set yourself instead, the free ET Open set works as downloaded, without extracting it:

| Rule set | URL |
|----------|-----|
| ET Open for Suricata 7 (recommended) | `https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz` |
| ET Open for Snort 2.9 (legacy: Snort 2 is end-of-life) | `https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz` |

These are two different files. Tested with the November 2026 sets: 42,173 of 53,044 rules load from the
Suricata set, which is the one every count in this README refers to, and 42,039 of 52,925 from the legacy
Snort 2.9 set. Load only the Suricata set: most rules exist in both with the same SID, and if both are loaded,
the second copy of each SID is skipped (listed as "duplicate sid" in the load report), so the Snort set adds
little. Matching took about 0.2 to 0.3 ms per packet on recorded traffic.

**ReDoS protection.** Rule `pcre` patterns run on the `regex` module (a required dependency) with a 20 ms
limit per packet, after the rule's `content` checks have matched. A timeout fails closed, so an attacker cannot
dodge or switch off a rule by making its `pcre` slow:
- the `pcre` counts as matched (a negated `pcre` counts as absent), so the rule still alerts, and its alert
  detail starts with "pcre timed out (possible ReDoS); treated as match". A `pass` rule never lets traffic
  through on a timed-out `pcre`;
- rule **SIG-002** (HIGH, at most once per source per Window) reports the timeout, with no block target, since a
  large legitimate payload can also be slow;
- for the next 60 s that rule's `pcre` is not run for the same source and is assumed to match, so repeating
  the payload cannot stall detection. Then it is tried again.

The headless summary shows the number of timeouts. Without the `regex` module, `pcre` patterns run on Python's
`re` with no time limit, and every rule load prints a warning. Payloads are capped at 4 KB (see Limitations).

Each match is an alert from rule **SIG-001**, with the rule's message as the description and
`[gid:sid:rev] classtype; file:line` as evidence. Severity comes from the rule's `priority`, or its classtype:
priority 1 is HIGH, 2 is MEDIUM, 3 and 4 are LOW. Disable SIG-001 on the Detection Rules tab to stop
signature matching. Its Window (default 60 s) is the minimum time between repeated alerts for one rule,
source and destination.

`HOME_NET` defaults to the private address ranges plus this computer's public IPv6 /64 prefixes, because
home connections usually have public IPv6 addresses. `EXTERNAL_NET` is everything else. Set your own value on
the Signatures tab or with `--home-net "[192.168.1.0/24]"`.

**Supported:** actions `alert`, `pass`, `drop` and `reject` (both drop only the packet, and only in the
inline IPS outside dry-run); protocols `ip`, `tcp`, `udp`, `icmp`, `http`, `dns`, `tls`; address and port
lists, ranges, negation and variables; `content` with all its usual modifiers, `pcre`, `isdataat`, `dsize`,
`bsize`, `urilen`, `flags`, `flow`, `flowbits`, `threshold`, `detection_filter`, `sameip`; the HTTP request
buffers (`http.uri`, `http.host`, `http.user_agent`, `http.header`, `http.cookie`, `http.method` and more),
`dns.query` and `tls.sni`, in both Suricata sticky-buffer and Snort 2 modifier styles; and transforms such as
`dotprefix`, `to_lowercase` and `url_decode`.

**Not supported, so these rules are skipped:** HTTP responses and request bodies (`http.stat_code`,
`file.data`, `http.request_body`, `http_client_body`), TLS certificates and JA3, `byte_test`, `byte_jump`,
`byte_extract`, `stream_size`, `xbits`, `base64_*`, ICMP type and code, and protocols other than those
above (for example SMTP, SMB, RDP, SSH). The Signatures tab lists every skipped rule with its reason.

Known differences from Snort and Suricata:
- Matching works on single packets. There is no TCP stream reassembly, so content split across packets
  is missed, and HTTP buffers come from the first packet of a request.
- `flow:established` is approximated from the TCP flags (ACK set, SYN not set). The direction keywords
  (`to_server`, `to_client`) are accepted without being checked, because the rule header already sets the
  direction for nearly all rules.
- HTTP is recognized by its request line on any port, `dns` by port 53, and `tls` by the record header.
  HTTPS contents are encrypted, so only the server name (`tls.sni`) can be matched.

## Wi-Fi monitoring and signal survey
The **Wi-Fi** tab uses this computer's Wi-Fi adapter through the operating system (the Native Wifi API on
Windows, `nmcli` on Linux). It needs no Ethernet connection, monitor mode or administrator rights. macOS is not
supported. On Windows 11, Wi-Fi scanning may require **Settings > Privacy & security > Location** to be on,
including "Let desktop apps access your location".
- **Nearby access points:** click **Scan now**, or tick **Monitor every N s** to scan in the background. Monitoring is never resumed at startup;
  nothing scans until you start it. The
  table shows each access point's name, BSSID, signal in dBm, channel, band and security (Open, WEP, WPA,
  WPA2, WPA3, Enterprise or OWE, read from the beacon).
- **Trusted access points:** select your own access points and click **Trust selected**, or click
  **Trust all visible** where you know every network. WIFI-002 and WIFI-003 compare scans with this list.
- **Wireless rules:** the WIFI-* rules raise normal alerts, which show on the Alerts tab and go to the
  notification channels. Their Threshold is the weakest signal considered, as a positive number (70 means
  -70 dBm).
- **Distance estimates:** the access point table shows each network's estimated distance, from the
  log-distance path-loss formula `d = 10 ^ ((P1m - RSSI) / (10 x n))` metres. `P1m` is the signal 1 m from the
  access point (default -38 dBm at 2.4 GHz and -45 dBm at 5 GHz, from free-space loss at 1 m) and `n` is the
  path-loss exponent, picked with **Walls**: open space 2.2, home 3.0, office or thick walls 3.5. Hover over a
  distance to see the formula with the numbers filled in. **Calibrate...** measures your router's signal while
  you hold the laptop 1 m away and uses that as `P1m`. Walls, people and furniture change real readings, so
  expect errors of tens of percent.
- **Automatic map (default):** no drawing needed. After a scan, the map shows every network around you at its
  estimated distance, on rings at 1, 2, 5, 10, 20 and 40 m. Directions are unknown from a single spot. Record
  signal at 3 or more spots around the area and IDPS solves for where your spots and the access points
  are: it finds the positions whose distances best match all the estimates (weighted least squares, several
  random starts). The heat map is then drawn over that layout, and the map shows its typical error. It has no
  walls and may be rotated or mirrored. In tests on simulated homes with 3 dB of signal noise, spots came out
  about 1 to 2 m from their true spacing.
- **Floor plan:** choose **Floor plan** under **Map**, then click **New floor plan...** and enter the width and length of the area in metres. IDPS
  draws a scaled plan with a metre grid (half-metre lines when zoomed in), outer walls, overall dimension lines,
  a north arrow, a scale bar, a summary of the floor area and a signal colour legend. Pick what a click does
  in the **Tool** list:
  - **Draw rooms:** drag to add a room (snaps to 0.5 m). Rooms are tinted and labelled with name, size and area.
  - **Add doors** / **Add windows:** click near a wall to add a 0.9 m door (with its swing arc) or a 1.2 m
    window. Openings snap to the nearest wall and slide along it to fit.
  - **Place router:** click where your router or access point is, and name it.
  - **Record points:** place survey points (see below).

  **Undo** removes the last thing you added. The plan is saved and reopens with the app. A laptop cannot sense
  walls, so the size, rooms and openings come from you. To use an existing floor plan picture instead, click
  **Use an image...**.
- **Channels:** the **Channels** view shows which 2.4 GHz and 5 GHz channels nearby networks use, as a
  spectrum chart (2.4 GHz networks overlap their neighbours), and suggests a less crowded channel for your
  network.
- **Signal history:** the **Signal history** view graphs the connected network's signal for every scan, with
  gaps where you were disconnected, and counts drops below -67 dBm. Tick **Monitor every N s** to build it in
  the background. The history is kept while the app is open.
- **Signal survey:** choose **Record points**, walk to a spot, click it on the plan, type a name and click
  **Record signal here**. With **Measure ping** ticked (the default), each recording also pings your router
  and the internet (1.1.1.1, or 8.8.8.8 if that is blocked) 4 times using the system `ping`, which needs no
  administrator rights. **Show** colours the map by signal or by ping, and the points table lists ping and
  packet loss. Many routers ignore pings, so "no reply" for the router is normal. Each recording scans for about 4 seconds. The map colours each area by the estimated
  signal (green -60 dBm or better, yellow about -67 dBm, red -85 dBm or worse) for the strongest network or
  one you pick. **Save map image...** writes the plan with the colours and points as a PNG, and
  **Export CSV...** writes every reading. Without a plan, recordings are listed by name.

A laptop can only see access points over the air. It cannot tell whether an access point is cabled into
your wired network, so "rogue" here means "strong and not in your trusted list". IDPS does not work
with NetSpot or Ekahau files.
## Saving live captures
On the Dashboard, tick **Save live capture to PCAP** and choose a file, or pass `--save-pcap FILE` in headless
mode (live source only). Every captured packet is written before parsing, up to 1 GB, after which recording
stops and detection continues. The file holds full packet contents, including anything unencrypted, so treat
it as sensitive; it is created with owner-only permissions where the OS supports them. Replay it later with
the PCAP source to test rule thresholds against your own traffic.

## Blocklist feeds
On the **IPS / Blocklist** tab, enter one HTTPS URL per line under **Blocklist feeds**, click **Save feeds**,
then **Update now**, or tick **Update automatically every N hours**. Nothing is downloaded until you add a URL.
Examples:

| Feed | URL |
|------|-----|
| abuse.ch Feodo Tracker (botnet C2 servers) | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` |
| Spamhaus DROP (hijacked networks; free for non-commercial use) | `https://www.spamhaus.org/drop/drop.txt` |

- Each update replaces that feed's entries, so addresses removed from the feed are unblocked. Removing a URL
  from the list removes its entries on the next update.
- A failed download, or a response with no valid entries, keeps the previous entries.
- Poisoning guard: once a feed has 50 or more entries, an update that would change more than half of them is
  refused and the previous entries are kept, so a compromised or broken feed cannot suddenly mass-block
  ordinary hosts. If the change is genuine, remove the feed URL, save, and add it again.
- The usual safety rules apply: entries covering this machine, the gateway, DNS servers or trusted hosts are
  skipped, manual and automatic blocks are never replaced, and IPv4 ranges broader than /8 (IPv6 /16) are skipped.
- Downloads use HTTPS only, with a 15 s timeout and a 20 MB limit.

## Inline IPS
1. On the **IPS / Blocklist** tab, tick the safety switch. Leave dry-run on until you have checked the results.
2. **Windows:** `pydivert` is installed from `requirements.txt`. Run as Administrator. The Windows filter uses WinDivert syntax, not BPF
   (default `ip or ipv6`; for example `tcp.DstPort == 80`). An invalid filter is reported with the reason.
   The default diverts all IP traffic through IDPS. To limit the load and the blast radius, narrow it,
   for example `inbound and (tcp.DstPort == 80 or tcp.DstPort == 443)` for a web server, or
   `ip and not loopback`.
3. **Linux:** install `NetfilterQueue` and route traffic into the queue yourself:
   ```bash
   sudo iptables -I INPUT -j NFQUEUE --queue-num 1 --queue-bypass     # traffic to this machine
   sudo iptables -I FORWARD -j NFQUEUE --queue-num 1 --queue-bypass   # also needed on a router/gateway
   # when finished, the same commands with -D instead of -I
   ```
   `--queue-bypass` lets traffic through if IDPS is not running. Outgoing traffic (for example to a
   blocklisted command-and-control server) needs an `OUTPUT` rule as well. IDPS never changes
   firewall rules itself.
4. Inspection errors fail open (the packet is accepted). Auto-blocking only applies to WEB-001, needs two
   hits within 60 s against this host, and expires after the TTL.

## Headless mode
```powershell
python idps.py --headless --source sim --duration 60 --json-log alerts.jsonl
python idps.py --headless --source pcap --pcap capture.pcapng --db lab.db
python idps.py --headless --source live --iface "Wi-Fi" --bpf "tcp or udp port 53"
python idps.py --headless --source live --iface "Wi-Fi" --save-pcap capture.pcap --duration 300
python idps.py --headless --source live --feed https://feodotracker.abuse.ch/downloads/ipblocklist.txt
python idps.py --list-interfaces
python idps.py --self-test                 # live capture + self-test, then exit
python idps.py --wifi-scan                 # nearby Wi-Fi access points and WIFI-* alerts
```
On Linux, use the virtual environment's Python and `sudo` (or the capabilities above) for live capture:
```bash
.venv/bin/python idps.py --headless --source sim --duration 60 --json-log alerts.jsonl
sudo .venv/bin/python idps.py --headless --source live --iface wlan0 --et-open
./run.sh --headless --source pcap --pcap samples/attacks.pcap --rules samples/demo.rules
netsentinel --headless --source live          # after pip install ".[gui,ips]" (or pip install . on servers)
```
Without `--iface`, live capture picks a connected adapter and prints its name.
`--feed URL` can be repeated. Feeds are downloaded at startup and then every `--feed-interval` hours (default 24).
A feed update that would change more than half of a feed's entries (once it has at least 50) is refused and the
previous entries are kept, since a broken or compromised feed can list thousands of ordinary hosts. In the GUI,
**Update now** then asks whether to accept the change; in headless mode, `--accept-feed-change` accepts it on
the first update. Likewise, an ET Open update with less than half the active rules of the current set is
refused; the GUI asks after **Update ET Open now**, and headless mode has `--accept-rule-drop`.
Notifications in headless mode:
```powershell
python idps.py --headless --source live --webhook https://example.com/hook --syslog 10.0.0.5:514 --min-severity MEDIUM
```
Run `python idps.py --help` for all options. Headless mode is passive only and never
drops traffic. Ctrl+C stops it and prints a per-rule summary.

## Notifications
Click the gear button at the top right of the window (or **File > Notification settings...**). Set the minimum
severity and enable any channels:
- **Desktop:** a system tray popup, or the status bar if no tray is available.
- **Webhook:** `POST` with a JSON body containing the alert fields plus `app` and `sent_at`. Use `https://`;
  plain `http://` is refused except for this computer or a private network address (a local collector).
- **Syslog:** UDP, RFC 5424, facility local0.

Each rule and source notifies at most once per minute, with at most 30 notifications per minute in total.
Evidence is redacted unless payload saving is enabled.

## Blocklist import format
One entry per line. `#` starts a comment, and an optional reason follows `;` or `,`:
```
203.0.113.7
198.51.100.0/24 ; known scanner
2001:db8::/32, test range
```
Entries that cover a protected address, overlap a trusted host, or replace a manual or auto block are skipped.

## Tests
```powershell
.\.venv\Scripts\python.exe -m pytest
```
Install `requirements-dev.txt` first. The tests use temporary databases, settings and rule files, and never
touch `~/.netsentinel`. Tests that need scapy or PyQt6 are skipped when those packages are missing; GUI tests
always run with Qt's offscreen platform. Markers (`pytest -m "not gui"` and so on): `gui`, `needs_scapy`,
`needs_root`, `network`. Check dependencies for known vulnerabilities with
`python -m pip_audit -r requirements-lock.txt --require-hashes`. `tests/test_fuzz.py` feeds seeded random rule
text and packets to the parsers (set `NETSENTINEL_FUZZ_CASES` for a longer run).

`.github/workflows/ci.yml` runs lint and the tests on Windows and Ubuntu with Python 3.10 and 3.14 (Qt offscreen),
then the tests and pip-audit again with the exact locked versions; a weekly run also fuzzes longer.

## Troubleshooting
- **No packets on live capture (Windows):** install [Npcap](https://npcap.com/), and pick the adapter that
  carries your traffic (usually Wi-Fi) if "default" chose a different one.
- **"Live capture needs Administrator rights" or "Inline IPS does not start":** click **Restart as
  Administrator** on the Dashboard, or start IDPS from an Administrator terminal (see
  [Running as Administrator](#running-as-administrator)). For other IPS errors, such as an invalid WinDivert
  filter, the IPS tab shows the reason.
- **"Live capture needs Npcap":** install [Npcap](https://npcap.com/) and start IDPS again.
- **Wi-Fi scan "access denied" (Windows 11):** turn on Settings > Privacy & security > Location, including
  "Let desktop apps access your location".
- **Wi-Fi scan fails on Linux:** NetworkManager (`nmcli`) must be installed and running, and the user must be
  allowed to rescan (on some distributions this needs `sudo` or a polkit rule).
- **`run.bat` / `run.sh` says the virtual environment is missing:** create it with the commands it prints.

## Limitations
- Signatures match single packets: there is no IP defragmentation or TCP stream reassembly yet, so content
  split across packets or fragments is missed, and HTTPS contents are encrypted (only the server name is seen).
- The GUI runs with the same rights as capture: on Windows and Linux that means Administrator/root when
  capturing live. Run headless mode on exposed systems where possible.
- Detection runs on one CPU core. In testing, a 100 MB download over Wi-Fi (about 900 packets per second) was
  inspected with no drops and ET Open loaded; the ceiling depends on the CPU and the rules. Packets beyond it
  are dropped from the capture queue and counted on the Dashboard ("Capture queue drops") and in the headless
  summary. Drops inside the capture driver (libpcap/Npcap) are not counted yet.
- Settings, including webhook URLs, are stored in `~/.netsentinel/settings.json`. The files are owner-only: on
  Linux by file mode (0600, folders 0700); on Windows by an ACL on `~/.netsentinel` that allows only your
  account, SYSTEM and Administrators (set with `icacls`; new files inherit it). Files you place elsewhere with
  `--db`, `--json-log` or `--save-pcap` get the same restriction when created. Administrators can still read
  them, so do not put secrets in a webhook URL on a computer whose administrators you do not trust.
- Signatures see at most the first 4 KB of each packet's payload. Content after that is not matched, and an
  attacker who knows this can pad a request to hide it; behaviour rules (scans, floods, brute force) are not
  affected. This bounds the time each packet costs.
- A `pcre` that runs past its 20 ms limit is treated as matched (the rule alerts, and SIG-002 reports it), so
  a crafted slow payload can cause extra alerts but cannot switch a rule off.
- If the `regex` package is missing, `pcre` checks run without a time limit and a crafted payload can stall
  detection. IDPS warns about this on every rule load.
- The database keeps at most 20,000 alerts and 50,000 packets; older rows are deleted automatically.
- A laptop sees only its own traffic and broadcasts. To watch other devices, capture on a switch port with
  port mirroring (SPAN), or run IDPS on the gateway.

## Project layout
```
idps.py                     launcher (also: python -m netsentinel, or the netsentinel command)
run.bat / run.sh            start with the project's virtual environment (Windows / Linux)
netsentinel/                application package (see .kiro/specs for requirements and design)
netsentinel/assets/         logo and the built-in starter rules
samples/                    attack recording, demo rule and demo blocklist for testing
tests/                      pytest suite (including packaging checks and seeded fuzzing)
tools/make_lock.py          regenerates the hashed requirements-lock.txt from pyproject.toml
pyproject.toml              package metadata, the only place dependency ranges are declared, the netsentinel command
requirements*.txt           install shortcuts (-e .[...]) and the exact, hash-checked lock
.github/workflows/ci.yml    CI: Windows and Ubuntu, Python 3.10 and 3.14, locked install, pip-audit
.gitattributes              CRLF for .bat, LF for .sh
pytest.ini                  test settings and markers
pyrightconfig.json          type-checker settings
LICENSE / SECURITY.md       MIT licence; how to report a vulnerability privately
```

## Security
Report vulnerabilities privately by email to [puja280106@gmail.com](mailto:puja280106@gmail.com) or through
[GitHub security advisories](https://github.com/AZ7cy/IDPS/security/advisories/new), not in public issues.
See [SECURITY.md](SECURITY.md).

## License
[MIT](LICENSE) © 2026 AZ7cy. The ET Open rules that IDPS can download are published by Proofpoint
under their own licence and are not part of this repository.
