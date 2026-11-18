# Requirements: IDPS testing aids and Wi-Fi monitoring

## Introduction

Hackathon judges must be able to test IDPS on their own computers and networks. Without help, live capture can listen on an unplugged adapter and see nothing, and normal traffic rarely reaches a rule threshold. This spec adds:
- reliable adapter selection
- a live self-test
- a sample attack recording
- Wi-Fi scanning, wireless security rules and a signal survey

Everything in the `netsentinel-rewrite` and `netsentinel-enhancements` specs still applies. Only GUI and worker code may import PyQt6, and headless mode stays passive.

## Glossary

- **Access point (AP):** one Wi-Fi radio, identified by its BSSID (a MAC address). One network name (SSID) can have several APs.
- **Trusted access point:** an AP the user has marked as theirs. The trusted list is the baseline for WIFI-002 and WIFI-003.
- **TEST-NET-1:** `192.0.2.0/24`, reserved for documentation by RFC 5737 and never routed on the internet.

## Requirements

### T1 - Automatic adapter selection

**User story:** As a judge, I want live capture to use my connected adapter without choosing one, so that capture works the first time.

1. WHEN live capture starts with no interface chosen THEN the system SHALL pick an interface that is up, is not loopback, and has an address that is not link-local.
2. Among those interfaces, the system SHALL prefer one with a default route, lowest metric first. An interface that is reported as down or disconnected SHALL NOT be chosen, even if it still has a default route.
3. The system SHALL report the chosen interface, in the GUI status and on the console in headless mode. If no interface qualifies, the system SHALL fall back to the capture library default and say so.

### T2 - Live self-test

**User story:** As a judge, I want a one-click check that live capture and detection work on my network, so that I don't have to stage an attack.

1. The self-test SHALL send traffic only to TEST-NET-1, using ordinary sockets. It SHALL NOT need administrator rights.
2. The self-test SHALL exercise NET-001, AUTH-001, NET-004, NET-006 and DNS-001. It SHALL size each burst from that rule's current threshold, so edited thresholds still fire.
3. WHEN the test traffic has been sent THEN the system SHALL wait up to 4 seconds and SHALL report, for each enabled rule it exercised, whether an alert with a TEST-NET-1 destination was raised.
4. `--self-test` SHALL run headless live capture, report the results and exit with 0 only if every exercised rule fired. It SHALL be rejected for sources other than live.
5. The Dashboard SHALL have a **Run self-test** button. If live capture is not running, the button SHALL offer to start it.
6. WHEN this computer has no route to the test address THEN the system SHALL report that, not a generic socket error.

### T3 - Sample attack recording

**User story:** As a judge without Npcap or a network, I want to replay recorded attacks, so that I can see every rule fire.

1. `samples/attacks.pcap` SHALL contain one scenario for each of NET-001 to NET-006, ICMP-001, AUTH-001, ARP-001, WEB-001, DNS-001, TLS-001, IOC-001 and SIG-001, plus normal traffic.
2. With the default rules, replaying the file SHALL raise each of the 12 rules that need no extra input. With `samples/demo.rules` loaded, SIG-001 SHALL also fire. With `samples/blocklist.txt` imported, IOC-001 SHALL also fire.
3. The packets SHALL use only documentation and private addresses. `python -m netsentinel.samples` SHALL regenerate identical files.
4. Version control SHALL keep `samples/attacks.pcap` even though `.gitignore` ignores other PCAP files.

### T4 - Wi-Fi scanning

**User story:** As a user on Wi-Fi only, I want to see nearby access points, so that I can check my wireless environment without Ethernet.

1. The system SHALL scan using the OS Wi-Fi API: the Native Wifi API on Windows and `nmcli` on Linux. It SHALL NOT need monitor mode, Ethernet or administrator rights. Other platforms SHALL get a clear "not supported" error.
2. Each result SHALL include SSID (or hidden), BSSID, signal in dBm, quality, channel, band and security. Security SHALL be one of Open, WEP, WPA, WPA2, WPA3, Enterprise or OWE. On Windows it SHALL be decoded per AP from the beacon's information elements.
3. The result SHALL identify the connected network and BSSID when there is one, and SHALL list each BSSID once, keeping its strongest reading.
4. Errors SHALL be specific. When Windows denies access, the error SHALL name the Location privacy setting. A stopped WLAN service SHALL also be named.
5. `--wifi-scan` SHALL print the scan, run the Wi-Fi rules on it, store any alerts and exit.

### T5 - Wireless security rules

**User story:** As a user, I want alerts about risky or suspicious Wi-Fi networks, so that I notice evil twins and rogue access points.

1. The system SHALL add WIFI-001, WIFI-002 and WIFI-003 to the rule table. Users SHALL be able to edit them like the other rules. Each rule's threshold SHALL be the weakest signal it considers, written as a positive number (70 means -70 dBm).
2. **WIFI-001** SHALL alert on Open and WEP access points at or above the threshold. WEP alerts SHALL be at least MEDIUM severity.
3. **WIFI-002** SHALL alert when any of these is true:
   - (a) an AP that is not trusted uses the SSID of a trusted or connected network with weaker security (HIGH)
   - (b) an AP that is not trusted uses a trusted SSID with equal security (MEDIUM)
   - (c) a trusted BSSID advertises weaker security than when it was trusted (HIGH)
   
   With no trusted list, other APs of the connected network that have equal security SHALL NOT alert.
4. **WIFI-003** SHALL alert on an AP that is not trusted, not connected, and at or above the threshold. It SHALL run only once at least one AP is trusted, and SHALL NOT repeat an alert already raised by WIFI-002 in the same scan.
5. Each rule SHALL wait its Window between alerts for the same BSSID. Alerts SHALL use the normal alert pipeline: storage, the Alerts tab, notifications and the dashboard timeline. Source SHALL be `wifi`, src SHALL be the BSSID and dst SHALL be the SSID.
6. Wi-Fi rule windows SHALL NOT extend the packet detector's state horizon.

### T6 - Wi-Fi tab and signal survey

**User story:** As a user, I want to record signal strength around a building and see it on a floor plan, so that I can find weak spots.

1. The Wi-Fi tab SHALL offer **Scan now**, background monitoring every N seconds (15 to 3600, remembered), and a table of the latest scan with Trusted and Connected columns.
2. Users SHALL be able to trust selected APs, trust all visible APs, and untrust selected APs. The trusted list SHALL be stored in the database.
3. Users SHALL be able to load a floor-plan image (remembered), click a spot, name it and record a scan there. Without a floor plan, recordings SHALL be stored by name only.
4. The map SHALL colour areas by the estimated signal at recorded spots, interpolated by inverse distance and fading away from readings. It SHALL show either the strongest network at each spot or one network the user picks. A network not heard at a spot SHALL count as -100 dBm.
5. Users SHALL be able to delete a point, clear the survey (after confirmation), and export all readings to CSV.
6. Scans SHALL run off the GUI thread. Closing the window SHALL wait for running scans.

### T7 - Documentation and compatibility

1. `README.md` SHALL describe the quick test, the self-test, the samples, the Wi-Fi features and their limits:
   - no macOS support
   - "rogue" means a strong AP that is not trusted, because a laptop cannot see cabling
   - no NetSpot or Ekahau import
2. Existing databases SHALL gain the new tables and rules on startup without losing data. Existing settings files SHALL load unchanged.
3. Existing tests SHALL pass, with only the rule counts updated, and `pyflakes` SHALL report nothing.
