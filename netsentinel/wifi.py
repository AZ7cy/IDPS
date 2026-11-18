"""Wi-Fi scanning, wireless security rules (WIFI-001..003) and survey helpers.

Scanning uses the operating system's Wi-Fi API, so it works on any Wi-Fi adapter, needs no Ethernet
connection, no monitor mode and no administrator rights:
- Windows: the Native Wifi API (wlanapi.dll). Windows 11 may require Location access for this app
  (Settings > Privacy & security > Location).
- Linux: NetworkManager's `nmcli`.
"""
from __future__ import annotations

import math
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .models import Alert, utc

WIFI_RULES = ('WIFI-001', 'WIFI-002', 'WIFI-003')
HIDDEN = '<hidden>'
NO_SIGNAL_DBM = -100            # value used for a network that was not heard at a survey point
SCAN_WAIT_SECONDS = 4.0         # drivers must finish a requested scan within 4 seconds

# Security labels, weakest first. Rank compares how strong a network's protection is.
SECURITY_RANK = {'Open': 0, 'WEP': 1, 'WPA-Personal': 2, 'WPA-Enterprise': 2, 'WPA2-Personal (TKIP)': 2,
                 'OWE': 3, 'WPA/WPA2-Personal': 3, 'WPA2-Personal': 3, 'WPA2-Enterprise': 4,
                 'WPA2/WPA3-Personal': 4, 'WPA3-Personal': 5, 'WPA3-Enterprise': 5, 'Unknown': 3}


class WifiError(RuntimeError):
    pass


@dataclass(frozen=True)
class AccessPoint:
    ssid: str                   # '' for a hidden network
    bssid: str                  # lower-case aa:bb:cc:dd:ee:ff
    rssi: int                   # dBm
    signal: int                 # 0-100 link quality reported by the OS
    channel: int
    band: str
    security: str

    @property
    def name(self) -> str:
        return self.ssid or HIDDEN

    @property
    def rank(self) -> int:
        return SECURITY_RANK.get(self.security, 3)


@dataclass
class ScanResult:
    access_points: list[AccessPoint]
    interface: str = ''
    connected_ssid: str = ''
    connected_bssid: str = ''
    timestamp: str = field(default_factory=utc)
    latency: Optional[dict] = None      # measure_latency() result, for survey recordings

    def connected(self) -> Optional[AccessPoint]:
        return next((a for a in self.access_points if a.bssid == self.connected_bssid), None)


# ----------------------------------------------------------------------------
# Decoding helpers (shared by the platform scanners)
# ----------------------------------------------------------------------------
def channel_from_mhz(mhz: int) -> tuple[int, str]:
    """(channel, band) for a centre frequency in MHz; (0, '') if it is not a Wi-Fi channel."""
    if mhz == 2484:
        return 14, '2.4 GHz'
    if 2412 <= mhz <= 2472:
        return (mhz - 2407) // 5, '2.4 GHz'
    if mhz == 5935:
        return 2, '6 GHz'                       # the one 6 GHz channel below the regular grid
    if 5950 < mhz <= 7125:
        return (mhz - 5950) // 5, '6 GHz'
    if 5000 < mhz <= 5925:
        return (mhz - 5000) // 5, '5 GHz'
    if 4910 <= mhz < 5000:
        return (mhz - 4000) // 5, '4.9 GHz'     # public-safety band, channels 182-196
    return 0, ''


def quality_to_dbm(quality: int) -> int:
    """Approximate dBm for a 0-100 quality value (the mapping Windows and NetworkManager use)."""
    return int(round(max(0, min(100, quality)) / 2 - 100))


def format_bssid(raw: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in raw[:6])


_AKM_LABELS = {1: 'enterprise', 3: 'enterprise', 5: 'enterprise', 2: 'psk', 4: 'psk', 6: 'psk',
               8: 'sae', 9: 'sae', 24: 'sae', 25: 'sae', 12: 'enterprise3', 13: 'enterprise3', 18: 'owe'}


def _suites(data: bytes, i: int) -> tuple[list[int], int]:
    count = int.from_bytes(data[i:i + 2], 'little')
    i += 2
    out = []
    for _ in range(count):
        if i + 4 > len(data):
            break
        out.append(data[i + 3])
        i += 4
    return out, i


def security_from_ies(ies: bytes, privacy: bool) -> str:
    """Security label from a beacon's information elements and its capability privacy bit."""
    rsn_akms: list[int] = []
    rsn_ciphers: list[int] = []
    has_rsn = has_wpa = truncated = False
    wpa_akms: list[int] = []
    i = 0
    while i + 2 <= len(ies):
        eid, length = ies[i], ies[i + 1]
        body = ies[i + 2:i + 2 + length]
        i += 2 + length
        if len(body) < length:
            truncated = True
            break
        try:
            if eid == 48 and len(body) >= 8:            # RSN (WPA2/WPA3)
                has_rsn = True
                j = 2 + 4                               # version, group cipher
                rsn_ciphers, j = _suites(body, j)
                rsn_akms, j = _suites(body, j)
            elif eid == 221 and body[:4] == b'\x00\x50\xf2\x01':   # Microsoft WPA (version 1)
                has_wpa = True
                j = 4 + 2 + 4
                _ciphers, j = _suites(body, j)
                wpa_akms, j = _suites(body, j)
        except IndexError:
            continue
    if has_rsn:
        kinds = {_AKM_LABELS.get(a, 'other') for a in rsn_akms} or {'psk'}
        if 'enterprise3' in kinds:
            return 'WPA3-Enterprise'
        if 'enterprise' in kinds:
            return 'WPA2-Enterprise'
        if kinds == {'owe'}:
            return 'OWE'
        if 'sae' in kinds:
            return 'WPA2/WPA3-Personal' if 'psk' in kinds else 'WPA3-Personal'
        if rsn_ciphers and all(c == 2 for c in rsn_ciphers):
            return 'WPA2-Personal (TKIP)'
        return 'WPA/WPA2-Personal' if has_wpa else 'WPA2-Personal'
    if has_wpa:
        return 'WPA-Enterprise' if 1 in wpa_akms else 'WPA-Personal'
    if privacy and truncated:
        return 'Unknown'            # encrypted, but the security element could not be read
    return 'WEP' if privacy else 'Open'


def security_from_nmcli(text: str) -> str:
    words = set(text.replace('/', ' ').split())
    if not words or words == {'--'}:
        return 'Open'
    if '802.1X' in words:
        return 'WPA3-Enterprise' if 'WPA3' in words else 'WPA2-Enterprise' if 'WPA2' in words else 'WPA-Enterprise'
    if 'OWE' in words:
        return 'OWE'
    if 'WPA3' in words:
        return 'WPA2/WPA3-Personal' if 'WPA2' in words else 'WPA3-Personal'
    if 'WPA2' in words:
        return 'WPA/WPA2-Personal' if 'WPA1' in words else 'WPA2-Personal'
    if 'WPA1' in words or 'WPA' in words:
        return 'WPA-Personal'
    if 'WEP' in words:
        return 'WEP'
    return 'Unknown'


def _split_nmcli(line: str) -> list[str]:
    """Split one `nmcli -t` line on unescaped ':'."""
    fields, cur, escaped = [], [], False
    for ch in line:
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == '\\':
            escaped = True
        elif ch == ':':
            fields.append(''.join(cur))
            cur = []
        else:
            cur.append(ch)
    fields.append(''.join(cur))
    return fields


def parse_nmcli(output: str) -> ScanResult:
    """Parse `nmcli -t -e yes -f IN-USE,SSID,BSSID,FREQ,SIGNAL,SECURITY,DEVICE device wifi list`."""
    aps, connected_ssid, connected_bssid, device = [], '', '', ''
    for line in output.splitlines():
        parts = _split_nmcli(line)
        if len(parts) < 7:
            continue
        in_use, ssid, bssid, freq, signal, security, dev = parts[:7]
        try:
            mhz = int(freq.split()[0])
            quality = int(signal)
        except (ValueError, IndexError):
            continue
        channel, band = channel_from_mhz(mhz)
        ap = AccessPoint(ssid, bssid.lower(), quality_to_dbm(quality), quality, channel, band,
                         security_from_nmcli(security))
        aps.append(ap)
        device = device or dev
        if in_use.strip() == '*':
            connected_ssid, connected_bssid = ap.ssid, ap.bssid
    return ScanResult(aps, device, connected_ssid, connected_bssid)


# ----------------------------------------------------------------------------
# Platform scanners
# ----------------------------------------------------------------------------
def _scan_linux(wait: float) -> ScanResult:
    if not shutil.which('nmcli'):
        raise WifiError('Wi-Fi scanning on Linux needs NetworkManager (nmcli).')
    cmd = ['nmcli', '-t', '-e', 'yes', '-f', 'IN-USE,SSID,BSSID,FREQ,SIGNAL,SECURITY,DEVICE', 'device', 'wifi',
           'list', '--rescan', 'yes' if wait > 0 else 'no']
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WifiError(f'nmcli failed: {exc}') from exc
    if out.returncode != 0:
        raise WifiError(f'nmcli failed: {out.stderr.strip() or out.returncode}')
    return parse_nmcli(out.stdout)


def _scan_windows(wait: float) -> ScanResult:
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [('Data1', wintypes.DWORD), ('Data2', wintypes.WORD), ('Data3', wintypes.WORD),
                    ('Data4', ctypes.c_ubyte * 8)]

    class WLAN_INTERFACE_INFO(ctypes.Structure):
        _fields_ = [('InterfaceGuid', GUID), ('strInterfaceDescription', ctypes.c_wchar * 256),
                    ('isState', ctypes.c_int)]

    class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
        _fields_ = [('dwNumberOfItems', wintypes.DWORD), ('dwIndex', wintypes.DWORD),
                    ('InterfaceInfo', WLAN_INTERFACE_INFO * 1)]

    class DOT11_SSID(ctypes.Structure):
        _fields_ = [('uSSIDLength', wintypes.ULONG), ('ucSSID', ctypes.c_ubyte * 32)]

    class WLAN_RATE_SET(ctypes.Structure):
        _fields_ = [('uRateSetLength', wintypes.ULONG), ('usRateSet', wintypes.USHORT * 126)]

    class WLAN_BSS_ENTRY(ctypes.Structure):
        _fields_ = [('dot11Ssid', DOT11_SSID), ('uPhyId', wintypes.ULONG), ('dot11Bssid', ctypes.c_ubyte * 6),
                    ('dot11BssType', ctypes.c_int), ('dot11BssPhyType', ctypes.c_int), ('lRssi', wintypes.LONG),
                    ('uLinkQuality', wintypes.ULONG), ('bInRegDomain', wintypes.BOOLEAN),
                    ('usBeaconPeriod', wintypes.USHORT), ('ullTimestamp', ctypes.c_ulonglong),
                    ('ullHostTimestamp', ctypes.c_ulonglong), ('usCapabilityInformation', wintypes.USHORT),
                    ('ulChCenterFrequency', wintypes.ULONG), ('wlanRateSet', WLAN_RATE_SET),
                    ('ulIeOffset', wintypes.ULONG), ('ulIeSize', wintypes.ULONG)]

    class WLAN_BSS_LIST(ctypes.Structure):
        _fields_ = [('dwTotalSize', wintypes.DWORD), ('dwNumberOfItems', wintypes.DWORD),
                    ('wlanBssEntries', WLAN_BSS_ENTRY * 1)]

    class WLAN_ASSOCIATION_ATTRIBUTES(ctypes.Structure):
        _fields_ = [('dot11Ssid', DOT11_SSID), ('dot11BssType', ctypes.c_int), ('dot11Bssid', ctypes.c_ubyte * 6),
                    ('dot11PhyType', ctypes.c_int), ('uDot11PhyIndex', wintypes.ULONG),
                    ('wlanSignalQuality', wintypes.ULONG), ('ulRxRate', wintypes.ULONG),
                    ('ulTxRate', wintypes.ULONG)]

    class WLAN_CONNECTION_ATTRIBUTES(ctypes.Structure):
        _fields_ = [('isState', ctypes.c_int), ('wlanConnectionMode', ctypes.c_int),
                    ('strProfileName', ctypes.c_wchar * 256),
                    ('wlanAssociationAttributes', WLAN_ASSOCIATION_ATTRIBUTES)]

    try:
        api = ctypes.WinDLL('wlanapi.dll')
    except OSError as exc:
        raise WifiError('The Windows Wi-Fi service (wlanapi.dll) is not available.') from exc

    def check(code: int, what: str):
        if code == 0:
            return
        if code == 5:
            raise WifiError(f'{what}: access denied. On Windows 11, turn on Settings > Privacy & security > '
                            'Location, including "Let desktop apps access your location".')
        if code == 1062:
            raise WifiError('The WLAN AutoConfig service is not running, or this computer has no Wi-Fi adapter.')
        raise WifiError(f'{what} failed with Windows error {code}.')

    handle = wintypes.HANDLE()
    version = wintypes.DWORD()
    check(api.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)), 'Opening the Wi-Fi API')
    try:
        ifaces = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        check(api.WlanEnumInterfaces(handle, None, ctypes.byref(ifaces)), 'Listing Wi-Fi adapters')
        try:
            count = ifaces.contents.dwNumberOfItems
            if count == 0:
                raise WifiError('No Wi-Fi adapter found.')
            infos = ctypes.cast(ctypes.addressof(ifaces.contents.InterfaceInfo),
                                ctypes.POINTER(WLAN_INTERFACE_INFO * count)).contents
            info = next((i for i in infos if i.isState == 1), infos[0])     # prefer the connected adapter
            guid = GUID()
            ctypes.memmove(ctypes.byref(guid), ctypes.byref(info.InterfaceGuid), ctypes.sizeof(GUID))
            description = info.strInterfaceDescription
        finally:
            api.WlanFreeMemory(ifaces)

        if wait > 0:
            if api.WlanScan(handle, ctypes.byref(guid), None, None, None) == 0:
                time.sleep(wait)            # otherwise use the adapter's cached results

        connected_ssid = connected_bssid = ''
        size = wintypes.DWORD()
        data = ctypes.c_void_p()
        if api.WlanQueryInterface(handle, ctypes.byref(guid), 7, None, ctypes.byref(size), ctypes.byref(data),
                                  None) == 0:
            try:
                attrs = ctypes.cast(data, ctypes.POINTER(WLAN_CONNECTION_ATTRIBUTES)).contents
                assoc = attrs.wlanAssociationAttributes
                connected_ssid = bytes(assoc.dot11Ssid.ucSSID[:assoc.dot11Ssid.uSSIDLength]).decode('utf-8',
                                                                                                    'replace')
                connected_bssid = format_bssid(bytes(assoc.dot11Bssid))
            finally:
                api.WlanFreeMemory(data)

        bss_list = ctypes.POINTER(WLAN_BSS_LIST)()
        check(api.WlanGetNetworkBssList(handle, ctypes.byref(guid), None, 3, False, None, ctypes.byref(bss_list)),
              'Reading the Wi-Fi scan results')
        aps = []
        try:
            n = bss_list.contents.dwNumberOfItems
            base = ctypes.addressof(bss_list.contents.wlanBssEntries)
            for k in range(n):
                address = base + k * ctypes.sizeof(WLAN_BSS_ENTRY)
                e = WLAN_BSS_ENTRY.from_address(address)
                ssid = bytes(e.dot11Ssid.ucSSID[:min(32, e.dot11Ssid.uSSIDLength)]).decode('utf-8', 'replace')
                ssid = ssid if ssid.strip('\x00') else ''
                ies = ctypes.string_at(address + e.ulIeOffset, e.ulIeSize) if e.ulIeSize else b''
                channel, band = channel_from_mhz(e.ulChCenterFrequency // 1000)
                aps.append(AccessPoint(ssid, format_bssid(bytes(e.dot11Bssid)), int(e.lRssi), int(e.uLinkQuality),
                                       channel, band,
                                       security_from_ies(ies, bool(e.usCapabilityInformation & 0x10))))
        finally:
            api.WlanFreeMemory(bss_list)
        return ScanResult(aps, description, connected_ssid, connected_bssid)
    finally:
        api.WlanCloseHandle(handle, None)


def scan(wait: float = SCAN_WAIT_SECONDS) -> ScanResult:
    """Scan for nearby access points. `wait` = seconds to wait for a fresh scan (0 uses cached results)."""
    system = platform.system()
    if system == 'Windows':
        result = _scan_windows(wait)
    elif system == 'Linux':
        result = _scan_linux(wait)
    else:
        raise WifiError(f'Wi-Fi scanning is supported on Windows and Linux, not {system}.')
    # One row per BSSID, strongest reading first.
    best: dict[str, AccessPoint] = {}
    for ap in result.access_points:
        if ap.bssid not in best or ap.rssi > best[ap.bssid].rssi:
            best[ap.bssid] = ap
    result.access_points = sorted(best.values(), key=lambda a: (-a.rssi, a.ssid, a.bssid))
    return result


# ----------------------------------------------------------------------------
# Wireless security rules
# ----------------------------------------------------------------------------
class WifiDetector:
    """Checks scan results against WIFI-001 (open/WEP), WIFI-002 (evil twin) and WIFI-003 (unknown AP).

    Rule thresholds are signal strengths as positive numbers: 70 means "-70 dBm or stronger".
    Trusted access points are the baseline that WIFI-002 and WIFI-003 compare against.
    """

    def __init__(self, store):
        self.store = store
        self.cooldowns: dict = {}
        self.lock = threading.Lock()

    def _rules(self) -> dict:
        return {r['id']: r for r in self.store.rules() if r['id'] in WIFI_RULES and r['enabled']}

    def _due(self, key, seconds: float, now: float) -> bool:
        if now - self.cooldowns.get(key, -math.inf) < seconds:
            return False
        self.cooldowns[key] = now
        return True

    @staticmethod
    def _make(r, ap: AccessPoint, evidence: str, severity: Optional[str] = None, confidence='medium') -> Alert:
        return Alert(r['id'], r['title'], severity or r['severity'], r['description'], ap.bssid, ap.name,
                     f'{evidence}; {ap.rssi} dBm, channel {ap.channel} ({ap.band}), {ap.security}',
                     'ALERT', None, confidence, 'wifi')

    def inspect(self, result: ScanResult, now: Optional[float] = None) -> list[Alert]:
        now = time.time() if now is None else now
        rules = self._rules()
        known = self.store.wifi_known()                 # bssid -> {ssid, security}
        known_by_ssid: dict[str, list[dict]] = {}
        for row in known.values():
            if row['ssid']:
                known_by_ssid.setdefault(row['ssid'], []).append(row)
        connected = result.connected()
        out: list[Alert] = []
        with self.lock:
            for ap in result.access_points:
                twin = self._check_twin(rules.get('WIFI-002'), ap, known, known_by_ssid, connected, now, out)
                self._check_open(rules.get('WIFI-001'), ap, now, out)
                if not twin:
                    self._check_unknown(rules.get('WIFI-003'), ap, known, connected, now, out)
            self.cooldowns = {k: t for k, t in self.cooldowns.items() if now - t < 86_400}
        return out

    def _strong_enough(self, r, ap: AccessPoint) -> bool:
        return ap.rssi >= -abs(int(r['threshold']))

    def _check_open(self, r, ap: AccessPoint, now: float, out: list):
        if not r or ap.security not in ('Open', 'WEP') or not self._strong_enough(r, ap):
            return
        if self._due(('WIFI-001', ap.bssid), r['window'], now):
            what = 'no encryption' if ap.security == 'Open' else 'WEP encryption, which can be broken in minutes'
            out.append(self._make(r, ap, f'{ap.name} uses {what}',
                                  severity='MEDIUM' if ap.security == 'WEP' else None))

    def _check_twin(self, r, ap: AccessPoint, known: dict, known_by_ssid: dict, connected: Optional[AccessPoint],
                    now: float, out: list) -> bool:
        """True if this access point raised (or would raise) a WIFI-002 alert."""
        if not r or not self._strong_enough(r, ap):
            return False
        reason, severity = '', None
        mine = known.get(ap.bssid)
        if mine is not None:
            # A trusted access point that suddenly advertises weaker security may be a clone of its BSSID.
            if mine['security'] and SECURITY_RANK.get(mine['security'], 3) > ap.rank:
                reason = (f'trusted access point {ap.bssid} now advertises {ap.security} instead of '
                          f'{mine["security"]}')
        elif ap.ssid:
            references = list(known_by_ssid.get(ap.ssid, ()))
            if connected is not None and connected.ssid == ap.ssid and connected.bssid != ap.bssid:
                references.append({'security': connected.security, 'bssid': connected.bssid})
            if references and ap.bssid != (connected.bssid if connected else ''):
                best = max(references, key=lambda x: SECURITY_RANK.get(x['security'], 3))
                if ap.rank < SECURITY_RANK.get(best['security'], 3):
                    reason = (f'unknown access point uses the name "{ap.ssid}" with weaker security '
                              f'({ap.security} instead of {best["security"]})')
                    severity = 'HIGH'
                elif ap.ssid in known_by_ssid:
                    reason = (f'unknown access point uses the trusted name "{ap.ssid}"; trust it if it is a new '
                              'access point of yours')
                    severity = 'MEDIUM'
        if not reason:
            return False
        if self._due(('WIFI-002', ap.bssid), r['window'], now):
            out.append(self._make(r, ap, reason, severity=severity or r['severity'],
                                  confidence='high' if severity != 'MEDIUM' else 'medium'))
        return True

    def _check_unknown(self, r, ap: AccessPoint, known: dict, connected: Optional[AccessPoint], now: float,
                       out: list):
        # Without a baseline every neighbour would be "unknown", so this rule waits for trusted APs.
        if not r or not known or ap.bssid in known or not self._strong_enough(r, ap):
            return
        if connected is not None and ap.bssid == connected.bssid:
            return
        if self._due(('WIFI-003', ap.bssid), r['window'], now):
            out.append(self._make(r, ap, 'access point not in the trusted list is nearby (possible rogue AP)',
                                  confidence='low'))


# ----------------------------------------------------------------------------
# Survey helpers
# ----------------------------------------------------------------------------
def network_key(ap) -> str:
    """Survey map key: the network name, or the BSSID for hidden networks."""
    ssid = ap['ssid'] if isinstance(ap, dict) else ap.ssid
    bssid = ap['bssid'] if isinstance(ap, dict) else ap.bssid
    return ssid if ssid else f'{HIDDEN} {bssid}'


def strongest_by_network(readings: Iterable[dict]) -> dict[str, int]:
    """network key -> strongest dBm among the readings (several BSSIDs can share one name)."""
    out: dict[str, int] = {}
    for r in readings:
        key = network_key(r)
        out[key] = max(out.get(key, NO_SIGNAL_DBM), int(r['rssi']))
    return out


def signal_quality_label(dbm: int) -> str:
    if dbm >= -50:
        return 'excellent'
    if dbm >= -60:
        return 'good'
    if dbm >= -70:
        return 'fair'
    if dbm >= -80:
        return 'weak'
    return 'unusable'


def print_wifi_scan(db=None, out=None) -> int:
    """`--wifi-scan`: print nearby access points and WIFI-* alerts. Returns an exit code."""
    from .config import DB_PATH
    from .notify import alert_summary
    from .store import Store
    out = out or sys.stdout
    try:
        result = scan()
    except WifiError as exc:
        print(f'error: {exc}', file=out)
        return 1
    print(f'Adapter: {result.interface or "unknown"}; connected to: {result.connected_ssid or "nothing"}'
          + (f' ({result.connected_bssid})' if result.connected_bssid else ''), file=out)
    print(f'{"SSID":<28} {"BSSID":<17} {"dBm":>4} {"Ch":>3} {"Band":<7} Security', file=out)
    for ap in result.access_points:
        mark = '*' if ap.bssid == result.connected_bssid else ' '
        print(f'{mark}{ap.name[:27]:<27} {ap.bssid:<17} {ap.rssi:>4} {ap.channel:>3} {ap.band:<7} {ap.security}',
              file=out)
    store = Store(db or DB_PATH)
    try:
        alerts = WifiDetector(store).inspect(result)
        for a in alerts:
            store.add_alert(a)
            print(alert_summary(a), file=out)
        known = len(store.wifi_known())
    finally:
        store.close()
    print(f'{len(result.access_points)} access point(s); {len(alerts)} alert(s); {known} trusted access point(s).',
          file=out)
    return 0


# ----------------------------------------------------------------------------
# Generated floor plans
# ----------------------------------------------------------------------------
# A plan is a dict saved in settings: {'width': metres, 'length': metres,
#   'rooms': [{'name': str, 'x': m, 'y': m, 'w': m, 'h': m}, ...]}. (x, y) is a room's top-left corner,
# measured from the plan's top-left corner.
#   Optional details: 'doors' and 'windows': [{'x': m, 'y': m, 'vertical': bool, 'w': m}] (centre of the
#   opening on a wall), 'routers': [{'name': str, 'x': m, 'y': m}] (where access points are).
PLAN_MIN_M, PLAN_MAX_M = 2.0, 500.0
PLAN_MAX_ROOMS = 200
PLAN_MAX_ITEMS = 300            # doors, windows or routers, each
PLAN_MARGIN_PX = 64             # space around the plan for labels, dimension lines and the legend
DOOR_WIDTH_M, WINDOW_WIDTH_M = 0.9, 1.2
WALL_SNAP_M = 0.75              # how close to a wall a click must be to add a door or window
PLAN_TARGET_PX = 1200           # the longer side is drawn at about this many pixels
PLAN_SNAP_M = 0.5               # drawn rooms snap to half metres


def _number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def validate_plan(plan) -> bool:
    """True for an empty dict (no plan) or a well-formed plan whose rooms fit inside it."""
    if plan == {}:
        return True
    if not isinstance(plan, dict) or not _number(plan.get('width')) or not _number(plan.get('length')):
        return False
    w, h = plan['width'], plan['length']
    if not (PLAN_MIN_M <= w <= PLAN_MAX_M and PLAN_MIN_M <= h <= PLAN_MAX_M):
        return False
    rooms = plan.get('rooms', [])
    if not isinstance(rooms, list) or len(rooms) > PLAN_MAX_ROOMS:
        return False
    for r in rooms:
        if not isinstance(r, dict) or not isinstance(r.get('name'), str):
            return False
        if not all(_number(r.get(k)) for k in ('x', 'y', 'w', 'h')):
            return False
        if r['w'] <= 0 or r['h'] <= 0 or r['x'] < 0 or r['y'] < 0:
            return False
        if r['x'] + r['w'] > w + 1e-6 or r['y'] + r['h'] > h + 1e-6:
            return False
    for key in ('doors', 'windows'):
        items = plan.get(key, [])
        if not isinstance(items, list) or len(items) > PLAN_MAX_ITEMS:
            return False
        for o in items:
            if (not isinstance(o, dict) or not isinstance(o.get('vertical'), bool)
                    or not all(_number(o.get(k)) for k in ('x', 'y', 'w')) or not 0 < o['w'] <= 10
                    or not (0 <= o['x'] <= w + 1e-6 and 0 <= o['y'] <= h + 1e-6)):
                return False
    routers = plan.get('routers', [])
    if not isinstance(routers, list) or len(routers) > PLAN_MAX_ITEMS:
        return False
    for o in routers:
        if (not isinstance(o, dict) or not isinstance(o.get('name'), str) or not _number(o.get('x'))
                or not _number(o.get('y')) or not (0 <= o['x'] <= w + 1e-6 and 0 <= o['y'] <= h + 1e-6)):
            return False
    return True


def wall_segments(plan: dict) -> list[tuple[float, float, float, float]]:
    """Every wall as (x1, y1, x2, y2) in metres: the outer walls, then each room's four sides."""
    w, h = plan['width'], plan['length']
    segs = [(0.0, 0.0, w, 0.0), (w, 0.0, w, h), (0.0, h, w, h), (0.0, 0.0, 0.0, h)]
    for r in plan.get('rooms', []):
        x, y, rw, rh = r['x'], r['y'], r['w'], r['h']
        segs += [(x, y, x + rw, y), (x + rw, y, x + rw, y + rh), (x, y + rh, x + rw, y + rh), (x, y, x, y + rh)]
    return segs


def snap_opening(plan: dict, mx: float, my: float, width: float) -> Optional[dict]:
    """A door or window of `width` m on the wall nearest (mx, my), or None if no wall is close.

    The opening is centred on the click, moved along the wall so it fits, and snapped to 0.1 m.
    """
    best = None
    for x1, y1, x2, y2 in wall_segments(plan):
        vertical = x1 == x2
        length = (y2 - y1) if vertical else (x2 - x1)
        if length < width:
            continue
        along = my if vertical else mx
        start = y1 if vertical else x1
        centre = min(max(along, start + width / 2), start + length - width / 2)
        distance = abs(mx - x1) if vertical else abs(my - y1)
        if not (start - WALL_SNAP_M <= along <= start + length + WALL_SNAP_M):
            continue
        if best is None or distance < best[0]:
            centre = round(centre * 10) / 10
            best = (distance, {'x': x1 if vertical else centre, 'y': centre if vertical else y1,
                               'vertical': vertical, 'w': width})
    if best is None or best[0] > WALL_SNAP_M:
        return None
    return best[1]


def room_area(room: dict) -> float:
    return room['w'] * room['h']


def plan_scale(plan: dict) -> float:
    """Pixels per metre for drawing `plan`."""
    return max(10.0, min(120.0, PLAN_TARGET_PX / max(plan['width'], plan['length'])))


def plan_size_px(plan: dict) -> tuple[int, int]:
    s = plan_scale(plan)
    return (int(round(plan['width'] * s)) + 2 * PLAN_MARGIN_PX,
            int(round(plan['length'] * s)) + 2 * PLAN_MARGIN_PX)


def plan_metres_to_fraction(plan: dict, mx: float, my: float) -> tuple[float, float]:
    s = plan_scale(plan)
    w_px, h_px = plan_size_px(plan)
    return (PLAN_MARGIN_PX + mx * s) / w_px, (PLAN_MARGIN_PX + my * s) / h_px


def plan_fraction_to_metres(plan: dict, fx: float, fy: float) -> tuple[float, float]:
    """Map a position on the drawn plan (0..1 of the image) to metres, clamped to the plan."""
    s = plan_scale(plan)
    w_px, h_px = plan_size_px(plan)
    mx = (fx * w_px - PLAN_MARGIN_PX) / s
    my = (fy * h_px - PLAN_MARGIN_PX) / s
    return min(max(mx, 0.0), plan['width']), min(max(my, 0.0), plan['length'])


def snap(value: float, step: float = PLAN_SNAP_M) -> float:
    return round(value / step) * step


def room_from_drag(plan: dict, a: tuple[float, float], b: tuple[float, float], name: str) -> Optional[dict]:
    """A room for a drag between image fractions `a` and `b`, snapped to the grid; None if too small."""
    (x1, y1), (x2, y2) = plan_fraction_to_metres(plan, *a), plan_fraction_to_metres(plan, *b)
    left, right = sorted((snap(x1), snap(x2)))
    top, bottom = sorted((snap(y1), snap(y2)))
    if right - left < PLAN_SNAP_M or bottom - top < PLAN_SNAP_M:
        return None
    return {'name': name.strip()[:60] or 'Room', 'x': left, 'y': top, 'w': right - left, 'h': bottom - top}


def resize_plan(plan: dict, width: float, length: float) -> dict:
    """A plan with new dimensions, keeping only the rooms that still fit."""
    rooms = [r for r in plan.get('rooms', []) if r['x'] + r['w'] <= width and r['y'] + r['h'] <= length]
    out = {'width': float(width), 'length': float(length), 'rooms': rooms}
    for key in ('doors', 'windows', 'routers'):
        kept = [o for o in plan.get(key, []) if o['x'] <= width and o['y'] <= length]
        if key != 'routers':        # an opening must still sit on a wall
            kept = [o for o in kept if snap_opening(out, o['x'], o['y'], o['w']) == o]
        if kept:
            out[key] = kept
    return out


# ----------------------------------------------------------------------------
# Latency (ping) for survey points
# ----------------------------------------------------------------------------
INTERNET_HOSTS = ('1.1.1.1', '8.8.8.8')
PING_COUNT = 4
PING_TIMEOUT_MS = 1000
# "time=12.3 ms", "Zeit=3ms", "時間 =3ms", "time<1ms": the number before "ms" after "=" or "<".
_PING_TIME = re.compile(r'[=<]\s*([\d.,]+)\s*ms', re.I)


def parse_ping_ms(output: str) -> Optional[float]:
    """Round-trip time from one reply in `ping` output (any language), or None if there was no reply."""
    if 'ttl' not in output.lower():         # Windows prints "unreachable" replies without a TTL
        return None
    m = _PING_TIME.search(output)
    if not m:
        return None
    try:
        value = float(m.group(1).replace(',', '.'))
    except ValueError:
        return None
    return value / 2 if '<' in m.group(0) else value       # "<1ms": report half the bound


def ping_once(host: str, timeout_ms: int = PING_TIMEOUT_MS) -> Optional[float]:
    """One ICMP echo with the system `ping` (no administrator rights needed). Milliseconds or None."""
    if platform.system() == 'Windows':
        cmd = ['ping', '-n', '1', '-w', str(timeout_ms), host]
        flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)     # no console window flashing up
    else:
        cmd = ['ping', '-c', '1', '-W', str(max(1, timeout_ms // 1000)), host]
        flags = 0
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 3, creationflags=flags)
    except (OSError, subprocess.TimeoutExpired):
        return None
    # The words are localised (for example Japanese on this machine), but "TTL", "=", "<" and "ms" are ASCII
    # in every language, so a lossy decode is enough.
    return parse_ping_ms(out.stdout.decode('utf-8', 'replace'))


def _ping_series(host: str, count: int, ping=ping_once) -> tuple[Optional[float], float]:
    """(median ms, loss 0..1) over `count` pings."""
    times = [t for t in (ping(host) for _ in range(count)) if t is not None]
    if not times:
        return None, 1.0
    times.sort()
    mid = len(times) // 2
    median = times[mid] if len(times) % 2 else (times[mid - 1] + times[mid]) / 2
    return round(median, 1), round(1 - len(times) / count, 2)


def measure_latency(gateway: Optional[str] = None, count: int = PING_COUNT, ping=ping_once) -> dict:
    """Ping the router and the internet in parallel.

    Returns {'gateway_ms', 'internet_ms', 'loss'}: medians in ms (None when nothing replied) and the
    internet packet loss from 0 to 1. Loss is measured to the internet because routers often ignore pings.
    """
    if gateway is None:
        from .interfaces import default_gateway
        gateway = default_gateway()
    results: dict = {}

    def run(key, host):
        results[key] = _ping_series(host, count, ping)

    threads = [threading.Thread(target=run, args=('internet', INTERNET_HOSTS[0]), daemon=True)]
    if gateway:
        threads.append(threading.Thread(target=run, args=('gateway', gateway), daemon=True))
    for t in threads:
        t.start()
    for t in threads:
        t.join(count * (PING_TIMEOUT_MS / 1000 + 3))
    internet_ms, loss = results.get('internet', (None, 1.0))
    if internet_ms is None:                     # first host blocked: try the second one
        internet_ms, loss = _ping_series(INTERNET_HOSTS[1], count, ping)
    return {'gateway_ms': results.get('gateway', (None, 1.0))[0], 'internet_ms': internet_ms, 'loss': loss,
            'gateway': gateway or ''}


def ping_quality_label(ms: Optional[float]) -> str:
    if ms is None:
        return 'no reply'
    if ms <= 30:
        return 'good'
    if ms <= 80:
        return 'fair'
    if ms <= 150:
        return 'slow'
    return 'very slow'


# ----------------------------------------------------------------------------
# Channel congestion
# ----------------------------------------------------------------------------
CHANNELS_24 = tuple(range(1, 14))
NON_OVERLAPPING_24 = (1, 6, 11)
# Non-DFS 5 GHz channels that every router supports; DFS channels can be suggested by the router itself.
PREFERRED_5 = (36, 40, 44, 48, 149, 153, 157, 161, 165)


def _strength(ap: AccessPoint) -> float:
    """0 for -100 dBm up to 1 for -40 dBm or stronger."""
    return max(0.0, min(1.0, (ap.rssi + 100) / 60))


def channel_load(aps: Iterable[AccessPoint], channel: int, band: str, ignore: frozenset = frozenset()) -> float:
    """How crowded `channel` is. A 2.4 GHz network 20 MHz wide also overlaps 4 channels on each side."""
    load = 0.0
    for ap in aps:
        if ap.bssid in ignore or ap.band != band or not ap.channel:
            continue
        diff = abs(ap.channel - channel)
        if band == '2.4 GHz':
            if diff <= 4:
                load += _strength(ap) * (1 - diff / 5)
        elif diff == 0:
            load += _strength(ap)
    return round(load, 3)


def channel_advice(result: ScanResult) -> list[str]:
    """Plain-language channel suggestions for the connected network (or the area, if not connected)."""
    aps = result.access_points
    if not aps:
        return ['No access points in the last scan.']
    connected = result.connected()
    own = frozenset(a.bssid for a in aps if connected is not None and a.ssid and a.ssid == connected.ssid)
    lines = []
    for band, choices in (('2.4 GHz', NON_OVERLAPPING_24), ('5 GHz', PREFERRED_5)):
        here = [a for a in aps if a.band == band]
        if not here:
            continue
        loads = {ch: channel_load(aps, ch, band, own) for ch in choices}
        best = min(choices, key=lambda ch: (loads[ch], ch))
        mine = next((a for a in here if a.bssid in own), None)
        others = len([a for a in here if a.bssid not in own])
        if mine is not None:
            current = channel_load(aps, mine.channel, band, own)
            if mine.channel == best or current <= loads[best] + 0.15:
                lines.append(f'{band}: your network "{mine.ssid}" is on channel {mine.channel}, which is a good '
                             f'choice ({others} other access point(s) on this band).')
            else:
                lines.append(f'{band}: your network "{mine.ssid}" is on channel {mine.channel} (load '
                             f'{current:.2f}). Channel {best} is less crowded (load {loads[best]:.2f}); change it '
                             'in your router settings.')
        else:
            lines.append(f'{band}: {others} access point(s). The least crowded channel is {best} '
                         f'(load {loads[best]:.2f}).')
    if connected is None:
        lines.append('Connect to your network to get advice for it specifically.')
    return lines


# ----------------------------------------------------------------------------
# Signal history of the connected network
# ----------------------------------------------------------------------------
HISTORY_MAX = 5000
DROP_DBM = -67                  # below this, video calls start to suffer


class SignalHistory:
    """(time, dBm or None when disconnected, network name) per scan, newest last."""

    def __init__(self, maxlen: int = HISTORY_MAX):
        from collections import deque
        self.points = deque(maxlen=maxlen)

    def add(self, result: ScanResult, t: Optional[float] = None):
        ap = result.connected()
        self.points.append((time.time() if t is None else t, ap.rssi if ap else None,
                            (ap.ssid or HIDDEN) if ap else ''))

    def clear(self):
        self.points.clear()

    def __len__(self):
        return len(self.points)

    def drops(self) -> int:
        """Times the signal fell from usable (DROP_DBM or better) to weak or disconnected."""
        count, prev = 0, None
        for _t, dbm, _name in self.points:
            ok = dbm is not None and dbm >= DROP_DBM
            if prev is True and not ok:
                count += 1
            prev = ok
        return count

    def summary(self) -> str:
        values = [d for _t, d, _n in self.points if d is not None]
        if not self.points:
            return 'No readings yet. Each scan adds one; tick "Monitor every" to build a history.'
        if not values:
            return f'{len(self.points)} reading(s), all while disconnected.'
        now = self.points[-1][1]
        span = self.points[-1][0] - self.points[0][0]
        minutes = f'{span / 60:.0f} min' if span >= 60 else f'{span:.0f} s'
        offline = sum(1 for _t, d, _n in self.points if d is None)
        return (f'Now {now if now is not None else "disconnected"}{" dBm" if now is not None else ""}; over '
                f'{minutes} ({len(self.points)} readings): best {max(values)}, average '
                f'{sum(values) / len(values):.0f}, worst {min(values)} dBm; {self.drops()} drop(s) below '
                f'{DROP_DBM} dBm' + (f'; disconnected in {offline} reading(s)' if offline else '') + '.')


# ----------------------------------------------------------------------------
# Distance from signal strength, and an automatic layout from survey readings
# ----------------------------------------------------------------------------
# Log-distance path-loss model:   RSSI(d) = P1m - 10 * n * log10(d)
#                         so      d = 10 ** ((P1m - RSSI) / (10 * n))   metres
# P1m is the signal 1 m from the access point. Free-space loss at 1 m is 40 dB at 2.4 GHz and 46.7 dB at
# 5 GHz; with a typical home router's ~0 to +5 dBm effective output that gives about -38 and -45 dBm.
# n is the path-loss exponent: 2 in free space, about 3 indoors with walls (published indoor measurements
# range from 2.5 to 4). Calibration replaces the default P1m with a measured one.
REFERENCE_DBM = {'2.4 GHz': -38.0, '5 GHz': -45.0, '6 GHz': -47.0, '4.9 GHz': -44.0}
ENVIRONMENTS = (('home', 'Home (walls)', 3.0), ('open', 'Open space', 2.2), ('office', 'Office / thick walls', 3.5))
PATH_LOSS = {key: n for key, _label, n in ENVIRONMENTS}
DIST_MIN, DIST_MAX = 0.5, 80.0
LAYOUT_MIN_POINTS = 3           # fewer recorded spots: a "radar" around the latest one instead
LAYOUT_MAX_APS = 24             # strongest access points used to solve the layout


def estimate_distance(rssi: float, band: str, n: float = 3.0, offset: float = 0.0) -> float:
    """Metres to an access point heard at `rssi` dBm. `offset` is the calibration correction to P1m in dB."""
    p1m = REFERENCE_DBM.get(band, -40.0) + offset
    return max(DIST_MIN, min(DIST_MAX, 10 ** ((p1m - rssi) / (10 * n))))


def distance_label(metres: float) -> str:
    if metres <= DIST_MIN:
        return 'under 1 m'
    if metres >= DIST_MAX:
        return f'over {DIST_MAX:g} m'
    return f'~{metres:.0f} m' if metres >= 10 else f'~{metres:.1f} m'


def calibration_offset(rssi_at_1m: float, band: str) -> float:
    """Correction so that `rssi_at_1m`, measured 1 m from the access point, means 1 m."""
    return round(rssi_at_1m - REFERENCE_DBM.get(band, -40.0), 1)


@dataclass
class Layout:
    """Estimated positions in metres. Orientation is arbitrary; only distances are estimated."""
    mode: str                                   # 'solved' (3+ spots) or 'radar' (one spot, directions unknown)
    points: list[tuple[float, float]]           # one per survey point, in the order given
    aps: list[tuple[str, str, float, float, float]]   # name, bssid, x, y, mean dBm
    error_m: float = 0.0                        # typical mismatch between the layout and the distances
    point_ids: list = field(default_factory=list)
    distances: list[float] = field(default_factory=list)    # radar: true estimated metres, per access point


def radar_radius(metres: float) -> float:
    """Radar drawing radius for a distance. Logarithmic, so 1 m and 40 m both fit on one picture."""
    return 6.0 + 5.0 * math.log2(1.0 + metres)     # +6 keeps very near access points off the centre


def _solve(n_points: int, n_aps: int, meas: list[tuple[int, int, float, float]], seed: int,
           iterations: int) -> tuple[list[list[float]], list[list[float]], float]:
    """Gradient descent on weighted stress sum(w * (|p_i - a_j| - d_ij)^2). Returns (points, aps, stress)."""
    import random
    rnd = random.Random(seed)
    spread = max(1.0, sum(d for _i, _j, d, _w in meas) / len(meas))
    P = [[rnd.uniform(-spread, spread) / 2, rnd.uniform(-spread, spread) / 2] for _ in range(n_points)]
    A = [[rnd.uniform(-spread, spread), rnd.uniform(-spread, spread)] for _ in range(n_aps)]
    count_p, count_a = [0] * n_points, [0] * n_aps
    for i, j, _d, _w in meas:
        count_p[i] += 1
        count_a[j] += 1
    for it in range(iterations):
        rate = 0.5 * (1 - it / iterations) + 0.02
        gp = [[0.0, 0.0] for _ in range(n_points)]
        ga = [[0.0, 0.0] for _ in range(n_aps)]
        for i, j, d, w in meas:
            dx, dy = P[i][0] - A[j][0], P[i][1] - A[j][1]
            dist = math.hypot(dx, dy) or 1e-6
            g = w * (dist - d) / dist
            gp[i][0] += g * dx
            gp[i][1] += g * dy
            ga[j][0] -= g * dx
            ga[j][1] -= g * dy
        for i in range(n_points):
            if count_p[i]:
                P[i][0] -= rate * gp[i][0] / count_p[i]
                P[i][1] -= rate * gp[i][1] / count_p[i]
        for j in range(n_aps):
            if count_a[j]:
                A[j][0] -= rate * ga[j][0] / count_a[j]
                A[j][1] -= rate * ga[j][1] / count_a[j]
    total = weight = 0.0
    for i, j, d, w in meas:
        e = math.hypot(P[i][0] - A[j][0], P[i][1] - A[j][1]) - d
        total += w * e * e
        weight += w
    return P, A, math.sqrt(total / weight) if weight else 0.0


def auto_layout(points: list[tuple[object, list[dict]]], n: float = 3.0, offset: float = 0.0,
                restarts: int = 10, iterations: int = 1500) -> Optional[Layout]:
    """Estimate where survey points and access points are, from signal strength alone.

    `points` is [(point id, readings)], each reading a dict with ssid, bssid, rssi and band. With 3 or more
    points, positions are solved so that every point-to-access-point distance matches its estimate as well
    as possible. With fewer, the latest point is placed in the middle and access points around it at their
    estimated distance (direction unknown). Returns None if there is nothing to place.
    """
    points = [(pid, [r for r in rows if r.get('bssid')]) for pid, rows in points]
    points = [(pid, rows) for pid, rows in points if rows]
    if not points:
        return None
    heard: dict[str, list] = {}
    for idx, (_pid, rows) in enumerate(points):
        for r in rows:
            heard.setdefault(r['bssid'], []).append((idx, r))
    if len(points) < LAYOUT_MIN_POINTS:
        pid, rows = points[-1]
        # One marker per network name: a router usually has a 2.4 GHz and a 5 GHz radio (and hidden mesh
        # links), which would otherwise stack on top of each other.
        groups: dict[str, list] = {}
        for r in rows:
            groups.setdefault(r['ssid'] or HIDDEN, []).append(
                (estimate_distance(r['rssi'], r.get('band', ''), n, offset), r))
        ranked = sorted(groups.items(), key=lambda kv: min(d for d, _r in kv[1]))[:LAYOUT_MAX_APS]
        aps, distances = [], []
        for k, (name, members) in enumerate(ranked):
            d, r = min(members, key=lambda m: m[0])
            radius = radar_radius(d)
            # Spread evenly, starting just past straight up, so none lands exactly on your label (to the right).
            angle = -math.pi / 2 + 2 * math.pi * (k + 0.35) / max(1, len(ranked))
            label = (name if len(name) <= 20 else name[:19] + '...') + \
                (f' ({len(members)} radios)' if len(members) > 1 else '')
            aps.append((label, r['bssid'], radius * math.cos(angle), radius * math.sin(angle), float(r['rssi'])))
            distances.append(d)
        layout_points = [(0.0, 0.0) if i == len(points) - 1 else (math.nan, math.nan) for i in range(len(points))]
        return Layout('radar', layout_points, aps, 0.0, [p for p, _ in points], distances)
    # Prefer access points heard at several points (they constrain the layout), then the strongest.
    ranked = sorted(heard.items(), key=lambda kv: (-len(kv[1]), -max(r['rssi'] for _i, r in kv[1])))
    chosen = [b for b, seen in ranked if len(seen) >= 2][:LAYOUT_MAX_APS] or [ranked[0][0]]
    index = {b: j for j, b in enumerate(chosen)}
    meas = []
    for b in chosen:
        for i, r in heard[b]:
            d = estimate_distance(r['rssi'], r.get('band', ''), n, offset)
            meas.append((i, index[b], d, 1.0 / max(d, 1.0)))      # near readings are more reliable
    best = None
    for seed in range(restarts):
        result = _solve(len(points), len(chosen), meas, seed, iterations)
        if best is None or result[2] < best[2]:
            best = result
    P, A, err = best
    # Centre on the survey points and turn the map so the strongest access point is at the top.
    cx = sum(p[0] for p in P) / len(P)
    cy = sum(p[1] for p in P) / len(P)
    strongest = max(range(len(chosen)), key=lambda j: max(r['rssi'] for _i, r in heard[chosen[j]]))
    ax, ay = A[strongest][0] - cx, A[strongest][1] - cy
    turn = -math.pi / 2 - math.atan2(ay, ax) if (ax or ay) else 0.0
    cos_t, sin_t = math.cos(turn), math.sin(turn)
    rot = lambda x, y: ((x - cx) * cos_t - (y - cy) * sin_t, (x - cx) * sin_t + (y - cy) * cos_t)
    aps = []
    for j, b in enumerate(chosen):
        rows = [r for _i, r in heard[b]]
        best_row = max(rows, key=lambda r: r['rssi'])
        x, y = rot(*A[j])
        aps.append((best_row['ssid'] or f'{HIDDEN} {b}', b, x, y, sum(r['rssi'] for r in rows) / len(rows)))
    return Layout('solved', [rot(*p) for p in P], aps, round(err, 1), [p for p, _ in points])
