"""Persistent user settings stored as JSON."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Optional

from .config import (DEFAULT_BPF, FEED_INTERVAL_DEFAULT, FEED_INTERVAL_MAX, FEED_INTERVAL_MIN, LEGACY_DEFAULT_BPF,
                     LEGACY_WINDIVERT_FILTER, WINDIVERT_DEFAULT_FILTER,
                     SETTINGS_PATH, SEVERITIES, TTL_DEFAULT, TTL_MAX, TTL_MIN, WIFI_INTERVAL_DEFAULT,
                     WIFI_INTERVAL_MAX, WIFI_INTERVAL_MIN)
from .feeds import validate_feed_url
from .secure import restrict_to_owner
from .signatures import validate_home_net
from .wifi import validate_plan

DEFAULTS: dict[str, Any] = {
    'source_index': 1,              # 0 live, 1 simulated, 2 pcap
    'iface': '',
    'bpf': DEFAULT_BPF,
    'pcap_path': '',
    'keep_payload': False,
    'persist_packets': False,
    'auto_block': False,
    'dry_run': True,
    'ttl': TTL_DEFAULT,
    'ips_filter': WINDIVERT_DEFAULT_FILTER,
    'queue_num': 1,
    'notify_min_severity': 'HIGH',
    'notify_desktop': True,
    'notify_webhook': '',
    'notify_syslog': '',
    'save_pcap': False,
    'save_pcap_path': '',
    'feed_urls': [],
    'feed_auto': False,
    'feed_interval_hours': FEED_INTERVAL_DEFAULT,
    'feed_last_update': 0.0,
    'sig_paths': [],
    'sig_home_net': '',
    'sig_disabled': [],             # 'gid:sid' of rules switched off in the rule browser
    'sig_enabled': [],              # 'gid:sid' switched on in the browser although the rule level turns them off
    'sig_level': 'balanced',        # signatures.RULE_LEVELS
    'sig_builtin': True,            # load the built-in starter rules
    'sig_et_auto': False,           # download ET Open again every day
    'sig_et_last': 0.0,             # time of the last successful ET Open download
    'sig_et_url': '',               # '' = rule_updates.ET_OPEN_URL; any https .tar.gz rule set
    'wifi_monitor': False,
    'wifi_interval': WIFI_INTERVAL_DEFAULT,
    'wifi_floor_plan': '',          # uploaded image; used only when there is no generated plan
    'wifi_plan': {},                # generated floor plan (see wifi.validate_plan)
    'wifi_layout': 'auto',          # 'auto': layout estimated from signal; 'plan': floor plan or image
    'wifi_env': 'home',             # wifi.ENVIRONMENTS: path-loss exponent for distance estimates
    'wifi_cal': 0.0,                # calibration offset in dB, measured 1 m from the router
}

VALIDATORS: dict[str, Callable[[Any], bool]] = {
    'source_index': lambda v: 0 <= v <= 2,
    'ttl': lambda v: TTL_MIN <= v <= TTL_MAX,
    'queue_num': lambda v: 0 <= v <= 65535,
    'notify_min_severity': lambda v: v in SEVERITIES,
    'feed_urls': lambda v: all(isinstance(u, str) and validate_feed_url(u) is None for u in v),
    'feed_interval_hours': lambda v: FEED_INTERVAL_MIN <= v <= FEED_INTERVAL_MAX,
    'feed_last_update': lambda v: v >= 0,
    'sig_paths': lambda v: all(isinstance(x, str) and x for x in v),
    'sig_home_net': lambda v: validate_home_net(v) is None,
    'sig_disabled': lambda v: len(v) <= 200_000 and all(isinstance(x, str) and ':' in x for x in v),
    'sig_enabled': lambda v: len(v) <= 200_000 and all(isinstance(x, str) and ':' in x for x in v),
    'sig_level': lambda v: v in ('balanced', 'essential', 'all'),
    'sig_et_last': lambda v: v >= 0,
    'sig_et_url': lambda v: v == '' or validate_feed_url(v) is None,
    'wifi_interval': lambda v: WIFI_INTERVAL_MIN <= v <= WIFI_INTERVAL_MAX,
    'wifi_plan': validate_plan,
    'wifi_layout': lambda v: v in ('auto', 'plan'),
    'wifi_env': lambda v: v in ('home', 'open', 'office'),
    'wifi_cal': lambda v: -40.0 <= v <= 40.0,
}

# Never restore a state that could drop traffic without an explicit choice in this session.
# Nothing scans until the user starts it in this session, so background Wi-Fi monitoring is not resumed either.
FORCED_ON_LOAD = {'dry_run': True, 'wifi_monitor': False}


def _valid(key: str, value: Any) -> bool:
    if key not in DEFAULTS:
        return False
    default = DEFAULTS[key]
    if type(value) is not type(default):    # rejects bool for int and vice versa
        return False
    check = VALIDATORS.get(key)
    return check is None or bool(check(value))


class Settings:
    def __init__(self, path: Optional[Path] = SETTINGS_PATH, autosave: bool = True):
        self.path = Path(path) if path else None
        self.autosave = autosave
        self.last_error = ''
        self._values = dict(DEFAULTS)
        self.load()

    def load(self):
        self._values = dict(DEFAULTS)
        if self.path and self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding='utf-8'))
                if isinstance(data, dict):
                    for key, value in data.items():
                        if _valid(key, value):
                            self._values[key] = value
            except (OSError, ValueError) as exc:
                self.last_error = f'Could not read settings: {exc}'
        if self._values['bpf'] == LEGACY_DEFAULT_BPF:
            self._values['bpf'] = DEFAULT_BPF       # the old default did not capture ARP
        if self._values['ips_filter'].strip() == LEGACY_WINDIVERT_FILTER:
            self._values['ips_filter'] = WINDIVERT_DEFAULT_FILTER   # the old default was not valid WinDivert
        self._values.update(FORCED_ON_LOAD)

    def get(self, key: str):
        return self._values[key]

    def set(self, key: str, value) -> bool:
        """Store a valid value (and save if autosave). Returns False if the value was rejected."""
        if not _valid(key, value):
            return False
        if self._values.get(key) != value:
            self._values[key] = value
            if self.autosave:
                self.save()
        return True

    def as_dict(self) -> dict:
        return dict(self._values)

    def save(self) -> bool:
        if not self.path:
            return True
        tmp = self.path.with_name(self.path.name + '.tmp')
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(self._values, indent=2, sort_keys=True), encoding='utf-8')
            os.replace(tmp, self.path)
            restrict_to_owner(self.path)        # Windows: ACL on ~/.netsentinel; elsewhere: mode 0600
            self.last_error = ''
            return True
        except OSError as exc:
            self.last_error = f'Could not save settings: {exc}'
            return False
