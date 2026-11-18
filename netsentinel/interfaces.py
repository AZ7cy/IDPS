"""List capture interfaces and pick a connected one."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Interface:
    name: str           # value passed to the sniffer
    description: str = ''
    address: str = ''

    @property
    def label(self) -> str:
        extra = ', '.join(x for x in (self.description, self.address) if x and x != self.name)
        return f'{self.name} ({extra})' if extra else self.name


def _from_scapy() -> list[Interface]:
    try:
        from scapy.all import conf
        items = list(conf.ifaces.values())
    except Exception:
        return []
    found = []
    for iface in items:
        name = str(getattr(iface, 'name', '') or '')
        if not name:
            continue
        ip = getattr(iface, 'ip', '') or ''
        found.append(Interface(name, str(getattr(iface, 'description', '') or ''), str(ip)))
    return found


def _from_psutil() -> list[Interface]:
    try:
        import psutil
        addrs = psutil.net_if_addrs()
    except Exception:
        return []
    found = []
    for name, values in addrs.items():
        ipv4 = next((a.address for a in values if a.family == socket.AF_INET), '')
        found.append(Interface(name, '', ipv4))
    return found


def list_interfaces() -> list[Interface]:
    """Interfaces sorted by name; scapy first, psutil as fallback."""
    found = _from_scapy() or _from_psutil()
    unique = {i.name: i for i in found}
    return sorted(unique.values(), key=lambda i: i.name.lower())


# ----------------------------------------------------------------------------
# Automatic choice
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class Candidate:
    name: str
    address: str = ''
    up: Optional[bool] = None       # None when the link state is unknown
    loopback: bool = False
    route_metric: Optional[int] = None   # metric of this interface's default route, if it has one


def _usable_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast)


def choose_interface(candidates: list[Candidate]) -> Optional[str]:
    """The connected interface most likely to carry this computer's traffic.

    Interfaces that are down, loopback, or have no routable address are skipped. Among the rest, one
    with a default route wins (lowest metric first); otherwise the first by name. Windows keeps the
    default route of an unplugged adapter, so the link state matters more than the metric.
    """
    usable = [c for c in candidates if c.up is not False and not c.loopback and _usable_address(c.address)]
    if not usable:
        return None
    usable.sort(key=lambda c: (c.route_metric is None, c.route_metric or 0, c.name.lower()))
    return usable[0].name


def _candidates() -> list[Candidate]:
    try:
        from scapy.all import conf
        ifaces = list(conf.ifaces.values())
    except Exception:
        ifaces = []
    try:
        import psutil
        stats = psutil.net_if_stats()
    except Exception:
        stats = {}
    metrics: dict[str, int] = {}
    try:
        from scapy.all import conf
        for net, mask, gateway, iface, _addr, metric in conf.route.routes:
            if net == 0 and mask == 0 and gateway not in ('0.0.0.0', ''):
                key = str(getattr(iface, 'network_name', iface))
                metrics[key] = min(metric, metrics.get(key, metric))
    except Exception:
        pass
    found = []
    for iface in ifaces:
        name = str(getattr(iface, 'name', '') or '')
        if not name:
            continue
        flags = str(getattr(iface, 'flags', '') or '')
        up: Optional[bool] = None
        if name in stats:
            up = bool(stats[name].isup)
        if 'DISCONNECTED' in flags:
            up = False
        network_name = str(getattr(iface, 'network_name', '') or '')
        metric = metrics.get(network_name, metrics.get(name))
        found.append(Candidate(name, str(getattr(iface, 'ip', '') or ''), up, 'LOOPBACK' in flags, metric))
    if not found:                       # scapy unavailable: psutil only
        try:
            import psutil
            for name, values in psutil.net_if_addrs().items():
                ipv4 = next((a.address for a in values if a.family == socket.AF_INET), '')
                st = stats.get(name)
                found.append(Candidate(name, ipv4, bool(st.isup) if st else None, name.lower().startswith('lo')))
        except Exception:
            pass
    return found


def auto_interface() -> Optional[str]:
    """Name of a connected interface to capture on, or None to leave the choice to scapy."""
    try:
        return choose_interface(_candidates())
    except Exception:
        return None


def default_gateway() -> Optional[str]:
    """IPv4 gateway of the interface live capture would use, or None."""
    try:
        from scapy.all import conf
        chosen = auto_interface()
        fallback = None
        for net, mask, gateway, iface, _addr, _metric in conf.route.routes:
            if net != 0 or mask != 0 or gateway in ('0.0.0.0', ''):
                continue
            names = {str(iface), str(getattr(iface, 'name', '')), str(getattr(iface, 'network_name', ''))}
            if chosen and chosen in names:
                return gateway
            fallback = fallback or gateway
        return fallback
    except Exception:
        return None
