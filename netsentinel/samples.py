"""Build the sample attack recording (samples/attacks.pcap).

Run `python -m netsentinel.samples [FILE]` to regenerate it. The recording is deterministic: the same
code always writes the same packets. Each attack runs in its own time slot, so rule windows never
overlap. Addresses come from the documentation ranges (RFC 5737) and private ranges.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

START = 1_794_000_000.0        # fixed capture start time (November 2026)
SLOT = 30.0                    # seconds between attack scenarios
VICTIM = '192.168.50.10'
GATEWAY = '192.168.50.1'
ATTACKER = '198.51.100.23'
INSIDER = '192.168.50.66'
C2_SERVER = '203.0.113.66'     # listed in samples/blocklist.txt (IOC-001)
GATEWAY_MAC = '02:00:5e:50:00:01'
SPOOFER_MAC = '02:00:5e:66:66:66'
VICTIM_MAC = '02:00:5e:50:00:10'

# Rules each scenario should trigger when replayed with the default thresholds.
SCENARIOS = (
    ('baseline', 'normal HTTPS session with a full handshake', ()),
    ('port_scan', 'SYN scan of 30 ports on one host', ('NET-001',)),
    ('syn_burst', '120 SYNs to one port from one source', ('NET-002',)),
    ('syn_flood', '300 SYNs to a web server from 20 spoofed sources', ('NET-003',)),
    ('horizontal', 'SYNs to TCP/443 on 45 hosts in 3 networks', ('NET-004',)),
    ('stealth', 'FIN, NULL and Xmas probes', ('NET-005',)),
    ('udp_scan', 'UDP datagrams to 30 ports', ('NET-006',)),
    ('icmp_flood', '300 ICMP echo requests in 4 seconds', ('ICMP-001',)),
    ('brute_force', '20 SSH connection attempts', ('AUTH-001',)),
    ('arp_spoof', 'a second MAC address claims the gateway IP', ('ARP-001',)),
    ('web_attack', 'path traversal and sqlmap requests over plain HTTP', ('WEB-001',)),
    ('dns_tunnel', 'DNS queries for 12 long random names', ('DNS-001',)),
    ('tls_dga', 'TLS handshakes to 12 long random server names', ('TLS-001',)),
    ('c2_beacon', 'connections to a blocklisted address (load samples/blocklist.txt)', ('IOC-001',)),
    ('signature', 'request matched by samples/demo.rules (load it as a signature file)', ('SIG-001',)),
)
DEFAULT_RULES = sorted({r for _, _, rules in SCENARIOS for r in rules} - {'IOC-001', 'SIG-001'})


def client_hello(server_name: str) -> bytes:
    """A minimal TLS 1.2 ClientHello carrying `server_name` in the SNI extension."""
    name = server_name.encode('ascii')
    sni = b'\x00' + len(name).to_bytes(2, 'big') + name
    sni_list = len(sni).to_bytes(2, 'big') + sni
    extension = b'\x00\x00' + len(sni_list).to_bytes(2, 'big') + sni_list
    body = (b'\x03\x03' + bytes(32) + b'\x00' + b'\x00\x02\xc0\x2f' + b'\x01\x00'
            + len(extension).to_bytes(2, 'big') + extension)
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake


def _random_label(rnd: random.Random, length: int) -> str:
    return ''.join(rnd.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=length))


def build_packets() -> list:
    """All sample packets as scapy objects with capture times set."""
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw

    rnd = random.Random(20261118)
    packets = []

    def add(t, pkt, src_mac='02:00:5e:00:00:aa', dst_mac=VICTIM_MAC):
        frame = pkt if pkt.haslayer(Ether) else Ether(src=src_mac, dst=dst_mac) / pkt
        frame.time = t
        packets.append(frame)

    def spread(start, count, seconds):
        step = seconds / max(1, count)
        return (start + i * step for i in range(count))

    for slot, (name, _desc, _rules) in enumerate(SCENARIOS):
        t0 = START + slot * SLOT
        if name == 'baseline':
            for i, t in enumerate(spread(t0, 5, 5)):
                sport = 50000 + i
                add(t, IP(src=VICTIM, dst='93.184.215.14') / TCP(sport=sport, dport=443, flags='S'))
                add(t + 0.02, IP(src='93.184.215.14', dst=VICTIM) / TCP(sport=443, dport=sport, flags='SA'))
                add(t + 0.03, IP(src=VICTIM, dst='93.184.215.14') / TCP(sport=sport, dport=443, flags='A'))
                add(t + 0.04, IP(src=VICTIM, dst='93.184.215.14') / TCP(sport=sport, dport=443, flags='PA')
                    / Raw(client_hello('www.example.com')))
        elif name == 'port_scan':
            for port, t in zip(rnd.sample(range(20, 1024), 30), spread(t0, 30, 5)):
                add(t, IP(src=ATTACKER, dst=VICTIM) / TCP(sport=61000, dport=port, flags='S'))
        elif name == 'syn_burst':
            for i, t in enumerate(spread(t0, 120, 3)):
                add(t, IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000 + i, dport=8443, flags='S'))
        elif name == 'syn_flood':
            sources = [f'198.18.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}' for _ in range(20)]
            for i, t in enumerate(spread(t0, 300, 4)):
                add(t, IP(src=sources[i % 20], dst=VICTIM) / TCP(sport=rnd.randint(1024, 65535), dport=80,
                                                                flags='S'))
        elif name == 'horizontal':
            hosts = [f'192.168.{net}.{x}' for net in (50, 51, 52) for x in range(100, 115)]
            for host, t in zip(hosts, spread(t0, len(hosts), 10)):
                add(t, IP(src=INSIDER, dst=host) / TCP(sport=52000, dport=443, flags='S'))
        elif name == 'stealth':
            for flags, t in zip(['F', '', 'FPU'] * 4, spread(t0, 12, 6)):
                add(t, IP(src=ATTACKER, dst=VICTIM) / TCP(sport=62000, dport=rnd.randint(1, 1024), flags=flags))
        elif name == 'udp_scan':
            for port, t in zip(rnd.sample(range(1, 1024), 30), spread(t0, 30, 5)):
                add(t, IP(src=ATTACKER, dst=VICTIM) / UDP(sport=41000, dport=port))
        elif name == 'icmp_flood':
            for i, t in enumerate(spread(t0, 300, 4)):
                add(t, IP(src=ATTACKER, dst=VICTIM) / ICMP(id=7, seq=i) / Raw(bytes(56)))
        elif name == 'brute_force':
            for i, t in enumerate(spread(t0, 20, 15)):
                add(t, IP(src=ATTACKER, dst=VICTIM) / TCP(sport=45000 + i * 7, dport=22, flags='S'))
        elif name == 'arp_spoof':
            add(t0, Ether(src=GATEWAY_MAC, dst=VICTIM_MAC) / ARP(op=2, psrc=GATEWAY, hwsrc=GATEWAY_MAC,
                                                                   pdst=VICTIM, hwdst=VICTIM_MAC))
            add(t0 + 2, Ether(src=SPOOFER_MAC, dst=VICTIM_MAC) / ARP(op=2, psrc=GATEWAY, hwsrc=SPOOFER_MAC,
                                                                       pdst=VICTIM, hwdst=VICTIM_MAC))
        elif name == 'web_attack':
            requests = (b'GET /download.php?file=../../../../etc/passwd HTTP/1.1\r\nHost: shop.example\r\n\r\n',
                        b'GET /item?id=1 HTTP/1.1\r\nHost: shop.example\r\nUser-Agent: sqlmap/1.8\r\n\r\n')
            for i, (payload, t) in enumerate(zip(requests, spread(t0, 2, 4))):
                add(t, IP(src=ATTACKER, dst=VICTIM) / TCP(sport=53000 + i, dport=80, flags='PA') / Raw(payload))
        elif name == 'dns_tunnel':
            for t in spread(t0, 12, 20):
                qname = f'{_random_label(rnd, 50)}.tunnel.example'
                add(t, IP(src=VICTIM, dst='192.168.50.53') / UDP(sport=rnd.randint(40000, 60000), dport=53)
                    / DNS(rd=1, qd=DNSQR(qname=qname)))
        elif name == 'tls_dga':
            for i, t in enumerate(spread(t0, 12, 20)):
                sni = f'{_random_label(rnd, 48)}.example.net'
                add(t, IP(src=VICTIM, dst='203.0.113.80') / TCP(sport=55000 + i, dport=443, flags='PA')
                    / Raw(client_hello(sni)))
        elif name == 'c2_beacon':
            for i, t in enumerate(spread(t0, 3, 9)):
                add(t, IP(src=VICTIM, dst=C2_SERVER) / TCP(sport=56000 + i, dport=8080, flags='S'))
        elif name == 'signature':
            add(t0, IP(src=ATTACKER, dst=VICTIM) / TCP(sport=57000, dport=80, flags='PA')
                / Raw(b'GET /netsentinel-demo/admin.php HTTP/1.1\r\nHost: shop.example\r\n\r\n'))
    packets.sort(key=lambda p: float(p.time))
    return packets


DEMO_RULES = ('# Demo rule for samples/attacks.pcap. Load it on the Signatures tab or with --rules.\n'
              'alert http any any -> $HOME_NET any (msg:"NetSentinel demo: admin page probe"; '
              'flow:to_server; http.uri; content:"/netsentinel-demo/admin.php"; classtype:web-application-attack; '
              'sid:9000001; rev:1;)\n')
DEMO_BLOCKLIST = (f'# Demo blocklist for samples/attacks.pcap. Import it with File > Import IP/CIDR blocklist.\n'
                  f'{C2_SERVER} ; demo command-and-control server\n')


def write_samples(folder: Path) -> Path:
    """Write attacks.pcap, demo.rules and blocklist.txt into `folder`. Returns the PCAP path."""
    from scapy.utils import wrpcap
    folder.mkdir(parents=True, exist_ok=True)
    pcap = folder / 'attacks.pcap'
    wrpcap(str(pcap), build_packets())
    (folder / 'demo.rules').write_text(DEMO_RULES, encoding='utf-8')
    (folder / 'blocklist.txt').write_text(DEMO_BLOCKLIST, encoding='utf-8')
    return pcap


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    folder = Path(args[0]) if args else Path(__file__).resolve().parents[1] / 'samples'
    pcap = write_samples(folder)
    print(f'Wrote {pcap} and the demo rule and blocklist files.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
