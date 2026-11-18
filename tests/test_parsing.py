import pytest

pytest.importorskip('scapy')
pytestmark = pytest.mark.needs_scapy

from scapy.layers.dns import DNS, DNSQR  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6  # noqa: E402

from netsentinel.models import Packet  # noqa: E402
from netsentinel.parsing import parse_raw, scapy_packet  # noqa: E402


def parsed(pkt) -> Packet:
    result = scapy_packet(pkt)
    assert result is not None
    return result


def raw(data: bytes, source='ips') -> Packet:
    result = parse_raw(data, source)
    assert result is not None
    return result


def test_tcp_http_payload():
    p = parsed(IP(src='1.1.1.1', dst='2.2.2.2') / TCP(sport=4000, dport=80, flags='PA') / b'GET /x HTTP/1.1\r\n\r\n')
    assert (p.protocol, p.src_port, p.dst_port, p.flags) == ('TCP', 4000, 80, 'PA')
    assert p.payload.startswith('GET /x')


def test_non_http_tcp_payload_not_kept():
    assert parsed(IP() / TCP(dport=443, flags='PA') / b'secret').payload == ''


def test_dns_over_udp_and_tcp():
    udp = parsed(IP(dst='8.8.8.8') / UDP(sport=5000, dport=53) / DNS(rd=1, qd=DNSQR(qname='abc.example.com')))
    assert udp.payload == 'abc.example.com'
    body = bytes(DNS(rd=1, qd=DNSQR(qname='tcp.example.com')))
    tcp = parsed(IP(dst='8.8.8.8') / TCP(dport=53, flags='PA') / (len(body).to_bytes(2, 'big') + body))
    assert tcp.payload == 'tcp.example.com'


def test_icmp_and_icmpv6():
    assert parsed(IP() / ICMP()).protocol == 'ICMP'
    assert parsed(IPv6(src='2001:db8::1', dst='2001:db8::2') / ICMPv6EchoRequest()).protocol == 'ICMPv6'


def test_parse_raw_and_errors():
    v4 = raw(bytes(IP(src='1.1.1.1', dst='2.2.2.2') / TCP(dport=80)))
    assert v4.dst_port == 80 and v4.source == 'ips'
    v6 = raw(bytes(IPv6(src='2001:db8::1', dst='2001:db8::2') / UDP(dport=1234)), source='x')
    assert v6.protocol == 'UDP' and v6.src_ip == '2001:db8::1' and v6.source == 'x'
    assert parse_raw(b'') is None
    assert parse_raw(b'\x00garbage') is None
    assert scapy_packet(object()) is None
