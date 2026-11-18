import ipaddress

import pytest

from netsentinel.addresses import PROTECTED, PrefixIndex, blocks_self, canonical_ip, is_protected, normalize_network


@pytest.mark.parametrize('raw, expected', [
    ('10.0.0.1', '10.0.0.1'),
    ('::ffff:192.0.2.1', '192.0.2.1'),
    ('fe80::1%eth0', 'fe80::1'),
    ('2001:DB8::1', '2001:db8::1'),
    ('not-an-ip', 'not-an-ip'),
])
def test_canonical_ip(raw, expected):
    assert canonical_ip(raw) == expected


@pytest.mark.parametrize('raw, expected', [
    ('203.0.113.7', '203.0.113.7/32'),
    ('203.0.113.7/24', '203.0.113.0/24'),
    ('::ffff:198.51.100.0/120', '198.51.100.0/24'),
    (' 2001:db8::1/64 ', '2001:db8::/64'),
])
def test_normalize_network(raw, expected):
    assert str(normalize_network(raw)) == expected


def test_normalize_network_rejects_garbage():
    with pytest.raises(ValueError):
        normalize_network('999.1.1.1')


def test_prefix_index_membership():
    index = PrefixIndex([ipaddress.ip_network(n) for n in ('10.0.0.0/8', '10.1.2.0/24', '192.0.2.5/32',
                                                          '2001:db8::/32')])
    ip = ipaddress.ip_address
    assert index.contains(ip('10.200.0.1'))
    assert index.contains(ip('192.0.2.5'))
    assert not index.contains(ip('192.0.2.6'))
    assert not index.contains(ip('11.0.0.0'))
    assert index.contains(ip('2001:db8::1'))
    assert not index.contains(ip('2001:db9::1'))
    assert len(index) == 4
    assert not PrefixIndex().contains(ip('1.1.1.1'))


def test_nested_intervals_use_running_max_end():
    # A short interval after a long one must not hide the long one's coverage.
    index = PrefixIndex([ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('10.0.0.0/30')])
    assert index.contains(ipaddress.ip_address('10.5.0.1'))


def test_protection():
    PROTECTED.refresh()
    assert is_protected('127.0.0.1')
    assert is_protected('224.0.0.1')          # multicast
    assert is_protected('garbage')            # unparsable is treated as protected
    assert not is_protected('203.0.113.50')
    assert blocks_self(ipaddress.ip_network('127.0.0.0/8'))
    assert blocks_self(ipaddress.ip_network('::1/128'))
    assert not blocks_self(ipaddress.ip_network('203.0.113.0/24'))
