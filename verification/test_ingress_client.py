import unittest
from ingress_client import ClientAddresses, HEADER, address, proxy_config


class ClientAddressTests(unittest.TestCase):
    def test_direct_mode_uses_only_the_transport_peer(self):
        resolver = ClientAddresses()
        self.assertEqual('192.0.2.8', resolver.resolve({'REMOTE_ADDR':'192.0.2.8'}))
        with self.assertRaises(ValueError):
            resolver.resolve({'REMOTE_ADDR':'192.0.2.8', HEADER:'198.51.100.9'})

    def test_proxy_mode_requires_the_exact_peer_and_a_client_address(self):
        resolver = ClientAddresses('127.0.0.1')
        self.assertEqual('198.51.100.9', resolver.resolve({'REMOTE_ADDR':'127.0.0.1', HEADER:'198.51.100.9'}))
        for env in ({'REMOTE_ADDR':'127.0.0.1'},
                    {'REMOTE_ADDR':'127.0.0.2',HEADER:'198.51.100.9'},
                    {'REMOTE_ADDR':'10.0.0.1',HEADER:'198.51.100.9'},
                    {'REMOTE_ADDR':'198.51.100.9',HEADER:'198.51.100.9'}):
            with self.subTest(env=env), self.assertRaises(ValueError): resolver.resolve(env)

    def test_invalid_or_ambiguous_addresses_are_rejected(self):
        for value in (None, '', 1, True, [], 'unknown', '192.0.2.8, 198.51.100.9',
                      '192.0.2.8:443', '[2001:db8::8]', 'fe80::1%eth0',
                      ' 192.0.2.8', '192.0.2.8\n', '192.000.2.8', '0.0.0.0', '::',
                      '224.0.0.1', 'ff02::1', '::ffff:0.0.0.0', '::ffff:224.0.0.1', 'a'*46):
            with self.subTest(value=value), self.assertRaises(ValueError): address(value)

    def test_equivalent_ip_spellings_cannot_create_extra_rate_buckets(self):
        self.assertEqual(address('192.0.2.8'), address('::ffff:192.0.2.8'))
        self.assertEqual(address('2001:db8::8'), address('2001:0db8:0:0:0:0:0:8'))

    def test_proxy_configuration_never_trusts_a_range_or_remote_listener(self):
        self.assertIsNone(proxy_config(None, '10.0.0.1'))
        for ip in ('127.0.0.1','::1'):
            self.assertEqual(ip, proxy_config(ip,ip))
        for value,bind in (('127.0.0.1','10.0.0.1'), ('127.0.0.1','0.0.0.0'),
                           ('127.0.0.0/8','127.0.0.1'), ('10.0.0.1','10.0.0.1'),
                           ('127.0.0.2','127.0.0.2'), ('localhost','127.0.0.1'),
                           (True,'127.0.0.1'), (['127.0.0.1'],'127.0.0.1')):
            with self.subTest(value=value,bind=bind), self.assertRaises(ValueError): proxy_config(value,bind)

    def test_ipv6_proxy_has_its_own_explicit_peer(self):
        resolver = ClientAddresses('::1')
        self.assertEqual('2001:db8::8',resolver.resolve({'REMOTE_ADDR':'::1',HEADER:'2001:db8::8'}))
        with self.assertRaises(ValueError): resolver.resolve({'REMOTE_ADDR':'127.0.0.1',HEADER:'2001:db8::8'})


if __name__ == '__main__': unittest.main()
