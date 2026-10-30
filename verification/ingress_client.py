"""Client address for admission only; never an identity or authorization claim."""
import ipaddress

HEADER = 'HTTP_X_OPENID_CLIENT_IP'


def address(value):
    if not isinstance(value, str) or not 0 < len(value) <= 45 or '%' in value:
        raise ValueError('invalid client address')
    parsed = ipaddress.ip_address(value)
    if isinstance(parsed, ipaddress.IPv6Address): parsed = parsed.ipv4_mapped or parsed
    if parsed.is_unspecified or parsed.is_multicast:
        raise ValueError('invalid client address')
    return str(parsed)


def proxy_config(value, bind=None):
    if value is None:
        return None
    # This mode is only for the local nginx ingress. No CIDRs, remote proxies,
    # container bridge ranges or implicit trust of all private addresses.
    if value not in ('127.0.0.1', '::1') or (bind is not None and bind != value):
        raise ValueError('trustedProxy must match the explicit loopback listener')
    return value


class ClientAddresses:
    def __init__(self, trusted_proxy=None):
        self.proxy = proxy_config(trusted_proxy)

    def resolve(self, environ):
        peer = address(environ.get('REMOTE_ADDR'))
        if self.proxy is None:
            if HEADER in environ:
                raise ValueError('unexpected ingress header')
            return peer
        if peer != self.proxy:
            raise ValueError('unexpected ingress peer')
        # A missing/invalid value cannot silently collapse clients to loopback.
        return address(environ.get(HEADER))
