from shared.generator.addresses import unique_addresses


class _Ioc:
    def __init__(self, ioc_type, value):
        self.ioc_type = ioc_type
        self.value = value


def test_unique_addresses_includes_ipv6_and_removes_duplicates():
    iocs = [
        _Ioc("ip", "10.0.0.1"),
        _Ioc("ip", "10.0.0.1"),
        _Ioc("ip_cidr", "10.1.0.0/16"),
        _Ioc("ipv6", "2001:db8::1"),
        _Ioc("domain", "example.com"),
        _Ioc("hash", "abc"),
        _Ioc("email", "user@example.com"),
    ]
    assert unique_addresses(iocs) == [
        "10.0.0.1", "10.1.0.0/16", "2001:db8::1", "example.com",
    ]
