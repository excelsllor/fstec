ADDRESS_IOC_TYPES = frozenset({"ip", "ip_cidr", "ipv6", "domain"})


def unique_addresses(iocs) -> list[str]:
    return sorted({
        str(value).strip()
        for ioc in (iocs or [])
        for value in [getattr(ioc, "value", "")]
        if getattr(ioc, "ioc_type", "") in ADDRESS_IOC_TYPES and str(value).strip()
    })
