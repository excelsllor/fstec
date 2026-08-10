from app.models import Letter, IoC


def export_emails(letter: Letter, iocs: list[IoC]) -> str:
    emails = sorted({i.value for i in iocs if i.ioc_type == "email"})
    if not emails:
        return ""
    lines = ["Адреса электронной почты для блокировки:"]
    lines.extend(emails)
    return "\n".join(lines) + "\n"


def export_ips(letter: Letter, iocs: list[IoC]) -> str:
    ips = sorted({i.value.split(":")[0] for i in iocs if i.ioc_type == "ip"})
    if not ips:
        return ""
    lines = ["Сетевые индикаторы компрометации"]
    lines.extend(ips)
    return "\n".join(lines) + "\n"


def export_domains(letter: Letter, iocs: list[IoC]) -> str:
    domains = sorted({i.value for i in iocs if i.ioc_type == "domain"})
    if not domains:
        return ""
    lines = ["Обеспечить на уровне сетевых средств защиты информации ограничение обращений к адресам:"]
    lines.extend(domains)
    return "\n".join(lines) + "\n"


def export_all_iocs(letter: Letter, iocs: list[IoC]) -> str:
    lines = []

    ips = sorted({i.value.split(":")[0] for i in iocs if i.ioc_type == "ip"})
    if ips:
        lines.append("Сетевые индикаторы компрометации")
        lines.extend(ips)
        lines.append("")

    domains = sorted({i.value for i in iocs if i.ioc_type == "domain"})
    if domains:
        lines.append("Обеспечить на уровне сетевых средств защиты информации ограничение обращений к адресам:")
        lines.extend(domains)
        lines.append("")

    hashes = sorted({i.value for i in iocs if i.ioc_type == "hash"})
    if hashes:
        lines.append("Файловые индикаторы компрометации (хэши):")
        lines.extend(hashes)
        lines.append("")

    emails = sorted({i.value for i in iocs if i.ioc_type == "email"})
    if emails:
        lines.append("Адреса электронной почты для блокировки:")
        lines.extend(emails)
        lines.append("")

    bdu = sorted({i.value for i in iocs if i.ioc_type == "bdu"})
    if bdu:
        lines.append("Идентификаторы уязвимостей (BDU):")
        lines.extend(bdu)
        lines.append("")

    cve = sorted({i.value for i in iocs if i.ioc_type == "cve"})
    if cve:
        lines.append("Идентификаторы уязвимостей (CVE):")
        lines.extend(cve)
        lines.append("")

    return "\n".join(lines) + "\n" if lines else ""


EXPORT_TYPES = {
    "emails": export_emails,
    "ip_addresses": export_ips,
    "domains": export_domains,
    "ioc_indicators": export_all_iocs,
}

EXPORT_FILENAMES = {
    "emails": "emails.txt",
    "ip_addresses": "ip-адреса на блокировку.txt",
    "domains": "Адреса на блокировку.txt",
    "ioc_indicators": "ioc_indicators.txt",
}
