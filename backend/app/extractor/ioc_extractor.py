import re
from dataclasses import dataclass, field
from app.extractor.patterns import (
    HASH_SHA256, HASH_MD5, HASH_SHA1, HASH_SHA384, HASH_SHA512,
    IP_OBFUSCATED, IP_OBFUSCATED_PAREN, IP_PLAIN,
    DOMAIN_OBFUSCATED, DOMAIN_OBFUSCATED_PAREN, DOMAIN_PLAIN,
    EMAIL_PATTERN, BDU_PATTERN, CVE_PATTERN,
)

INTERNAL_EMAILS = {
    "cfo@fstec.ru", "cfo_otd9@fstec.ru", "info@fstec.ru",
    "post@fstec.ru", "dir@fstec.ru",
}

FP_DOMAINS = {"r2.dev", "onion", "bin", "forum"}
FP_EXTENSIONS = {
    ".msi", ".exe", ".rar", ".zip", ".7z", ".cab", ".jpg", ".png",
    ".doc", ".docx", ".pdf", ".scr", ".bat", ".cmd", ".php",
    ".qxd", ".bin", ".dat", ".xml", ".xls", ".xlsx", ".odt",
    ".rtf", ".lnk", ".js", ".json", ".bz", ".vbs", ".ps1",
    ".htaccess", ".ini", ".cfg", ".conf", ".sql", ".db",
    ".gif", ".bmp", ".tif", ".tiff", ".svg", ".ico",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".py", ".sh", ".rb", ".go", ".rs", ".c", ".cpp", ".java",
    ".html", ".htm", ".css",
}
FP_PREFIXES = {
    "document", "content", "header", "footer", "style", "theme",
    "captcha.yandex", "mail.fstec", "fstec.ru",
}
COMMON_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "drive.google.com",
    "cloud.mail.ru", "api.telegram.org", "www.dropbox.com",
    "www.microsoft.com", "update.microsoft.com",
}

FP_EXACT = {
    "dr.web", "next.js", "1.ru", "1.com", "2.com", "3.com",
    "cf.js", "node.js", "react.js",
}


@dataclass
class IoCResult:
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    vuln_ids: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)


def extract_iocs(text: str, tables: list | None = None) -> IoCResult:
    result = IoCResult()
    seen_ips = set()
    text = text.replace("\xa0", " ")
    seen_domains = set()
    seen_hashes = set()
    seen_emails = set()
    seen_bdu = set()
    seen_cve = set()

    for pat in [IP_OBFUSCATED, IP_OBFUSCATED_PAREN]:
        for m in pat.finditer(text):
            ip = f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
            if _valid_ip(ip) and ip not in seen_ips:
                result.ips.append(ip)
                seen_ips.add(ip)

    for m in IP_PLAIN.finditer(text):
        ip = m.group(1)
        if not _valid_ip(ip) or _is_meta_ip(ip):
            continue
        context = text[max(0, m.start() - 2) : min(len(text), m.end() + 8)]
        port_m = re.search(r":(\d{1,5})\b", context[len(ip) :])
        ip_entry = f"{ip}:{port_m.group(1)}" if port_m else ip
        if ip_entry not in seen_ips:
            result.ips.append(ip_entry)
            seen_ips.add(ip_entry)

    for m in DOMAIN_OBFUSCATED.finditer(text):
        raw = m.group(0)
        domain = raw.replace("[.]", ".")
        domain = _clean_domain(domain)
        if domain and _valid_domain(domain, obfuscated=True) and domain not in seen_domains:
            result.domains.append(domain)
            seen_domains.add(domain)

    for m in DOMAIN_OBFUSCATED_PAREN.finditer(text):
        raw = m.group(0)
        domain = raw.replace("(.)", ".")
        domain = _clean_domain(domain)
        if domain and _valid_domain(domain, obfuscated=True) and domain not in seen_domains:
            result.domains.append(domain)
            seen_domains.add(domain)

    for m in DOMAIN_PLAIN.finditer(text):
        domain = _clean_domain(m.group(1))
        if domain and _valid_domain(domain) and domain not in seen_domains:
            result.domains.append(domain)
            seen_domains.add(domain)

    for pat in [HASH_SHA512, HASH_SHA384, HASH_SHA256, HASH_SHA1, HASH_MD5]:
        for m in pat.finditer(text):
            h = m.group(0).lower()
            if h not in seen_hashes:
                result.hashes.append(h)
                seen_hashes.add(h)

    for m in EMAIL_PATTERN.finditer(text):
        email = m.group(0).lower()
        if email not in seen_emails and not _is_internal_email(email):
            result.emails.append(email)
            seen_emails.add(email)

    for m in BDU_PATTERN.finditer(text):
        bdu = f"BDU:{m.group(1)}"
        if bdu not in seen_bdu:
            result.vuln_ids.append(bdu)
            seen_bdu.add(bdu)

    for m in CVE_PATTERN.finditer(text):
        cve = m.group(1).upper()
        if cve not in seen_cve:
            result.cve_ids.append(cve)
            seen_cve.add(cve)

    if tables:
        _extract_from_tables(tables, result, seen_ips, seen_domains, seen_hashes, seen_bdu, seen_cve)

    return result


def _clean_domain(domain: str) -> str:
    domain = domain.strip(".")
    domain = re.sub(r"^https?://", "", domain, flags=re.IGNORECASE)
    domain = re.sub(r"^hxxps?://", "", domain, flags=re.IGNORECASE)
    domain = re.sub(r"^hxxps?\[\:\]//", "", domain, flags=re.IGNORECASE)
    domain = re.sub(r"^hxxps?\(\.\)//", "", domain, flags=re.IGNORECASE)
    domain = re.sub(r"^\[/\]//", "", domain)
    domain = re.sub(r"^\[\:\]//", "", domain)
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    domain = domain.strip(".")
    return domain


def _extract_from_tables(tables, result, seen_ips, seen_domains, seen_hashes, seen_bdu, seen_cve):
    for table in tables:
        for row in table:
            for cell in row:
                cell = (cell or "").strip()
                if not cell:
                    continue

                for pat in [IP_OBFUSCATED, IP_OBFUSCATED_PAREN]:
                    for m in pat.finditer(cell):
                        ip = f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
                        if _valid_ip(ip) and ip not in seen_ips:
                            result.ips.append(ip)
                            seen_ips.add(ip)

                for m in IP_PLAIN.finditer(cell):
                    ip = m.group(1)
                    if _valid_ip(ip) and not _is_meta_ip(ip) and ip not in seen_ips:
                        result.ips.append(ip)
                        seen_ips.add(ip)

                for m in DOMAIN_OBFUSCATED.finditer(cell):
                    raw = m.group(0)
                    domain = _clean_domain(raw.replace("[.]", "."))
                    if domain and _valid_domain(domain, obfuscated=True) and domain not in seen_domains:
                        result.domains.append(domain)
                        seen_domains.add(domain)

                for m in DOMAIN_OBFUSCATED_PAREN.finditer(cell):
                    raw = m.group(0)
                    domain = _clean_domain(raw.replace("(.)", "."))
                    if domain and _valid_domain(domain, obfuscated=True) and domain not in seen_domains:
                        result.domains.append(domain)
                        seen_domains.add(domain)

                for m in DOMAIN_PLAIN.finditer(cell):
                    domain = _clean_domain(m.group(1))
                    if domain and _valid_domain(domain) and domain not in seen_domains:
                        result.domains.append(domain)
                        seen_domains.add(domain)

                for pat in [HASH_SHA512, HASH_SHA384, HASH_SHA256, HASH_SHA1, HASH_MD5]:
                    for m in pat.finditer(cell):
                        h = m.group(0).lower()
                        if h not in seen_hashes:
                            result.hashes.append(h)
                            seen_hashes.add(h)

                for m in EMAIL_PATTERN.finditer(cell):
                    email = m.group(0).lower()
                    if email not in seen_emails and not _is_internal_email(email):
                        result.emails.append(email)
                        seen_emails.add(email)

                for m in BDU_PATTERN.finditer(cell):
                    bdu = f"BDU:{m.group(1)}"
                    if bdu not in seen_bdu:
                        result.vuln_ids.append(bdu)
                        seen_bdu.add(bdu)

                for m in CVE_PATTERN.finditer(cell):
                    cve = m.group(1).upper()
                    if cve not in seen_cve:
                        result.cve_ids.append(cve)
                        seen_cve.add(cve)


def _is_internal_email(email: str) -> bool:
    return email.lower() in INTERNAL_EMAILS


def _valid_domain(domain: str, obfuscated: bool = False) -> bool:
    dl = domain.lower()
    if not obfuscated:
        if dl in FP_EXACT:
            return False
        if dl in FP_DOMAINS:
            return False
        if dl in COMMON_DOMAINS:
            return False
    for ext in FP_EXTENSIONS:
        if dl.endswith(ext):
            return False
    for prefix in FP_PREFIXES:
        if dl.startswith(prefix) or dl == prefix:
            return False
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    if len(tld) < 2 or len(tld) > 10:
        return False
    if len(domain) < 4:
        return False
    if re.match(r"^\d+\.\d+", domain):
        return False
    if re.match(r"^[A-Z][a-z]+\.[a-z]{2,3}$", domain) and parts[0] in {"Dr", "Next", "Node", "React", "Cf"}:
        return False
    return True


def _valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(0 <= int(p) <= 255 for p in parts)


def _is_meta_ip(ip: str) -> bool:
    return ip.startswith("0.") or ip.startswith("255.") or ip == "127.0.0.1"
