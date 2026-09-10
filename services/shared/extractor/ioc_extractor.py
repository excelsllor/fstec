import ipaddress
import re
from dataclasses import dataclass, field

from shared.extractor.patterns import (
    HASH_SHA256, HASH_MD5, HASH_SHA1, HASH_SHA384, HASH_SHA512,
    IP_OBFUSCATED, IP_OBFUSCATED_PAREN, IP_PLAIN, IPV4_CIDR, IPV6_PLAIN,
    DOMAIN_OBFUSCATED, DOMAIN_OBFUSCATED_PAREN, DOMAIN_PLAIN,
    EMAIL_PATTERN, BDU_PATTERN, CVE_PATTERN, VDB_URL_PATTERN,
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
    ".py", ".rb", ".go", ".rs", ".c", ".cpp", ".java",
    ".html", ".htm", ".css",
    ".txt", ".csv", ".dotm", ".docm", ".dot", ".pptx", ".pptm",
    ".xlsm", ".msg", ".eml", ".tar", ".gz", ".tgz", ".bz2", ".xz",
}
# .sh — легитимный ccTLD (Св. Елена); блокируем только типовые shell-скрипты
FP_SHELL_SCRIPTS = {
    "install.sh", "run.sh", "setup.sh", "configure.sh", "download.sh",
    "build.sh", "compile.sh", "test.sh", "start.sh", "make.sh",
    "deploy.sh", "init.sh", "update.sh", "clean.sh", "check.sh",
}
FP_PREFIXES = {
    "document", "content", "header", "footer", "style", "theme",
    "mail.fstec", "fstec.ru",
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
    ipv4_cidr: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    vuln_ids: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    vdb_urls: list[str] = field(default_factory=list)


def extract_iocs(text: str, tables: list | None = None) -> IoCResult:
    result = IoCResult()
    text = _normalize_dotted_whitespace(text.replace("\xa0", " "))
    seen_ips, seen_cidr4, seen_ipv6 = set(), set(), set()
    seen_domains, seen_hashes, seen_emails, seen_bdu, seen_cve, seen_urls = set(), set(), set(), set(), set(), set()

    for pat in (IP_OBFUSCATED, IP_OBFUSCATED_PAREN):
        for m in pat.finditer(text):
            ip = f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
            if _valid_ip(ip) and ip not in seen_ips:
                result.ips.append(ip)
                seen_ips.add(ip)

    for m in IPV4_CIDR.finditer(text):
        cidr = m.group(1)
        if _valid_ipv4_cidr(cidr) and cidr not in seen_cidr4:
            result.ipv4_cidr.append(cidr)
            seen_cidr4.add(cidr)

    for m in IPV6_PLAIN.finditer(text):
        ipv6 = m.group(1).lower()
        if _valid_ipv6(ipv6) and ipv6 not in seen_ipv6:
            result.ipv6.append(ipv6)
            seen_ipv6.add(ipv6)

    for m in IP_PLAIN.finditer(text):
        ip = m.group(1)
        if not _valid_ip(ip) or _is_meta_ip(ip):
            continue
        after = text[m.end(): m.end() + 12]
        port_m = re.search(r":(\d{1,5})\b", after)
        ip_entry = f"{ip}:{port_m.group(1)}" if port_m else ip
        if ip_entry not in seen_ips:
            result.ips.append(ip_entry)
            seen_ips.add(ip_entry)

    for m in DOMAIN_OBFUSCATED.finditer(text):
        if _in_url_path(text, m.start()):
            continue
        domain = _clean_domain(m.group(0).replace("[.]", "."))
        if domain and not _in_guillemets(text, m.start()) and _valid_domain(domain, obfuscated=True) and domain not in seen_domains:
            result.domains.append(domain)
            seen_domains.add(domain)

    for m in DOMAIN_OBFUSCATED_PAREN.finditer(text):
        if _in_url_path(text, m.start()):
            continue
        domain = _clean_domain(m.group(0).replace("(.)", "."))
        if domain and not _in_guillemets(text, m.start()) and _valid_domain(domain, obfuscated=True) and domain not in seen_domains:
            result.domains.append(domain)
            seen_domains.add(domain)

    for m in DOMAIN_PLAIN.finditer(text):
        if _in_guillemets(text, m.start()) or _in_url_path(text, m.start()):
            continue
        domain = _clean_domain(m.group(1))
        in_list = _in_list_line(text, m.start(), m.end())
        if domain and _valid_domain(domain, in_list_line=in_list) and domain not in seen_domains:
            result.domains.append(domain)
            seen_domains.add(domain)

    for pat in (HASH_SHA512, HASH_SHA384, HASH_SHA256, HASH_SHA1, HASH_MD5):
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

    for m in VDB_URL_PATTERN.finditer(text):
        url = m.group(0)
        if url not in seen_urls:
            result.vdb_urls.append(url)
            seen_urls.add(url)

    if tables:
        _extract_from_tables(tables, result)

    return result


def _extract_from_tables(tables, result: IoCResult):
    for table in tables:
        for row in table:
            for cell in row:
                cell = (cell or "").strip()
                if not cell:
                    continue
                seen = set()
                res = extract_iocs(cell)
                for attr in ("ips", "ipv4_cidr", "ipv6", "domains", "hashes", "emails", "vuln_ids", "cve_ids", "vdb_urls"):
                    for val in getattr(res, attr):
                        out = getattr(result, attr)
                        if val not in seen:
                            seen.add(val)
                            if val not in out:
                                out.append(val)


def _normalize_dotted_whitespace(text: str) -> str:
    """Склейка пробелов вокруг точек внутри IP/доменов: '104 .238' → '104.238'."""
    return re.sub(r"(?<=\d)\s*\.\s*(?=\d)", ".", text)


def _in_guillemets(text: str, index: int) -> bool:
    """True, если индекс внутри незакрытых «...» — имена вложений/файлов,
    а не адреса в списках блокировки."""
    if index <= 0:
        return False
    tail = text[:index]
    return tail.rfind("«") > tail.rfind("»")


def _in_url_path(text: str, index: int) -> bool:
    """True, если кандидат — фрагмент пути URL ('/0/ferr[.]um'), а не хост
    ('//host[.]tld' после двойного слэша)."""
    if index <= 1:
        return False
    return text[index - 1] == "/" and text[index - 2] != "/"


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


def _is_internal_email(email: str) -> bool:
    return email.lower() in INTERNAL_EMAILS


def _valid_domain(domain: str, obfuscated: bool = False, in_list_line: bool = False) -> bool:
    dl = domain.lower()
    if not obfuscated:
        if dl in FP_EXACT or dl in FP_DOMAINS:
            return False
        # известные сервисы (github.com и т.п.) подавляем только в сплошном тексте,
        # но НЕ когда домен — самостоятельная строка списка «на блокировку»
        if dl in COMMON_DOMAINS and not in_list_line:
            return False
    for ext in FP_EXTENSIONS:
        if dl.endswith(ext):
            return False
    if dl.endswith(".sh") and dl in FP_SHELL_SCRIPTS:
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


def _in_list_line(text: str, start: int, end: int) -> bool:
    """True, если домен — самостоятельная строка списка «на блокировку»
    (в строке нет пояснительного текста)."""
    ls = text.rfind("\n", 0, start)
    le = text.find("\n", end)
    if ls == -1:
        ls = 0
    if le == -1:
        le = len(text)
    line = text[ls:le].strip()
    without = (line[:start - ls] + line[end - ls:]).strip()
    return not re.search(r"[0-9a-zA-Zа-яё]{2,}", without, re.I)


def _valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(0 <= int(p) <= 255 for p in parts)


def _valid_ipv4_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def _valid_ipv6(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
            return True
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_meta_ip(ip: str) -> bool:
    return ip.startswith("0.") or ip.startswith("255.") or ip == "127.0.0.1"