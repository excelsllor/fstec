import re

HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
HASH_SHA512 = re.compile(r"\b[a-fA-F0-9]{128}\b")
HASH_SHA384 = re.compile(r"\b[a-fA-F0-9]{96}\b")

IP_OBFUSCATED = re.compile(r"(\d{1,3})\[\.\](\d{1,3})\[\.\](\d{1,3})\[\.\](\d{1,3})")
IP_OBFUSCATED_PAREN = re.compile(r"(\d{1,3})\(\.\)(\d{1,3})\(\.\)(\d{1,3})\(\.\)(\d{1,3})")

# IPv4 без CIDR-суффикса (требование ТЗ 2.3.2: CIDR выделяется отдельно).
# Хвостовой \b намеренно не ставится: в реальных списках бывает мусор после
# адреса ("203.0.113.10l", ".162l") — срезаем по (?!\d).
IP_PLAIN = re.compile(r"(?<![0-9.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!/\d)(?!\d)")
IPV4_CIDR = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")

# IPv6, включая сжатие "::", embedded IPv4 и CIDR-суффикс (ТЗ 2.3.2)
_IPV6_BODY = (
    r"(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}"
    r"|(?:[0-9a-f]{1,4}:){1,7}:"
    r"|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}"
    r"|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}"
    r"|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}"
    r"|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}"
    r"|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}"
    r"|[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})"
    r"|:(?:(?::[0-9a-f]{1,4}){1,7}|:)"
    r"|::ffff:\d{1,3}(?:\.\d{1,3}){3}"
    r"|fe80:(?::[0-9a-f]{0,4}){0,4}%[0-9a-zA-Z]+"
    r"|(?:[0-9a-f]{1,4}:){1,4}:\d{1,3}(?:\.\d{1,3}){3}"
)
IPV6_PLAIN = re.compile(r"\b((?:" + _IPV6_BODY + r")(?:/\d{1,3})?)\b", re.IGNORECASE)

DOMAIN_OBFUSCATED = re.compile(
    r"([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\[\.\][a-zA-Z0-9][a-zA-Z0-9\-]*)+)"
)
DOMAIN_OBFUSCATED_PAREN = re.compile(
    r"([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\(\.\)[a-zA-Z0-9][a-zA-Z0-9\-]*)+)"
)
DOMAIN_PLAIN = re.compile(r"\b((?:[a-zA-Z0-9][a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,10})\b")

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

BDU_PATTERN = re.compile(r"(?:BDU|БДУ)[:\s]*\s*(\d{4}-\d{3,6})", re.IGNORECASE)
CVE_PATTERN = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)

VDB_URL_PATTERN = re.compile(
    r"(?:https?://)?(?:www\.)?"
    r"(nvd\.nist\.gov|cve\.mitre\.org|bdu\.fstec\.ru|nvd\.nist\.gov/vuln/detail(?:/[A-Z\-0-9]+)?|bdu\.fstec\.ru/vul(?:/?\d+)?)",
    re.IGNORECASE,
)

PORT_PATTERN = re.compile(r":(\d{1,5})\b")

# NER: контакты (ТЗ 2.3.2)
PHONE_PATTERN = re.compile(
    r"(?:\+7\s?[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}"
    r"|8\s?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2})"
)
DEADLINE_PATTERN = re.compile(
    r"(?:в\s+течение|не\s+позднее|в\s+срок|до\s+)\s*"
    r"(?:(\d{1,3})\s+(?:календарн[а-яё]+\s+)?(?:день|дня|дней|недел[а-яё]+|месяц[а-яё]+|месяцев|дней))"
    r"|до\s+(\d{1,2})[./](\d{1,2})[./](\d{4})",
    re.IGNORECASE,
)

KNOWN_GROUPS = [
    "Rare Werewolf", "Cloud Werewolf", "Fluffy Wolf", "Fairy Wolf",
    "Watch Wolf", "Rainbow Hyena", "Vortex Werewolf", "Sticky Werewolf",
    "Versatile Werewolf", "Hoody Hyena", "Forbidden Hyena", "Geo Likho",
    "Paper Werewolf", "Shedding Zmiy", "Iridescent Hyena",
    "UAT-8302", "UAT-5776",
    "Vengeful Wolf", "Clubfoot Wolf", "Core Werewolf",
    "Cavalry Werewolf", "Larcenous Werewolf", "Fairy Werewolf",
    "King Werewolf", "Silent Werewolf", "Insolent Hyena",
]

MALWARE_NAMES = [
    "Cobalt Strike", "Agent Tesla", "FormBook", "NanoCore",
    "AsyncRAT", "RedLine", "Raccoon", "Vidar", "Lumma",
    "Hta", "hta",
]

ARCHIVE_NAMES = re.compile(
    r'(?:архив\s+(?:с\s+)?(?:наименованием|названием)\s*[«"]([^«»"]+)[»"])',
    re.IGNORECASE,
)

EXE_NAMES = re.compile(
    r'(?:исполняем[а-яё]+\s+файл\s+(?:с\s+)?(?:наименованием|названием)\s*[«"]([^«»"]+)[»"])',
    re.IGNORECASE,
)

THEME_PATTERN = re.compile(
    r'(?:на\s+тему|тематик\w*|тем\w*)\s*[«"]([^«»"]+)[»"]',
    re.IGNORECASE,
)

SEVERITY_PATTERN = re.compile(
    r"(критическ[а-яё]+|высок[а-яё]+|средн[а-яё]+|низк[а-яё]+)",
    re.IGNORECASE,
)