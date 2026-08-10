import re

HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
HASH_SHA512 = re.compile(r"\b[a-fA-F0-9]{128}\b")
HASH_SHA384 = re.compile(r"\b[a-fA-F0-9]{96}\b")

IP_OBFUSCATED = re.compile(
    r"(\d{1,3})\[\.\](\d{1,3})\[\.\](\d{1,3})\[\.\](\d{1,3})"
)
IP_OBFUSCATED_PAREN = re.compile(
    r"(\d{1,3})\(\.\)(\d{1,3})\(\.\)(\d{1,3})\(\.\)(\d{1,3})"
)
IP_PLAIN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

DOMAIN_OBFUSCATED = re.compile(
    r"([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\[\.\][a-zA-Z0-9][a-zA-Z0-9\-]*)+)"
)
DOMAIN_OBFUSCATED_PAREN = re.compile(
    r"([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\(\.\)[a-zA-Z0-9][a-zA-Z0-9\-]*)+)"
)
DOMAIN_PLAIN = re.compile(
    r"\b((?:[a-zA-Z0-9][a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,10})\b"
)

EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

BDU_PATTERN = re.compile(r"(?:BDU|БДУ)[:\s]*\s*(\d{4}-\d{3,6})", re.IGNORECASE)
CVE_PATTERN = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)

PORT_PATTERN = re.compile(r":(\d{1,5})\b")

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
    r'(?:тематике|на\s+тему|тема)\s*[«"]([^«»"]+)[»"]',
    re.IGNORECASE,
)

SEVERITY_PATTERN = re.compile(
    r"(критическ[а-яё]+|высок[а-яё]+|средн[а-яё]+|низк[а-яё]+)",
    re.IGNORECASE,
)
