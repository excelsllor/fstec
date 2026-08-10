import re
from dataclasses import dataclass
from app.extractor.patterns import BDU_PATTERN, CVE_PATTERN


@dataclass
class VulnInfo:
    bdu_id: str = ""
    cve_id: str = ""
    description: str = ""
    software: str = ""
    severity: str = "unknown"


def extract_vulns(text: str, tables: list | None = None) -> list[VulnInfo]:
    results = []
    seen = set()

    text = text.replace("\xa0", " ")

    for m in BDU_PATTERN.finditer(text):
        bdu = f"BDU:{m.group(1)}"
        if bdu in seen:
            continue
        seen.add(bdu)

        sentence_start = _find_sentence_start(text, m.start())
        sentence_end = _find_sentence_end(text, m.end())
        sentence = text[sentence_start:sentence_end]

        desc = sentence.strip()[:500]
        software = _extract_software(sentence, m.group(0))
        severity = _extract_severity(sentence, m.group(0))

        results.append(VulnInfo(
            bdu_id=bdu,
            description=desc,
            software=software,
            severity=severity,
        ))

    for m in CVE_PATTERN.finditer(text):
        cve = m.group(1).upper()
        cve_key = f"CVE:{cve}"
        if cve_key in seen:
            continue
        seen.add(cve_key)

        sentence_start = _find_sentence_start(text, m.start())
        sentence_end = _find_sentence_end(text, m.end())
        sentence = text[sentence_start:sentence_end]

        desc = sentence.strip()[:500]
        software = _extract_software(sentence, m.group(0))
        severity = _extract_severity(sentence, m.group(0))

        results.append(VulnInfo(
            cve_id=cve,
            description=desc,
            software=software,
            severity=severity,
        ))

    if tables:
        for table in tables:
            for row in table:
                row_text = " ".join((c or "") for c in row)
                for m in BDU_PATTERN.finditer(row_text):
                    bdu = f"BDU:{m.group(1)}"
                    if bdu not in seen:
                        seen.add(bdu)
                        results.append(VulnInfo(bdu_id=bdu, description=row_text[:500]))

    return results


def _find_sentence_start(text: str, pos: int) -> int:
    for i in range(pos, max(0, pos - 500), -1):
        if text[i] in "!?\n":
            return min(i + 1, pos)
        if text[i] == ".":
            if i > 0 and i + 1 < len(text) and text[i - 1].isdigit() and text[i + 1].isdigit():
                continue
            return min(i + 1, pos)
    return max(0, pos - 500)


def _find_sentence_end(text: str, pos: int) -> int:
    for i in range(pos, min(len(text), pos + 500)):
        if text[i] in "!?\n":
            return i + 1
        if text[i] == ".":
            if i > 0 and i + 1 < len(text) and text[i - 1].isdigit() and text[i + 1].isdigit():
                continue
            return i + 1
    return min(len(text), pos + 500)


def _extract_software(sentence: str, bdu_str: str = "") -> str:
    bad_words = {"cvss", "gsocket", "backdoor", "бэкдор", "троян", "стилер",
                 "червь", "файл", "архив", "письмо", "уровень", "опасности",
                 "danger", "vulnerability", "эксплуатация", "уязвимост"}

    search_zone = sentence
    if bdu_str and bdu_str in sentence:
        first_bdu = re.search(r"(?:BDU|БДУ)[:\s]", sentence, re.IGNORECASE)
        if first_bdu:
            search_zone = sentence[:first_bdu.start()]

    sw = _find_software_in(search_zone, bad_words)
    if sw:
        return sw

    first_bdu = re.search(r"(?:BDU|БДУ)[:\s]", sentence, re.IGNORECASE)
    if first_bdu:
        sw = _find_software_in(sentence[:first_bdu.start()], bad_words)
        if sw:
            return sw

    return ""


def _find_software_in(text: str, bad_words: set) -> str:
    m = re.search(
        r"(?:программного\s+обеспечения|программы|пакета?\s+программ|"
        r"библиотеки|текстового\s+редактора|редактора|"
        r"операционн[а-яё]+\s+систем|системы|средства)\s+"
        r"([A-ZА-Я][\w\s.\-]{2,80}?)\s*(?:\(|,|;|$)",
        text, re.IGNORECASE
    )
    if m:
        sw = m.group(1).strip().rstrip(",.;:")
        if _is_valid_software(sw, bad_words):
            return sw

    m = re.search(r"([A-Z][A-Za-z][A-Za-z0-9\s.\-]{2,60}?)\s*\(\s*(?:BDU|БДУ)", text)
    if m:
        sw = m.group(1).strip().rstrip(",.;:")
        if _is_valid_software(sw, bad_words):
            return sw

    candidates = re.findall(r"([A-Z][A-Za-z][A-Za-z0-9\s.\-]{2,60})", text)
    for c in reversed(candidates):
        c = c.strip().rstrip(",.;:")
        if _is_valid_software(c, bad_words):
            return c

    return ""


def _is_valid_software(sw: str, bad_words: set) -> bool:
    sw_lower = sw.lower()
    if len(sw) < 3:
        return False
    if sw_lower.endswith((".zip", ".rar", ".exe", ".lnk", ".hta", ".doc",
                          ".docx", ".pdf", ".xls", ".xlsx", ".rtf", ".wsf",
                          ".bat", ".cmd", ".scr")):
        return False
    for w in bad_words:
        if w in sw_lower:
            return False
    if re.search(r"\d{4}", sw):
        return False
    if "_" in sw:
        return False
    if re.match(r"^[А-Яа-яёЁ\s]+$", sw) and len(sw) > 40:
        return False
    return True


def _extract_severity(sentence: str, bdu_str: str) -> str:
    pos = sentence.find(bdu_str)
    if pos < 0:
        return "unknown"

    after = sentence[pos:]

    m = re.search(
        r"уровень\s+опасности\s+по\s+CVSS\s*[\d.]+\s*[-—]\s*"
        r"(критическ[а-яё]+|высок[а-яё]+|средн[а-яё]+|низк[а-яё]+)",
        after, re.IGNORECASE
    )
    if not m:
        m = re.search(
            r"уровень\s+опасности.{0,30}?"
            r"(критическ[а-яё]+|высок[а-яё]+|средн[а-яё]+|низк[а-яё]+)",
            after, re.IGNORECASE
        )
    if not m:
        m = re.search(
            r"(критическ[а-яё]+|высок[а-яё]+|средн[а-яё]+|низк[а-яё]+)",
            after, re.IGNORECASE
        )
    if m:
        s = m.group(1).lower()
        if "крит" in s:
            return "critical"
        if "высок" in s:
            return "high"
        if "средн" in s:
            return "medium"
        if "низк" in s:
            return "low"
    return "unknown"
