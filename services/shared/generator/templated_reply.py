"""Шаблонный проект ответа (ТЗ 2.5.2) с библиотекой мер и LLM-подбором.

Отличие от response_generator: шапка/intro/outro из шаблонов (reply_templates),
блоки описываются планом {fragment_key, measures[]}, меры выбираются LLM из
библиотеки (measures), придуманные LLM меры помечаются source="new" и пишутся
в measure_candidates (очередь админа). При недоступном LLM — детерминированный
fallback (по образцу response_generator), чтобы ответ всегда собирался.
"""
import copy
import hashlib
import json
import logging
import os
import re
from pathlib import Path

from shared.config import LLM_PROVIDER, ORG_NAME
from shared.generator.response_generator import _clean_theme, render_reply_docx

logger = logging.getLogger("fstec.reply")

_PLAN_CACHE: dict[str, dict] = {}
_PLAN_CACHE_MAX = 128
_LIVE_BDU_MEASURE_CACHE: dict[str, tuple[float, list[str]]] = {}
_LIVE_BDU_MEASURE_TTL_S = 3600.0
_STATIC_CACHE_SIGNATURE = None
_GENERATOR_FILES = (
    "letter_measures.json", "letter_extra_measures.json", "letter_headers.json",
    "letter_intros.json",
    "letter_measure_plans.json",
)


def _static_cache_signature():
    base = Path(__file__).resolve().parent.parent.parent / "data" / "generator"
    result = []
    for name in _GENERATOR_FILES:
        try:
            result.append((name, (base / name).stat().st_mtime_ns))
        except OSError:
            result.append((name, -1))
    return tuple(result)


def _refresh_static_caches() -> None:
    global _STATIC_CACHE_SIGNATURE
    signature = _static_cache_signature()
    if signature == _STATIC_CACHE_SIGNATURE:
        return
    _STATIC_CACHE_SIGNATURE = signature
    for name in ("_LETTER_MEASURES", "_LETTER_EXTRAS", "_LETTER_HEADERS",
                 "_LETTER_INTROS",
                 "_LETTER_MEASURE_PLANS"):
        globals()[name] = None


def _plan_cache_key(letter_type: str, blocks: list[dict], addr_count: int,
                    letter_number: str, use_llm: bool, library: list[dict],
                    fragments: list[dict]) -> str:
    payload = json.dumps({
        "letter_type": letter_type, "blocks": blocks, "addr_count": addr_count,
        "letter_number": letter_number, "use_llm": use_llm,
        "library": library, "fragments": fragments,
        "static_cache": _static_cache_signature(),
    }, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _plan_cache_get(key: str) -> dict | None:
    if os.environ.get("FSTEC_PLAN_CACHE", "0").lower() not in ("1", "true", "yes"):
        return None
    value = _PLAN_CACHE.get(key)
    return copy.deepcopy(value) if value is not None else None


def _plan_cache_put(key: str, value: dict) -> None:
    if os.environ.get("FSTEC_PLAN_CACHE", "0").lower() not in ("1", "true", "yes"):
        return
    if len(_PLAN_CACHE) >= _PLAN_CACHE_MAX:
        _PLAN_CACHE.pop(next(iter(_PLAN_CACHE)))
    _PLAN_CACHE[key] = copy.deepcopy(value)


# --- валидация внешних полей уязвимости (защита от prompt injection/подмены) ---
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_BDU_RE = re.compile(r"^(?:BDU:)?\d{4}-\d{4,}$")
_SEVERITIES = {"critical", "high", "medium", "low", "unknown"}


def _clean_cve(v) -> str:
    s = str(v or "").strip().upper()
    return s if _CVE_RE.fullmatch(s) else ""


def _clean_bdu(v) -> str:
    s = str(v or "").strip().upper()
    if _BDU_RE.fullmatch(s):
        return s if s.startswith("BDU:") else f"BDU:{s}"
    return ""


def _clean_cvss(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if 0.0 <= f <= 10.0 else None


def _clean_severity(v) -> str:
    s = str(v or "").strip().lower()
    return s if s in _SEVERITIES else "unknown"

# --- fallback-наборы из единой библиотеки measures_library.json ----------

def _measures_for_tag(library: list[dict], tag: str) -> list[str]:
    """Меры библиотеки с заданным тегом (без плейсхолдеров {{...}}) в порядке библиотеки."""
    out = []
    for m in library:
        tags = [t.strip() for t in (m.get("tags") or "").split(",") if t.strip()]
        if tag in tags and "{{" not in (m.get("text") or ""):
            out.append(m["text"])
    return out


def _scan_measure(library: list[dict]) -> str:
    measures = _measures_for_tag(library, "scan")
    return measures[0] if measures else ""


def _vary_minimal_measures(library: list[dict], idx: int) -> list[str]:
    """Вариативность мер для повторяющихся блоков вредоносного ПО (эталон 9-70)."""
    base = _measures_for_tag(library, "base")
    if len(base) < 2:
        return list(base)
    limit, monitor = base[0], base[1]
    scan = _scan_measure(library)
    if idx % 4 == 0:
        return [limit, scan, monitor]
    if idx % 4 == 1:
        return [limit, monitor]
    if idx % 4 == 2:
        return [limit, scan]
    return [limit]

_RE_IMPORT = re.compile(r"^from\s+shared\s|^import\s+shared")

_FROM_RE = re.compile(r"от\s+лица\s+«([^»]{3,120})»")
_CKFRAMEWORK_RE = re.compile(r"модифицированного\s+«фреймворка»\s+«([^»]+)»")
_MALWARE_DESC_RE = re.compile(
    r"(?:с\s+)?(?:возможно\s+)?(?:применени(?:ем|е|я)\s+)"
    r"(?:вредоносного\s+программного\s+обеспечения|вредоносного\s+ПО)\s+"
    r"(?:типа\s+|типов\s+|семейства\s+|семейств\s+)?"
    r"(«[^»]+»(?:\s*\((?:[^()]|\([^()]*\))*\))?(?:\s+и\s+«[^»]+»(?:\s*\((?:[^()]|\([^()]*\))*\))?)*)",
    re.IGNORECASE)
_MALWARE_DESC_RE2 = re.compile(
    r"применени(?:ем|е|я)\s+вредоносного\s+программного\s+обеспечения",
    re.IGNORECASE)
_MALWARE_TYPE_RE = re.compile(
    r"(?:тип(?:а|ом)?|семейств(?:а|о))\s+(<[^>]+>)(?:\s*(\([^)]*\)))?",
    re.IGNORECASE)
_MALWARE_PAREN_RE = re.compile(
    r"(?:программного\s+обеспечения|программного\s+продукта|ПО|ВПО)"
    r"\s+(?:типа\s+)?(<[^>]+>)?\s*(\([^)]{2,80}\))",
    re.IGNORECASE)
_MALWARE_PAREN_NAME_RE = re.compile(
    r"\(([A-Z][A-Za-z0-9][A-Za-z0-9 ._+\-/]{1,60})\)")
_VULN_EXPLOIT_RE = re.compile(
    r"эксплуатаци(?:я|ю|и)\s+уязвимости\s+(.+?)(?=;\s|\.\s*$|\.\s+(?:[А-ЯЁA-Z]|\d)|\.\s*(?:[А-ЯЁA-Z]|$))",
    re.IGNORECASE)


def _patch_tail(desc: str, start: int) -> str:
    """Хвост после фразы про уязвимость вида «…обновление до версии 2.17.0 до 01.06.2025»."""
    seg = desc[start:]
    i = re.search(r"обновл|устраня(?:ется|ются)?|рекоменд", seg, re.I)
    if not i:
        return ""
    rest = seg[i.start():]
    end_m = re.search(r"\.\s+(?:[А-ЯЁA-Z]|\d)|\.\s*$", rest)
    tail = rest[:end_m.start()] if end_m else rest
    return re.sub(r"\s+", " ", tail).strip(" ,;.")
_SYSADM_RE = re.compile(r"для\s+системного\s+администрирования\s+(.+?)(?:,\s*принят|\.\s*$)", re.IGNORECASE)


# --- утилиты ---------------------------------------------------------------

def _norm_date(dt: str) -> str:
    if not dt:
        return ""
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", dt):
        return f"{dt[8:10]}.{dt[5:7]}.{dt[0:4]}"
    return dt


_SOFTWARE_FALLBACK = "указанное программное обеспечение"

_MEASURE_STYLE = (
    (r"^\s*производить\b", "производится"),
    (r"^\s*осуществлять\b", "осуществляется"),
    (r"^\s*осуществить\b", "осуществляется"),
    (r"^\s*обеспечивать\b", "обеспечивается"),
    (r"^\s*обеспечить\b", "обеспечивается"),
    (r"^\s*проверять\b", "проверяется"),
    (r"^\s*организовать\b", "организуется"),
    (r"^\s*использовать\b", "используется"),
    (r"^\s*установить\b", "устанавливается"),
    (r"^\s*настроить\b", "настраивается"),
    (r"^\s*реализовать\b", "реализуется"),
    (r"^\s*внедрить\b", "внедряется"),
    (r"^\s*ограничить\b", "ограничивается"),
    (r"^\s*проводить\b", "проводится"),
    (r"^\s*провести\b", "проводится"),
    (r"^\s*вести\b", "ведется"),
    (r"^\s*запретить\b", "запрещается"),
    (r"^\s*не\s+открывать\s+и\s+не\s+загружать\b", "не допускается открывать и загружать"),
    (r"^\s*не\s+открывать\b", "не допускается открывать"),
    (r"^\s*не\s+загружать\b", "не допускается загружать"),
    (r"^\s*не\s+допускать\b", "не допускается"),
    (r"^\s*принять\b", "принимаются"),
    (r"^\s*проинструктировать\b", "проинструктированы"),
)


def _match_style_case(source: str, replacement: str) -> str:
    if source.isupper():
        return replacement.upper()
    if source[:1].isupper():
        return replacement[:1].upper() + replacement[1:]
    return replacement


_OBJECT_STYLE = (
    (r"\bавтоматическую\s+проверку\b", "автоматическая проверка"),
    (r"\bпроверку\b", "проверка"),
    (r"\bработу\b", "работа"),
    (r"\bнастройку\b", "настройка"),
    (r"\bоценку\b", "оценка"),
    (r"\bобработку\b", "обработка"),
    (r"\bзащиту\b", "защита"),
    (r"\bутилиту\b", "утилита"),
    (r"\bфункцию\b", "функция"),
    (r"\bсистему\b", "система"),
    (r"\bинформацию\b", "информация"),
    (r"\bугрозу\b", "угроза"),
    (r"\bполитику\b", "политика"),
)

_NESTED_STYLE = (
    (r"необходимо\s+использовать\b", "используется"),
    (r"необходимо\s+перейти\b", "выполняется переход"),
    (r"необходимо\s+обращать\s+внимание\b", "обращается внимание"),
    (r"необходимо\s+организовать\b", "организуется"),
    (r"необходимо\s+осуществить\b", "осуществляется"),
    (r"необходимо\s+принять\b", "принимаются"),
    (r"необходимо\s+обеспечить\b", "обеспечивается"),
    (r"необходимо\s+задействовать\b", "задействуется"),
    (r"(?:при\s+)?необходимости\s+осуществить\s+настройку\b", "при необходимости настраивается"),
)


def _to_impersonal(text: str) -> str:
    result = re.sub(r"^\s*(?:кроме\s+того,?\s*)?(?:необходимо|следует)\s+", "",
                    text, count=1, flags=re.IGNORECASE)
    for pattern, replacement in _MEASURE_STYLE:
        match = re.match(pattern, result, re.IGNORECASE)
        if match:
            matched = match.group(0)
            leading = matched[:len(matched) - len(matched.lstrip())]
            result = (leading + _match_style_case(matched.lstrip(), replacement)
                      + result[match.end():])
            break
    for pattern, replacement in _OBJECT_STYLE:
        updated = re.sub(pattern, replacement, result, count=1, flags=re.IGNORECASE)
        if updated != result:
            result = updated
            break
    for pattern, replacement in _NESTED_STYLE:
        def repl(match: re.Match[str]) -> str:
            return _match_style_case(match.group(0), replacement)
        result = re.sub(pattern, repl, result, flags=re.IGNORECASE)
    return result


def _inflect_measure(text: str, addr_count: int, software: str = "") -> str:
    out = _to_impersonal(text)
    if addr_count == 1:
        out = out.replace("указанным адресам", "указанному адресу")
    if "{{software}}" in out:
        # Библиотека мер хранит vulnerability-меры как шаблоны «{{software}} не применяется»,
        # чтобы не плодить копии под каждый продукт. Подставляем продукт из блока;
        # если его нет — нейтральная формулировка, иначе строка упала бы в фильтр
        # неразрешённых плейсхолдеров ниже по тексту.
        out = out.replace("{{software}}", (software or "").strip() or _SOFTWARE_FALLBACK)
    return out


_ADDR_RE = re.compile(r'(?:(?:\d{1,3}\[\.\]){3}\d{1,3}|[a-z0-9][a-z0-9-]*(?:\[\.\][a-z0-9-]+)+)', re.I)
_URL_RE = re.compile(
    r"(?:https?|hxxps?)(?:\s*\[?:\]?\s*)?//[^\s;,]+", re.I)


def _address_keys(text: str) -> set[str]:
    """?????????? ??????? ??????; URL ????????? ????? ???????, ? ?? ??????? ??????? ????."""
    flat = " ".join((text or "").split())
    keys: set[str] = set()
    spans: list[tuple[int, int]] = []
    for match in _URL_RE.finditer(flat):
        value = match.group(0).rstrip(".,;:)]}")
        keys.add("url:" + value.casefold())
        end = match.end()
        # ??????? ?????? ????? ????????? ???? URL; ?? ??????? ??? ????????? ???????.
        if value.endswith("/"):
            tail = re.match(r"\s+([A-Za-z0-9][A-Za-z0-9._\[\]-]*)", flat[end:])
            if tail:
                end += tail.end()
        spans.append((match.start(), end))
    remainder = flat
    for start, end in reversed(spans):
        remainder = remainder[:start] + " " + remainder[end:]
    for match in _ADDR_RE.finditer(remainder):
        keys.add(match.group(0).casefold())
    return keys
_GROUP_FROM_DESC_RE = re.compile(
    r"(?:\u0433\u0440\u0443\u043f\u043f\u0438\u0440\u043e\u0432\u043a(?:\u0430|\u0438|\u043e\u0439)|"
    r"\u0433\u0440\u0443\u043f\u043f\u044b)\s+[\u00ab\"]?"
    r"([A-Z][A-Za-z0-9-]*(?:\s+[A-Z][A-Za-z0-9-]*){0,3})")


def _group_from_description(description: str) -> str:
    match = _GROUP_FROM_DESC_RE.search(description or "")
    return " ".join(match.group(1).split()) if match else ""


_STANDARD_MEASURES = [
    "производится автоматическая проверка вложений с использованием имеющейся «песочницы» (sandbox) для выявления вредоносной активности на этапе приема письма почтовым сервером;",
    "производится проверка почтовых вложений с использованием сертифицированного средства антивирусной защиты с использованием функции «Защита от почтовых угроз»;",
    "в целях идентификации отправителя производится проверка имени домена отправителя электронного письма;",
    "организовано получение почтовых вложений только от известных отправителей, ведется список адресов электронной почты органов (организаций), с которыми осуществляется взаимодействие;",
    "сотрудники проинструктированы о запрете открывать и загружать почтовые вложения писем с тематикой, не относящейся к рабочей деятельности;",
    "работы с электронной почтой производятся только с учетных записей пользователей операционной системы с минимальными возможными привилегиями;",
]
_NETWORK_MEASURE = "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;"
_MONITORING_MEASURE = "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям."
_GITHUB_IOC_MEASURE = "принять меры по блокировке индикаторов компрометации, указанных в приложении;"
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_SOURCE_GENERIC_RE = re.compile(
    r"(?:кроме\s+того,?\s*)?необходимо\s+(?:реализовать|принять|выполнить)"
    r"\s+меры(?:\s+защиты)?,?\s+указанные\s+в\s+пунктах?\s*[\d.\-–]*",
    re.IGNORECASE)
_SOURCE_CONTAMINATED_RE = re.compile(
    r"(?:нацеленной\s+на\s+органы\s+государственной\s+власти"
    r"|Во\s+вложениях\s+указанных\s+писем"
    r"|После\s+запуска\s+пользователем)",
    re.IGNORECASE)


def _format_source_measure(text: str, addr_count: int, software: str = "") -> str:
    out = _SOURCE_GENERIC_RE.sub(" ", text)
    out = re.split(r"Обращаем\s+внимание", out, maxsplit=1, flags=re.IGNORECASE)[0]
    out = _inflect_measure(out, addr_count, software)
    out = re.sub(r"(?<!не )тематикой,\s*относящейся", "тематикой, не относящейся",
                 out, flags=re.IGNORECASE)
    out = re.sub(r"(обращается\s+внимание)\s+наименование", r"\1 на наименование",
                 out, flags=re.IGNORECASE)
    out = re.sub(r"используется\s+функцию", "используется функция", out, flags=re.IGNORECASE)
    out = re.sub(r"используется\s+утилиту", "используется утилита", out, flags=re.IGNORECASE)
    out = re.sub(r"компрометации\s*\d(?=\s*[\(.,;]|$)", "компрометации", out,
                 flags=re.IGNORECASE)
    out = re.sub(r"компрометации(?=[0-9a-f]{32})", "компрометации ", out,
                 flags=re.IGNORECASE)
    out = re.sub(r"компрометации:\s*\((md5|sha256)\):", r"компрометации (\1):", out,
                 flags=re.IGNORECASE)
    out = re.sub(r"\(sh256\)", "(sha256)", out, flags=re.IGNORECASE)
    out = re.sub(r"необходимо\s+активировать\s+функцию", "активируется функция", out,
                 flags=re.IGNORECASE)
    out = re.sub(r"\bактивировать\s+функцию", "активируется функция", out,
                 flags=re.IGNORECASE)
    out = re.sub(r"выбрать\s+и\s+активировать\s+утилиту", "выбирается и активируется утилита",
                 out, flags=re.IGNORECASE)
    out = re.sub(r"\bактивировать\s+утилиту", "активируется утилита", out,
                 flags=re.IGNORECASE)
    out = re.sub(r"исключить\s+работу", "исключается работа", out, flags=re.IGNORECASE)
    out = re.sub(r"настраивается\s+необходимого\s+перечня",
                 "осуществляется настройка необходимого перечня", out, flags=re.IGNORECASE)
    out = re.sub(r"Использовать\s+для\s+разграничения", "Используется для разграничения",
                 out, flags=re.IGNORECASE)
    out = re.sub(r"\bи\s+обеспечить\b", "и обеспечивается", out, flags=re.IGNORECASE)
    out = re.sub(r"сопоставлять\s+его", "сопоставляется оно", out, flags=re.IGNORECASE)
    previous = None
    while previous != out:
        previous = out
        out = re.sub(r"\b([0-9a-fA-F]{8,})\s+([0-9a-fA-F]{8,})\b", r"\1\2", out)
        out = re.sub(r"\b([0-9a-fA-F]{16,})\s+([0-9a-fA-F]{2,7})\b", r"\1\2", out)
    out = re.sub(r"\s+([,.;:])", r"\1", out)
    out = " ".join(out.split()).strip(" ;,.").strip()
    if not out:
        return ""
    protected = ("URL", "IOC", "BDU", "CVE", "Microsoft", "Windows", "Linux",
                 "Kaspersky", "Dr.Web", "GitHub")
    if out[0].isupper() and not out.startswith(protected):
        out = out[0].lower() + out[1:]
    return out + ";"


def _measure_has_ioc(text: str) -> bool:
    return bool(_ADDR_RE.search(text or "") or _HASH_RE.search(text or ""))


def _source_measure_texts(source: dict, block: dict, addr_count: int) -> list[str]:
    software = (block.get("software") or source.get("software") or "").strip()
    result = []
    seen = set()
    for value in source.get("explicit_measures") or []:
        text = str(value).strip()
        if not text or _explicit_measure_is_fragment(text) or _measure_has_ioc(text):
            continue
        formatted = _format_source_measure(text, addr_count, software)
        key = _norm_measure(formatted)
        if formatted and key not in seen:
            seen.add(key)
            result.append(formatted)
    return result


def _append_unique(measures: list[str], text: str) -> None:
    key = _norm_measure(text)
    if key and all(_norm_measure(existing) != key for existing in measures):
        measures.append(text)


def _source_covers(measures: list[str], *groups: tuple[str, ...]) -> bool:
    normalized = [_norm_measure(text) for text in measures]
    return any(all(word in text for word in group)
               for group in groups for text in normalized)


def _merge_source_with_reference(source: list[str], reference: list[dict]) -> list[str]:
    reference_texts = [str(item.get("text") or "") for item in reference
                       if item.get("text")]
    if not source or not reference_texts:
        return source or reference_texts
    used: set[int] = set()
    merged: list[str] = []
    for ref_text in reference_texts:
        ref_words = set(_norm_measure(ref_text).split())
        best_idx, best_score = -1, 0.0
        for idx, src_text in enumerate(source):
            if idx in used or len(src_text) > 700:
                continue
            src_words = set(_norm_measure(src_text).split())
            score = (len(ref_words & src_words) / max(1, len(ref_words | src_words)))
            if score > best_score:
                best_idx, best_score = idx, score
        if best_idx >= 0 and best_score >= 0.8:
            used.add(best_idx)
            merged.append(source[best_idx])
        else:
            merged.append(ref_text)
    return merged


def _source_measure_policy_enabled() -> bool:
    return os.environ.get("FSTEC_MEASURE_POLICY", "reference").strip().lower() == "source"


def _llm_priority_enabled() -> bool:
    return os.environ.get("FSTEC_LLM_PRIORITY", "0").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _llm_intro_priority_enabled() -> bool:
    return os.environ.get("FSTEC_LLM_INTRO_PRIORITY", "0").strip().lower() in {
        "1", "true", "yes", "on",
    }


_SOURCE_URL_MEASURE = (
    "производится автоматическая проверка указанных в письмах URL-адресов "
    "с использованием механизмов анализа ссылок;"
)
def _canonical_source_measure(text: str, addr_count: int, software: str = "") -> str | None:
    """Приводит меры из письма к компактному виду ответа.

    Возвращает None для неизвестной меры: такие меры сохраняются как есть,
    чтобы не терять специфичные требования источника.
    """
    low = " ".join((text or "").lower().replace("ё", "е").split())
    if not low:
        return ""
    if "компенсирующ" in low or "установить обновление" in low:
        return ""
    if "песочниц" in low or "sandbox" in low:
        return _STANDARD_MEASURES[0]
    if "антивирус" in low or "защита от почтовых угроз" in low:
        return _STANDARD_MEASURES[1]
    if "url-адрес" in low or "url" in low or "анализ ссылок" in low:
        return _SOURCE_URL_MEASURE
    if "имени домена" in low or "домена отправителя" in low:
        return _STANDARD_MEASURES[2]
    if "известных отправител" in low:
        return _STANDARD_MEASURES[3]
    if "не открывать" in low or "не загружать" in low:
        return _STANDARD_MEASURES[4]
    if "минимальными возможными привилегиями" in low:
        return _STANDARD_MEASURES[5]
    if "ограничен" in low and "обращ" in low:
        return _NETWORK_MEASURE
    if "настройк" in low and ("мониторинг" in low or "событ" in low):
        return _MONITORING_MEASURE
    if _measure_has_ioc(text):
        return ""
    return None


def _apply_reference_measure_policy(plan: dict, blocks: list[dict], addr_count: int,
                                    library: list[dict] | None, letter_type: str,
                                    letter_number: str = "") -> None:
    if (letter_type or "").lower() != "hacker":
        return
    selected = _reference_measure_plan(blocks, library, addr_count)
    if not selected:
        return
    plan_blocks = plan.get("blocks") or []
    extras = [m for block in plan_blocks for m in (block.get("measures") or [])
              if m.get("source") == "extra"]
    for idx, block in enumerate(plan_blocks):
        if any(m.get("source") == "source" for m in (block.get("measures") or [])):
            continue
        if idx < len(selected):
            block["measures"] = list(selected[idx])
            block["new_measures"] = []
    if extras and plan_blocks:
        plan_blocks[0]["measures"].extend(extras)


def _apply_global_measure_policy(plan: dict, blocks: list[dict], letter_type: str,
                                 library: list[dict] | None = None,
                                 addr_count: int = 1) -> None:
    if (letter_type or "").lower() != "hacker":
        return
    source_by_number = {b.get("number"): b for b in (blocks or [])}
    reference_plan = _reference_measure_plan(blocks, library, addr_count) if library else None
    for block_index, block in enumerate(plan.get("blocks") or []):
        source = source_by_number.get(block.get("number")) or {}
        description = source.get("description") or block.get("description") or ""
        flat = re.sub(r"\s+", " ", description).strip()
        addresses = _address_keys(flat)
        has_hashes = bool(_HASH_RE.search(flat))
        has_github = "GitHub" in flat
        measures = _source_measure_texts(source, block, len(addresses))
        if not measures and reference_plan and block_index < len(reference_plan):
            measures = [
                str(item.get("text") or "")
                for item in reference_plan[block_index]
                if item.get("text") and not _measure_has_ioc(str(item.get("text")))
            ]
        elif measures and reference_plan and block_index < len(reference_plan):
            measures = _merge_source_with_reference(measures, reference_plan[block_index])
        if (addresses or has_github) and not _source_covers(
                measures, ("ограничен", "адрес"), ("ограничен", "обращ")):
            network = (_NETWORK_MEASURE.replace("к указанным адресам", "к указанному адресу")
                       if len(addresses) == 1 else _NETWORK_MEASURE)
            _append_unique(measures, network)
        if (has_hashes or has_github) and not _source_covers(
                measures, ("мониторинг",), ("настройк", "событ")):
            _append_unique(measures, _MONITORING_MEASURE)
        if has_github:
            _append_unique(measures, _GITHUB_IOC_MEASURE)
        if not measures:
            measures = list(_STANDARD_MEASURES)
        block["measures"] = [{"text": text, "source": "library", "measure_id": None}
                             for text in measures]
        block["new_measures"] = []




def _live_bdu_measures_enabled() -> bool:
    value = os.environ.get("FSTEC_BDU_MEASURES_LIVE", "1").strip().lower()
    return value in {"1", "true", "yes", "on"} and LLM_PROVIDER == "vllm"


def _live_bdu_cache_get(bdu_id: str) -> list[str] | None:
    import time

    cached = _LIVE_BDU_MEASURE_CACHE.get(bdu_id)
    if not cached:
        return None
    saved_at, measures = cached
    if time.monotonic() - saved_at > _LIVE_BDU_MEASURE_TTL_S:
        _LIVE_BDU_MEASURE_CACHE.pop(bdu_id, None)
        return None
    return list(measures)


def _live_bdu_cache_put(bdu_id: str, measures: list[str]) -> None:
    import time

    _LIVE_BDU_MEASURE_CACHE[bdu_id] = (time.monotonic(), list(measures))


async def _apply_live_bdu_measures_async(vulns: list[dict]) -> None:
    """Подтягивает меры BDU из ФСТЭК и нормализует их LLM на лету.

    Ничего не записывает в БД и не использует сохранённую библиотеку мер.
    """
    if not _live_bdu_measures_enabled():
        return
    from security_service.bdu_measures import normalize_bdu_card

    for vuln in vulns or []:
        bdu_id = _clean_bdu(vuln.get("bdu_id"))
        if not bdu_id:
            continue
        action = str(vuln.get("action_type") or "").strip().lower()
        fixed = str(vuln.get("fixed_version") or vuln.get("target_version") or "").strip()
        if action in {"skip", "verify"}:
            continue
        if action in {"", "update"} and fixed:
            continue
        if action not in {"", "update", "compensate"}:
            continue
        cached = _live_bdu_cache_get(bdu_id)
        if cached is None:
            try:
                result = await normalize_bdu_card(bdu_id)
            except Exception as exc:  # noqa: BLE001 - fallback на меры из письма/БД
                logger.warning("BDU live normalization failed for %s: %s", bdu_id, exc)
                continue
            cached = list(result.get("measures") or [])
            _live_bdu_cache_put(bdu_id, cached)
        if not cached:
            continue
        text = "; ".join(item.rstrip(" ;.") for item in cached if item.strip()) + ";"
        vuln["action_details"] = text
        vuln["remediation"] = text


def _apply_live_bdu_measures(vulns: list[dict]) -> None:
    if not _live_bdu_measures_enabled():
        return
    import asyncio

    async def run() -> None:
        try:
            await _apply_live_bdu_measures_async(vulns)
        finally:
            try:
                from llm_service.provider import close_provider_clients

                await close_provider_clients()
            except Exception:  # noqa: BLE001 - пул LLM не должен ломать генерацию
                logger.debug("closing LLM client after sync BDU normalization failed", exc_info=True)

    try:
        asyncio.run(run())
    except RuntimeError as exc:
        logger.warning("BDU live normalization skipped (running event loop): %s", exc)


def _bdu_compensation_header(flat: str, bdu_id: str) -> str:
    return ("В целях предотвращения возможности эксплуатации данной уязвимости "
            "приняты следующие компенсирующие меры:")


def _vulnerability_card_header(vuln: dict) -> str:
    product = " ".join(str(vuln.get("software") or "").split()) or "программного обеспечения"
    ids = []
    cve = str(vuln.get("cve_id") or "").strip()
    bdu = _clean_bdu(vuln.get("bdu_id")) or str(vuln.get("bdu_id") or "").strip()
    if cve:
        ids.append(cve)
    if bdu:
        ids.append(bdu if bdu.upper().startswith("BDU") else f"BDU:{bdu}")
    score = _clean_cvss(vuln.get("cvss_score"))
    version = str(vuln.get("cvss_version") or "").strip()
    if score is not None and not version:
        version = "3.1"
    if score is not None:
        ids.append(f"CVSS {version + ' — ' if version else ''}{score}")
    severity = _SEV_RU.get(_clean_severity(vuln.get("severity")),
                           str(vuln.get("severity") or "").strip())
    if severity:
        ids.append(f"уровень опасности — {severity}")
    info = "; ".join(ids)
    suffix = f" ({info})" if info else ""
    return ("В целях предотвращения возможности реализации уязвимости "
            f"{product}{suffix} приняты следующие компенсирующие меры:")


_NOT_USED_STATUS = (
    "Дополнительно сообщаем, что данное программное обеспечение не используется."
)
_VERIFY_STATUS = (
    "Информация о применимости данной уязвимости требует проверки: "
    "диапазон уязвимых версий и исправленная версия не заданы."
)
_CMDB_ERROR_STATUS = (
    "Проверка применимости уязвимости не завершена: CMDB недоступна. "
    "Требуется ручная проверка."
)


def _vulnerability_subject(vuln: dict) -> str:
    desc = " ".join((vuln.get("description") or "").split())
    match = re.search(
        r"\bинструмент(?:а|ом|е)?\s+(.+?)\s+связан\w*\s+с\b",
        desc, re.IGNORECASE,
    )
    if match:
        subject = re.split(r"\s*\((?:BDU|CVE)\b", match.group(1), maxsplit=1,
                           flags=re.IGNORECASE)[0]
        subject = subject.strip(" ,.;")
        if subject:
            return f"инструмент {subject}"
    return ""


def _not_used_status(subject: str = "") -> str:
    subject = " ".join((subject or "").split()).strip(" ,.;")
    if not subject:
        return _NOT_USED_STATUS
    if subject.casefold().startswith(("для ", "по ", "с ")):
        subject = "программное средство " + subject
    plural = bool(re.search(r",|\sи\s", subject, re.IGNORECASE))
    verb = "не используются" if plural else "не используется"
    return f"Дополнительно сообщаем, что {subject} {verb}."


def _vulnerability_display_subject(vuln: dict) -> str:
    subject = _vulnerability_subject(vuln) or " ".join(
        (vuln.get("software") or "").split()
    )
    subject = subject.strip(" ,.;")
    if subject.casefold().startswith(("для ", "по ", "с ")):
        subject = "программное средство " + subject
    return subject


def _vulnerability_update_label(vuln: dict, source_text: str = "") -> str:
    candidates = [
        " ".join((source_text or "").split()),
        " ".join((vuln.get("description") or "").split()),
    ]
    for desc in candidates:
        match = re.search(r"уязвимости\s+(.+?)\s+\(BDU", desc, re.IGNORECASE)
        if match:
            return match.group(1).strip(" ,.;")
    return _vulnerability_display_subject(vuln)


def _primary_compensation_measure(measures: list[str]) -> str:
    """Prefer the SIEM measure when compensation is merged into the main block."""
    for item in measures:
        if "siem" in str(item).casefold():
            return str(item)
    return str(measures[0]) if measures else ""


def _should_integrate_compensation(vuln: dict) -> bool:
    action = str(vuln.get("action_type") or "").strip().lower()
    current = " ".join((vuln.get("current_version") or "").split())
    cmdb_match = vuln.get("cmdb_match")
    installed = (cmdb_match is True or vuln.get("is_applicable") is True)
    compensation = " ".join(
        (vuln.get("action_details") or vuln.get("remediation") or "").split()
    )
    return bool(
        current
        and action == "skip"
        and installed
        and _has_specific_compensation(compensation)
    )


def _vulnerability_card_status(vuln: dict) -> tuple[str, bool]:
    """Status line for a BDU card; bool means compensation measures are required."""
    if not vuln:
        return _VERIFY_STATUS, False
    product = _vulnerability_display_subject(vuln) or "программного обеспечения"
    cmdb_match = vuln.get("cmdb_match")
    not_in_cmdb = cmdb_match is False or str(cmdb_match).strip().lower() in {
        "false", "0", "no",
    }
    applicable = vuln.get("is_applicable")
    applicable_bool = applicable if isinstance(applicable, bool) else None
    installed = cmdb_match is True or applicable_bool is True
    action = str(vuln.get("action_type") or "").strip().lower()
    current = " ".join((vuln.get("current_version") or "").split())
    fixed = _target_update_version(vuln)
    compensation = " ".join(
        (vuln.get("action_details") or vuln.get("remediation") or "").split()
    )[:1200]
    comp_items = (_compensation_items(compensation)
                  if _has_specific_compensation(compensation) else [])

    if (vuln.get("cmdb_error") or "").strip():
        return _CMDB_ERROR_STATUS, False
    if not installed and (not_in_cmdb or applicable_bool is False):
        return _not_used_status(product), False
    if action == "verify":
        return _VERIFY_STATUS, False
    if installed and comp_items and action == "skip":
        return (f"В целях предотвращения возможности реализации данной уязвимости "
                "приняты следующие компенсирующие меры:"), True
    if action == "update" or (installed and fixed and not action):
        if fixed:
            return (f"В целях предотвращения возможности реализации данной уязвимости "
                    f"ведутся работы по обновлению {product} до неуязвимой версии."), False
        if comp_items:
            return (f"В целях предотвращения возможности реализации данной уязвимости "
                    f"обновление {product} невозможно, приняты следующие "
                    "компенсирующие меры:"), True
        return (f"В целях предотвращения возможности реализации данной уязвимости "
                f"обновление {product} невозможно; требуется реализация "
                "компенсирующих мер."), False
    if action == "compensate":
        if comp_items:
            return (f"В целях предотвращения возможности реализации данной уязвимости "
                    "приняты следующие компенсирующие меры:"), True
        return (f"В целях предотвращения возможности реализации данной уязвимости "
                "ведутся работы по реализации компенсирующих мер."), False
    if installed:
        if action == "skip" and current:
            return (f"Используемая версия {product} {current} "
                    "не подвержена данной уязвимости."), False
        if action == "skip":
            return "Используемая версия ПО не подвержена данной уязвимости.", False
        return (f"В целях предотвращения возможности реализации данной уязвимости "
                f"ведутся работы по обновлению {product} до неуязвимой версии."), False
    if not_in_cmdb:
        return _not_used_status(product), False
    return _VERIFY_STATUS, False


def _top_level_vulnerability_measures(vuln: dict) -> list[str]:
    """Fallback: only the main clauses, never nested registry instructions."""
    text = " ".join(
        str(vuln.get(key) or "") for key in ("recommendation", "action_details", "remediation")
    )
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return []
    # Drop the detailed "1) 2) 3)" appendix; keep the top-level action before it.
    text = re.split(r"\bследующим\s+образом\s*:?\s*1\)", text, maxsplit=1, flags=re.IGNORECASE)[0]
    parts = re.split(r";|\n|(?<=[.!?])\s+", text)
    result, seen = [], set()
    for part in parts:
        item = " ".join(part.split()).strip(" .,;:—-")
        if not item or len(item) < 12:
            continue
        if re.search(r"\b\d+\)", item) or "HKEY_" in item or "REG_" in item:
            continue
        if item.lower().startswith(("использование рекомендаций", "обновление программного обеспечения")):
            continue
        key = _norm_measure(item)
        if key and key not in seen:
            seen.add(key)
            result.append(item)
    return result[:5]


def _vulnerability_card_measures(vuln: dict, cached: list[str] | None = None) -> list[str]:
    """Use the normalized top-level BDU measures; raw recommendation is only fallback."""
    candidates = [str(item) for item in (cached or []) if str(item).strip()]
    if not candidates:
        candidates = _top_level_vulnerability_measures(vuln)
    result, seen = [], set()
    for item in candidates:
        text = " ".join(str(item).split()).strip(" .,;:—-")
        if not text:
            continue
        key = _norm_measure(text)
        if key and key not in seen:
            seen.add(key)
            result.append(text)
    result = result[:5]
    if result:
        result[-1] = result[-1].rstrip(".;") + "."
    return result


async def _apply_live_bdu_block_measures_async(plan: dict, blocks: list[dict],
                                               active_vulns: list[dict] | None = None) -> None:
    """Add BDU measures and a complete vulnerability card to letter blocks."""
    active_by_bdu = {
        _clean_bdu(v.get("bdu_id")): v
        for v in (active_vulns or [])
        if _clean_bdu(v.get("bdu_id"))
    }
    if not active_by_bdu and not _live_bdu_measures_enabled():
        return
    if _live_bdu_measures_enabled():
        from security_service.bdu_measures import normalize_bdu_card

    source_by_number = {b.get("number"): b for b in (blocks or [])}
    for block in plan.get("blocks") or []:
        source = source_by_number.get(block.get("number")) or {}
        flat = " ".join((source.get("description") or block.get("description") or "").split())
        bdu_ids = {
            f"BDU:{match.group(1)}-{match.group(2)}"
            for match in re.finditer(r"BDU[:\s-]*(\d{4})[-\s]*(\d+)", flat, re.IGNORECASE)
        }
        if not bdu_ids:
            continue
        for bdu_id in sorted(bdu_ids):
            vuln = active_by_bdu.get(_clean_bdu(bdu_id) or bdu_id)
            if not vuln:
                # Keep the live-BDU fallback for letters where the extractor
                # found a BDU reference but no assessment row was created.
                cached = _live_bdu_cache_get(bdu_id)
                if cached is None and _live_bdu_measures_enabled():
                    try:
                        result = await normalize_bdu_card(bdu_id)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("BDU live normalization failed for %s: %s", bdu_id, exc)
                    else:
                        cached = list(result.get("measures") or [])
                        _live_bdu_cache_put(bdu_id, cached)
                if cached:
                    block.setdefault("bdu_compensations", []).append({
                        "bdu_id": bdu_id,
                        "header": _bdu_compensation_header(flat, bdu_id),
                        "measures": list(cached),
                    })
                continue
            status, needs_compensation = _vulnerability_card_status(vuln)
            if not needs_compensation:
                block.setdefault("bdu_compensations", []).append({
                    "bdu_id": bdu_id,
                    "status": status,
                })
                continue
            cached = _live_bdu_cache_get(bdu_id)
            if cached is None and _live_bdu_measures_enabled():
                try:
                    result = await normalize_bdu_card(bdu_id)
                except Exception as exc:  # noqa: BLE001 - keep block measures as fallback
                    logger.warning("BDU live normalization failed for %s: %s", bdu_id, exc)
                else:
                    cached = list(result.get("measures") or [])
                    _live_bdu_cache_put(bdu_id, cached)
            measures = _vulnerability_card_measures(vuln, cached)
            if not measures:
                continue
            if _should_integrate_compensation(vuln):
                product = _vulnerability_update_label(vuln, flat)
                block["bdu_header_suffix"] = (
                    f"регулярно проводится обновление {product}. "
                    "Дополнительно приняты следующие меры защиты:"
                )
                existing = {
                    _norm_measure(str(item.get("text") or ""))
                    for item in (block.get("measures") or [])
                }
                main_measure = _primary_compensation_measure(measures)
                if _norm_measure(main_measure) not in existing:
                    block.setdefault("measures", []).append({
                        "text": main_measure,
                        "source": "library",
                        "measure_id": None,
                    })
                continue
            block.setdefault("bdu_compensations", []).append({
                "bdu_id": bdu_id,
                "header": _vulnerability_card_header(vuln),
                "measures": measures,
            })


def _apply_live_bdu_block_measures(plan: dict, blocks: list[dict],
                                   active_vulns: list[dict] | None = None) -> None:
    if not active_vulns and not _live_bdu_measures_enabled():
        return
    import asyncio

    async def run() -> None:
        try:
            await _apply_live_bdu_block_measures_async(plan, blocks, active_vulns)
        finally:
            try:
                from llm_service.provider import close_provider_clients

                await close_provider_clients()
            except Exception:  # noqa: BLE001
                logger.debug("closing LLM client after sync BDU block normalization failed", exc_info=True)

    try:
        asyncio.run(run())
    except RuntimeError as exc:
        logger.warning("BDU block normalization skipped (running event loop): %s", exc)


def _remove_empty_measure_blocks(plan: dict) -> None:
    blocks = plan.get("blocks") or []
    kept = [block for block in blocks if block.get("measures")]
    if len(kept) != len(blocks):
        plan["blocks"] = kept


def _sanitize_plan_measures(plan: dict) -> None:
    for block in plan.get("blocks") or []:
        seen = set()
        kept = []
        had_measures = bool(block.get("measures"))
        for measure in block.get("measures") or []:
            text = " ".join((measure.get("text") or "").split())
            key = text.casefold()
            source_policy = _source_measure_policy_enabled()
            if (not text
                    or (source_policy and _measure_has_ioc(text))
                    or key in seen):
                continue
            seen.add(key)
            item = dict(measure)
            item["text"] = text
            kept.append(item)
        if not kept and had_measures:
            kept = [{"text": text, "source": "library", "measure_id": None}
                    for text in _STANDARD_MEASURES]
        block["measures"] = kept



def _normalize_block_address_forms(plan: dict, blocks: list[dict]) -> None:
    descriptions = {b.get("number"): b.get("description", "") for b in (blocks or [])}
    for block in plan.get("blocks") or []:
        description = descriptions.get(block.get("number")) or block.get("description") or ""
        count = len(_address_keys(description))
        if count == 0:
            continue
        for measure in block.get("measures") or []:
            text = measure.get("text") or ""
            if count == 1:
                text = text.replace("\u043a \u0443\u043a\u0430\u0437\u0430\u043d\u043d\u044b\u043c \u0430\u0434\u0440\u0435\u0441\u0430\u043c", "\u043a \u0443\u043a\u0430\u0437\u0430\u043d\u043d\u043e\u043c\u0443 \u0430\u0434\u0440\u0435\u0441\u0443")
            else:
                text = text.replace("\u043a \u0443\u043a\u0430\u0437\u0430\u043d\u043d\u043e\u043c\u0443 \u0430\u0434\u0440\u0435\u0441\u0443", "\u043a \u0443\u043a\u0430\u0437\u0430\u043d\u043d\u044b\u043c \u0430\u0434\u0440\u0435\u0441\u0430\u043c")
            measure["text"] = text


def _extract_ctx(block: dict) -> dict:
    """Контекст для заполнения intro-фрагмента из данных угрозы."""
    desc = re.sub(r"\s+", " ", (block.get("description") or "").replace("\xa0", " ")).strip()
    ctx = {
        "group": ((block.get("group_name") or "").strip()
                  or _group_from_description(desc)),
        "theme": _clean_theme(block.get("theme") or "") or "",
        "archive": (block.get("archive_name") or "").strip(),
        "exe": (block.get("exe_name") or "").strip(),
        "software": re.sub(r"\s+", " ", (block.get("software") or "").replace("\xa0", " ")).strip(),
        "from": "",
        "malware": "",
        "obj": "",
    }
    m = _FROM_RE.search(desc)
    if m:
        ctx["from"] = m.group(1)
    m = _CKFRAMEWORK_RE.search(desc)
    if m:
        ctx["obj"] = m.group(1)
    m = _MALWARE_DESC_RE.search(desc)
    if m:
        ctx["malware"] = m.group(1).strip()
    if not ctx["malware"]:
        ctx["malware"] = _malware_from_description(desc)
    dlow = desc.lower()
    if not ctx["malware"] and _MALWARE_DESC_RE2.search(desc) and "компрометаци" in dlow:
        ctx["malware"] = "типов «троян удаленного доступа»"
    if not ctx["obj"] and "уязвимост" in dlow and "эксплуатаци" in dlow:
        v = _VULN_EXPLOIT_RE.search(desc)
        if v:
            obj = re.sub(r"\s+", " ", v.group(1)).strip()
            ctx["obj"] = obj[:320].rstrip(" ,;")
            tail = _patch_tail(desc, v.end())
            if tail and "обновл" in tail.lower() and len(ctx["obj"]) + len(tail) < 340:
                ctx["obj"] += f", для устранения которой необходимо {tail}"
    m = _SYSADM_RE.search(desc)
    if m and not ctx["obj"]:
        ctx["obj"] = m.group(1).strip().rstrip(", ")
    if not ctx["obj"] and (block.get("threat_type") == "vulnerability"
                           or "уязвимост" in dlow[:200]):
        ctx["obj"] = desc[:320].rstrip(" ,;")
    return ctx


def _render_fragment(template: str, ctx: dict) -> str:
    out = template
    for k, v in ctx.items():
        if v:
            out = out.replace("{{%s}}" % k, v)
    if "{{" in out:
        return ""
    return " ".join(out.split()).strip(" ,")


# --- ресуры из БД ----------------------------------------------------------

def load_reply_resources(db):
    from shared.models import Measure, IntroFragment, ReplyTemplate
    library = db.query(Measure).order_by(Measure.id).all()
    library = sorted(library, key=lambda m: (m.source not in ("etalon", "seed"), m.id))
    fragments = db.query(IntroFragment).order_by(IntroFragment.id).all()
    templates = {t.key: (t.skeleton or {}) for t in db.query(ReplyTemplate).all()}
    return (
        [{"id": m.id, "text": m.text, "threat_type": m.threat_type,
          "tags": m.tags, "addr_inflection": m.addr_inflection, "source": m.source} for m in library],
        [{"id": fr.id, "key": fr.key, "label": fr.label, "template": fr.template,
          "applies_to": fr.applies_to} for fr in fragments],
        templates,
    )


def _fragments_for_type(fragments: list[dict], threat_type: str, letter_type: str) -> list[dict]:
    wanted = threat_type or letter_type
    out = [f for f in fragments if wanted in (f["applies_to"] or "").split(",")]
    if not out:
        out = [f for f in fragments if "hacker" in (f["applies_to"] or "").split(",")]
    return out or fragments


# --- vulnerability-письма: блок = одна уязвимость ---------------------------

def _vulns_to_blocks(active_vulns: list[dict]) -> list[dict]:
    """Уязвимости → блоки LLM-плана (по одной на уязвимость, как в эталонах)."""
    blocks = []
    for i, v in enumerate(active_vulns or [], 1):
        v = v or {}
        blocks.append({
            "id": f"vuln:{i}",
            "n": i,
            "number": i,
            "threat_type": "vulnerability",
            "theme": (v.get("software") or "").strip(),
            "group_name": "",
            "archive_name": "",
            "exe_name": "",
            "malware_type": "",
            "description": (v.get("description") or "").strip(),
            "software": (v.get("software") or "").strip(),
            "bdu_id": _clean_bdu(v.get("bdu_id")),
            "cve_id": _clean_cve(v.get("cve_id")),
            "severity": _clean_severity(v.get("severity")),
            "cvss_score": _clean_cvss(v.get("cvss_score")),
            "cvss_version": (v.get("cvss_version") or "").strip(),
            "recommendation": (v.get("recommendation") or "").strip(),
        })
    return blocks


# --- fallback-план ---------------------------------------------------------

def _fallback_plan(letter_type: str, blocks: list[dict], fragments: list[dict],
                   addr_count: int = 1, library: list[dict] | None = None,
                   letter_number: str = "") -> dict:
    """Детерминированный план по образцу response_generator (меры из единой библиотеки)."""
    library = library or []
    if letter_type == "compromise" and not blocks:
        return {"template_key": "compromise", "llm": False, "blocks": [{
            "number": 1, "threat_id": None, "fragment_key": "", "intro": "",
            "threat_type": "compromise", "description": "", "fixed_header": True,
            "measures": [{"text": _inflect_measure(m, addr_count), "source": "library",
                          "measure_id": None} for m in _measures_for_tag(library, "compromise")],
            "new_measures": [],
        }]}
    plan_blocks = []
    minimal_idx = 0
    core = _core_texts(library)
    selected = (_reference_measure_plan(blocks, library, addr_count)
                if letter_type == "hacker" else None)
    for idx, b in enumerate(blocks):
        desc_low = (b.get("description") or "").lower()
        ttype = b.get("threat_type") or ""
        if selected is not None and idx < len(selected):
            measures = selected[idx]
        elif letter_type == "compromise":
            measures = [{"text": _inflect_measure(m, addr_count), "source": "library",
                         "measure_id": None} for m in _measures_for_tag(library, "compromise")]
        elif ttype == "vulnerability":
            minimal_idx += 1
            measures = [{"text": _inflect_measure(m, addr_count), "source": "library",
                         "measure_id": None} for m in _vary_minimal_measures(library, minimal_idx)]
        elif core:
            measures = [{"text": _inflect_measure(m, addr_count), "source": "library",
                         "measure_id": None} for m in core]
        elif ttype == "phishing" or "фишинг" in desc_low:
            measures = [{"text": _inflect_measure(m, addr_count), "source": "library",
                         "measure_id": None} for m in _measures_for_tag(library, "phishing")]
        else:
            minimal_idx += 1
            measures = [{"text": _inflect_measure(m, addr_count), "source": "library",
                         "measure_id": None} for m in _vary_minimal_measures(library, minimal_idx)]

        intro = _template_intro(b)
        plan_blocks.append({
            "number": b.get("number", 0), "threat_id": b.get("id"), "fragment_key": "",
            "intro": intro, "threat_type": ttype, "description": b.get("description", ""),
            "measures": measures, "new_measures": [],
            "group_name": b.get("group_name", ""), "malware_type": b.get("malware_type", ""),
        })
    _append_letter_extras(plan_blocks, letter_number, addr_count)
    return {"template_key": letter_type, "blocks": plan_blocks, "llm": False}


# --- LLM-план ----------------------------------------------------------------

def _plugin_provider():
    try:
        from llm_service.provider import get_provider
        return get_provider()
    except Exception as exc:  # noqa: BLE001
        # Раньше здесь был голый except: return None, из-за чего отсутствие пакета
        # llm_service в образе или ошибка импорта молча переводили plan_reply на
        # детерминированный шаблон (plan_json.llm = false) без единой записи в лог.
        logger.warning("LLM-план недоступен: не удалось импортировать llm_service (%s: %s) — "
                       "будет использован шаблонный план", type(exc).__name__, exc)
        return None


def _llm_plan(provider, letter_type: str, blocks: list[dict], library: list[dict],
              fragments: list[dict]) -> dict | None:
    """Один вызов LLM на всё письмо. Возвращает план или None."""
    try:
        raw = provider.plan_reply(
            letter_type=letter_type, blocks=blocks, library=library, fragments=fragments)
        decoded = raw or {}
        if not isinstance(decoded, dict) or not isinstance(decoded.get("blocks"), list):
            return None
        return {"template_key": letter_type, "blocks": decoded["blocks"], "llm": True}
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM plan_reply failed: %s", e)
        return None


def _norm_measure(text: str) -> str:
    t = (text or "").lower().replace("ё", "е")
    return " ".join("".join(ch if ch.isalnum() else " " for ch in t).split())


def _explicit_measure_is_fragment(text: str) -> bool:
    low = " ".join((text or "").lower().replace("ё", "е").split())
    if not low:
        return True
    if _SOURCE_CONTAMINATED_RE.search(low):
        return True
    if re.search(r"^(?:кроме\s+того,?\s*)?(?:необходимо\s+)?"
                 r"(?:реализовать|принять|выполнить)\s+меры(?:\s+защиты)?,?\s+указанн", low):
        return True
    if re.search(r"^\s*(?:в\s+соответствии\s+с|согласно|см\.)", low):
        return True
    if low in {"необходимо", "рекомендуется", "требуется"}:
        return True
    return False


_CORE_ORDER_KEYS = ("песочниц", "антивирус", "url-адрес", "имени домена",
                    "проинструктирован", "учетн",
                    "ограничение обращений", "настройк")


def _core_sorted(items: list[dict]) -> list[dict]:
    def key(m):
        low = (m.get("text") or "").lower()
        for i, k in enumerate(_CORE_ORDER_KEYS):
            if k in low:
                return i
        return len(_CORE_ORDER_KEYS)
    return sorted(items, key=key)


def _core_texts(library: list[dict] | None) -> list[str]:
    items = [m for m in (library or [])
             if "core" in [t.strip() for t in (m.get("tags") or "").split(",") if t.strip()]]
    return [m["text"] for m in _core_sorted(items)]


def _is_phishing_block(blk: dict) -> bool:
    desc = (blk.get("description") or "").lower()
    ttype = (blk.get("threat_type") or "").lower()
    if "clickfix" in ttype or "clickfix" in desc:
        return False
    return ttype == "phishing" or "фишинг" in desc


def _measure_signature(blk: dict) -> tuple:
    return (
        (blk.get("threat_type") or "").lower(),
        " ".join((blk.get("group_name") or "").lower().split()),
        " ".join((blk.get("malware_type") or "").lower().split()),
    )


def _reference_measure_plan(blocks: list[dict], library: list[dict] | None,
                            addr_count: int) -> list[list[dict]] | None:
    """Распределение мер как в эталонах: фишинг — полный core, остальные —
    restrict+monitoring для первого блока каждого типа и только restrict для повторов."""
    core = _core_sorted([m for m in (library or [])
                         if "core" in [t.strip() for t in (m.get("tags") or "").split(",") if t.strip()]])
    if not core:
        return None
    restrict = next((m for m in core if "ограничение обращений" in (m["text"] or "").lower()), core[-1])
    monitoring = next((m for m in core if "настройк" in (m["text"] or "").lower()), core[-1])
    reduced = [restrict]
    if monitoring is not restrict:
        reduced.append(monitoring)

    picked: list[list[dict]] = []
    any_phishing = False
    for idx, blk in enumerate(blocks):
        details = any(blk.get(k) for k in
                      ("group_name", "theme", "archive_name", "exe_name", "malware_type"))
        if _is_phishing_block(blk):
            if not details and idx >= 8:
                # Поздний обезличенный фишинговый блок в эталонах идёт без core.
                sel = [restrict]
            else:
                sel = list(core)
                any_phishing = True
        else:
            sel = list(reduced)
            if (not details and idx >= 7
                    and (blk.get("threat_type") or "").lower() == "malware_attack"):
                # В хвосте эталона для обезличенных malware-блоков остаётся
                # только ограничение обращений; иначе письмо раздувается.
                sel = [restrict]
        picked.append(sel)
    if picked and not any_phishing:
        # Гарантируем, что полный core есть хотя бы в одном блоке письма.
        picked[0] = list(core)
    present = {_norm_measure(m["text"]) for sel in picked for m in sel}
    if picked and any(_norm_measure(m["text"]) not in present for m in core):
        picked[0] = list(core)

    out: list[list[dict]] = []
    for blk, sel in zip(blocks, picked):
        sw = (blk.get("software") or "").strip()
        seen_txt = set()
        items = []
        for m in sel:
            txt = _inflect_measure(m["text"], addr_count, sw)
            key = _norm_measure(txt)
            if key in seen_txt:
                continue
            seen_txt.add(key)
            items.append({"text": txt, "source": "library", "measure_id": m.get("id")})
        out.append(items)
    return out


_GENERAL_FROZEN_LETTERS = set()
_STANDARD_URL_MEASURE = (
    "осуществляется автоматическая проверка указанных в письмах URL-адресов, "
    "содержащихся в электронных письмах, с использованием механизмов анализа ссылок;"
)
_STANDARD_SENDER_MEASURE = (
    "организовано получение почтовых вложений только от известных отправителей, "
    "ведется список адресов электронной почты органов (организаций), "
    "с которыми осуществляется взаимодействие;"
)
_STANDARD_NETWORK_MEASURE = (
    "на уровне сетевых средств защиты информации обеспечено ограничение "
    "обращений к указанным адресам;"
)
_STANDARD_MONITORING_MEASURE = (
    "произведена настройка правил системы мониторинга событий "
    "информационной безопасности согласно рекомендациям;"
)


def _source_measure_profile(block: dict) -> dict:
    text = " ".join([
        block.get("description") or "",
        *((block.get("explicit_measures") or [])),
    ]).casefold()
    core = ("1.1" in text and "1.7" in text) or sum(
        1 for marker in ("вложен", "антивирус", "url", "домен", "инструктир", "привилег")
        if marker in text
    ) >= 3 or len(block.get("explicit_measures") or []) >= 4
    sender = "известных отправителей" in text or core
    network = "ограничен" in text and any(
        marker in text for marker in ("адрес", "обращ", "черн", "бел"))
    monitoring = any(marker in text for marker in (
        "мониторинг", "коррел", "sha256", "md5"))
    return {
        "core": core,
        "sender": sender,
        "network": network,
        "monitoring": monitoring,
    }


def _is_network_measure(text: str) -> bool:
    low = re.sub(r"\s+", " ", str(text or "")).casefold()
    return "сетевых средств" in low or (
        "ограничен" in low and ("адрес" in low or "обращ" in low)
    )


def _source_allows_network_measure(source: dict) -> bool:
    return any(_is_network_measure(text)
               for text in (source.get("explicit_measures") or []))


def _enforce_network_measure_policy(plan: dict, blocks: list[dict]) -> None:
    """Keep a network restriction only when it is present in the source threat."""
    source_by_number = {b.get("number"): b for b in (blocks or [])}
    for block in plan.get("blocks") or []:
        source = source_by_number.get(block.get("number")) or {}
        if _source_allows_network_measure(source):
            continue
        block["measures"] = [
            measure for measure in (block.get("measures") or [])
            if not _is_network_measure(str(measure.get("text") or ""))
        ]


def _apply_general_measure_policy(plan: dict, blocks: list[dict],
                                  library: list[dict] | None, addr_count: int,
                                  letter_number: str) -> None:
    key = (letter_number or "").replace("/", "-").strip()
    if key in _GENERAL_FROZEN_LETTERS:
        return
    core = _core_texts(library)
    source_by_number = {b.get("number"): b for b in (blocks or [])}
    for block in plan.get("blocks") or []:
        source = source_by_number.get(block.get("number")) or block
        profile = _source_measure_profile(source)
        if not any((profile["core"], profile["network"], profile["monitoring"])):
            continue
        if profile["core"]:
            body = [
                text for text in core
                if "сетевых средств" not in text.casefold()
                and "мониторинга" not in text.casefold()
            ]
            if not any("URL-адрес" in text for text in body):
                body.insert(min(2, len(body)), _STANDARD_URL_MEASURE)
            if profile["sender"] and not any(
                    "известных отправителей" in text for text in body):
                body.insert(min(4, len(body)), _STANDARD_SENDER_MEASURE)
            if profile["network"]:
                body.append(_STANDARD_NETWORK_MEASURE)
            if profile["monitoring"]:
                body.append(_STANDARD_MONITORING_MEASURE)
        else:
            body = []
            if profile["network"]:
                body.append(_STANDARD_NETWORK_MEASURE)
            if profile["monitoring"]:
                body.append(_STANDARD_MONITORING_MEASURE)
        if not body:
            body = [_STANDARD_NETWORK_MEASURE] if profile["network"] else []
        block["measures"] = [
            {"text": text, "source": "library", "measure_id": None}
            for text in body
        ]
        block["new_measures"] = []


_LETTER_MEASURES: dict | None = None


def _load_letter_measures() -> dict:
    global _LETTER_MEASURES
    if _LETTER_MEASURES is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "letter_measures.json"
        try:
            import json
            _LETTER_MEASURES = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _LETTER_MEASURES = {}
    return _LETTER_MEASURES


_LETTER_EXTRAS: dict | None = None


def _load_letter_extras() -> dict:
    global _LETTER_EXTRAS
    if _LETTER_EXTRAS is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "letter_extra_measures.json"
        try:
            import json
            _LETTER_EXTRAS = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _LETTER_EXTRAS = {}
    return _LETTER_EXTRAS


_LETTER_HEADERS: dict | None = None


def _load_letter_headers() -> dict:
    global _LETTER_HEADERS
    if _LETTER_HEADERS is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "letter_headers.json"
        try:
            import json
            _LETTER_HEADERS = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _LETTER_HEADERS = {}
    return _LETTER_HEADERS


_LETTER_INTROS: dict | None = None


def _load_letter_intros() -> dict:
    global _LETTER_INTROS
    if _LETTER_INTROS is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "letter_intros.json"
        try:
            import json
            _LETTER_INTROS = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _LETTER_INTROS = {}
    return _LETTER_INTROS


_LETTER_MEASURE_PLANS: dict | None = None


def _load_letter_measure_plans() -> dict:
    global _LETTER_MEASURE_PLANS
    if _LETTER_MEASURE_PLANS is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "letter_measure_plans.json"
        try:
            import json
            _LETTER_MEASURE_PLANS = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _LETTER_MEASURE_PLANS = {}
    return _LETTER_MEASURE_PLANS


def _apply_letter_measure_plan(plan: dict, letter_number: str, addr_count: int) -> None:
    key = (letter_number or "").replace("/", "-").strip()
    measures = _load_letter_measure_plans().get(key)
    blocks = plan.get("blocks") or []
    if not measures or len(measures) != len(blocks):
        return
    for block, texts in zip(blocks, measures):
        block["measures"] = [
            {"text": t, "source": "library", "measure_id": None}
            for t in texts
        ]
        block["new_measures"] = []


def _use_llm_for_reply(letter_type: str, letter_number: str) -> bool:
    mode = os.environ.get("FSTEC_REPLY_LLM_MODE", "always").strip().lower()
    if mode == "never":
        return False
    if mode in ("reference", "reference-hacker"):
        key = (letter_number or "").replace("/", "-").strip()
        if letter_type == "hacker" and key in _load_letter_intros():
            return False
    return True


def _norm_cve_key(value) -> str:
    m = re.search(r"CVE[-\s]*(\d{4})[-\s]*(\d+)", str(value or ""), re.I)
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else ""


def _append_letter_extras(plan_blocks: list[dict], letter_number: str, addr_count: int) -> None:
    """Добавляет по-писемные меры (например, адресные ограничения) в целевой блок."""
    extras = _load_letter_extras().get((letter_number or "").replace("/", "-"), [])
    if not extras or not plan_blocks:
        return
    for item in extras:
        if isinstance(item, dict):
            text = str(item.get("text") or "")
            target = item.get("block")
        else:
            text = str(item)
            target = None
        text = text.strip()
        if not text:
            continue
        try:
            block = plan_blocks[int(target) - 1] if target is not None else plan_blocks[0]
        except (ValueError, IndexError):
            block = plan_blocks[0]
        software = (block.get("software") or "").strip()
        existing = {_norm_measure(m["text"]) for m in (block.get("measures") or [])}
        txt = _inflect_measure(text, addr_count, software)
        key = _norm_measure(txt)
        if key in existing:
            continue
        existing.add(key)
        block.setdefault("measures", []).append(
            {"text": txt, "source": "extra", "measure_id": None})


def _strip_cve(text: str) -> str:
    return re.sub(r",?\s*CVE[-\s]*\d{4}[-\s]*\d+", "", text or "", flags=re.I)


def _short_clause(text: str, limit: int = 260) -> str:
    """Первое смысловое предложение без служебных хвостов «В целях…»/«Для…»."""
    t = " ".join((text or "").split())
    if not t:
        return ""
    t = re.split(r",?\s*В целях\b", t, maxsplit=1, flags=re.I)[0]
    t = re.split(r"\.\s*(?=(?:Для предотвращения|Необходимо|Дополнительно|В целях)\b)",
                 t, maxsplit=1, flags=re.I)[0]
    t = re.split(r"\.\s+(?=[А-ЯЁA-Z«])", t, maxsplit=1)[0]
    t = t.strip().rstrip(".")
    if len(t) > limit:
        t = t[:limit].rsplit(" ", 1)[0].rstrip(".,;:")
    return t


def _malware_from_description(desc: str) -> str:
    for pattern in (_MALWARE_TYPE_RE, _MALWARE_PAREN_RE):
        match = pattern.search(desc)
        if match:
            return " ".join(part for part in match.groups() if part)
    for match in _MALWARE_PAREN_NAME_RE.finditer(desc):
        context = desc[max(0, match.start() - 220):match.start()].lower()
        if not any(word in context for word in ("обеспечен", "впо", "тип", "вредонос")):
            continue
        angle = re.search(r"<[^>]+>", context)
        return (f"{angle.group(0)} " if angle else "") + match.group(1)
    return ""


_BDU_PAREN_RE = re.compile(r"\((BDU[:\s-]*\d{4}[-\s]*\d+[^)]*)\)", re.IGNORECASE)


def _bdu_vulnerability_intro(desc: str) -> str:
    """Build the vulnerability clause from all BDU references in a source block."""
    matches = list(_BDU_PAREN_RE.finditer(desc or ""))
    if not matches:
        return ""
    phrases: list[str] = []
    previous_end = 0
    for match in matches:
        segment = desc[previous_end:match.start()]
        phrase_match = re.search(
            r"эксплуатаци\w*\s+(.+?)\s*$", segment, re.IGNORECASE,
        )
        if not phrase_match:
            previous_end = match.end()
            continue
        phrase = " ".join(phrase_match.group(1).split()).strip(" .,;:")
        if not phrase:
            previous_end = match.end()
            continue
        if phrases and phrase.casefold().startswith("уязвимости "):
            phrase = phrase[len("уязвимости "):]
        phrases.append(f"{phrase} ({match.group(1)})")
        previous_end = match.end()
    if not phrases:
        return ""
    if len(phrases) == 1:
        return ("деятельностью хакерских группировок, реализующих целевые "
                "компьютерные атаки путем эксплуатации " + phrases[0])
    return ("деятельностью хакерских группировок, эксплуатирующих "
            + " и ".join(phrases))


def _template_intro(src: dict) -> str:
    """Единый шаблон вступления для hacker-блоков (максимальное переиспользование).

    Возвращает только часть после «связанных с …»: блок-шаблон сам добавляет
    «В целях предотвращения … связанных с {intro}, приняты следующие меры защиты:».
    """
    desc = " ".join((src.get("description") or "").split())
    bdu_intro = _bdu_vulnerability_intro(desc)
    if bdu_intro:
        return bdu_intro
    group = (" ".join((src.get("group_name") or "").split())
             or _group_from_description(desc))
    theme = " ".join((src.get("theme") or "").split())
    archive = " ".join((src.get("archive_name") or "").split())
    exe = " ".join((src.get("exe_name") or "").split())
    if not archive or not exe:
        from shared.extractor.letter_analyzer import _attachment_fields
        parsed_archive, parsed_exe = _attachment_fields(desc)
        archive = archive or parsed_archive
        exe = exe or parsed_exe
    malware = " ".join((src.get("malware_type") or "").split())
    from shared.extractor.letter_analyzer import _malware_phrase
    parsed_malware = _malware_phrase(desc)
    if parsed_malware and (not malware or len(parsed_malware) > len(malware)):
        malware = parsed_malware
    if not malware:
        malware = _malware_from_description(desc)
    ttype = (src.get("threat_type") or "").strip().lower().replace("-", "_")
    desc_low = desc.lower()
    has_malware = bool(malware) or "вредоносн" in desc_low

    if group:
        g = group if group.startswith("«") else f"«{group}»"
        subject = f"деятельностью хакерской группировки {g}"
        singular = True
    else:
        subject = "деятельностью хакерских группировок"
        singular = False

    if "phish" in ttype:
        kind = "phishing"
    elif "click" in ttype:
        kind = "clickfix"
    elif any(x in ttype for x in ("malware", "trojan", "ransom", "backdoor")):
        kind = "malware"
    elif "vuln" in ttype:
        kind = "vulnerability"
    elif "compromise" in ttype:
        kind = "compromise"
    else:
        if "фишинг" in desc_low:
            kind = "phishing"
        elif "clickfix" in desc_low:
            kind = "clickfix"
        elif has_malware:
            kind = "malware"
        elif "эксплуатац" in desc_low:
            kind = "vulnerability"
        elif "компрометац" in desc_low:
            kind = "compromise"
        else:
            kind = "other"
    if kind == "compromise" and has_malware:
        kind = "malware"

    block_number = int(src.get("number") or 0)
    phishing_rank = int(src.get("phishing_rank") or 0)
    repeated_phishing = (phishing_rank > 1 if phishing_rank
                         else block_number > 1)
    compact_phishing = kind == "phishing" and repeated_phishing
    if kind == "phishing":
        activity = "фишинговые рассылки электронных писем"
        if compact_phishing and theme:
            activity += f" с тематикой «{theme}»"
        verb = "осуществляющей" if singular else "осуществляющих"
    elif kind == "clickfix":
        activity = "атаки с использованием метода «ClickFix»"
        verb = "осуществляющей" if singular else "осуществляющих"
    elif kind == "vulnerability":
        m = re.search(r"эксплуатаци[яи]\s+(.+)$", desc)
        rest = _strip_cve(_short_clause(m.group(1))) if m else ""
        activity = ("эксплуатацию " + rest if rest
                    else "эксплуатацию уязвимостей программного обеспечения")
        verb = "осуществляющей" if singular else "осуществляющих"
    elif kind == "malware":
        m = re.search(
            r"вредоносн\w*\s+программн\w*\s+обеспечени\w*\s+(?:типов|типа)\s+"
            r"(.+?)(?:\.\s+(?:[А-ЯЁA-Z]|$)|\.$|$)",
            desc, re.I)
        mt = _short_clause(m.group(1), 180) if m else malware
        if "эксплуатац" in desc_low and not mt:
            m2 = re.search(r"эксплуатаци[яи]\s+(.+)$", desc)
            rest = _strip_cve(_short_clause(m2.group(1))) if m2 else ""
            activity = ("целевые компьютерные атаки путем эксплуатации " + rest if rest
                        else "целевые компьютерные атаки")
        else:
            activity = ("целевые компьютерные атаки с применением вредоносного "
                        "программного обеспечения")
            if mt:
                plural = ("," in mt or " и " in mt or mt.lower().startswith("типов"))
                activity += " " + ("типов " if plural else "типа ") + mt
        verb = "реализующей" if singular else "реализующих"
    elif kind == "compromise":
        activity = "компрометацию информационных ресурсов"
        verb = "осуществляющей" if singular else "осуществляющих"
    else:
        activity = "целевые компьютерные атаки"
        verb = "реализующей" if singular else "реализующих"

    details = []
    if "\u0441\u0442\u0438\u043b\u0435\u0440" in desc_low and "\u0441\u0442\u0438\u043b\u0435\u0440" not in malware.lower():
        malware = f"{malware} / \u0441\u0442\u0438\u043b\u0435\u0440" if malware else "\u0441\u0442\u0438\u043b\u0435\u0440"
    malware = malware.replace("; ", ", ").strip()
    if theme:
        details.append(f"\u0442\u0435\u043c\u0430 \u2014 \u00ab{theme}\u00bb")
    if archive:
        lower_archive = archive.lower()
        if lower_archive.endswith(".lnk"):
            details.append(f"вложением является файл-ярлык «{archive}»")
        elif lower_archive.endswith((".7z", ".zip", ".rar", ".r11", ".r14",
                                     ".tar", ".gz", ".bz2")):
            attachment = f"вложением является архив «{archive}»"
            if exe and exe != archive:
                if exe.startswith("."):
                    attachment += f", содержащий файл с расширением «{exe}»"
                else:
                    attachment += f", содержащий файл «{exe}»"
            details.append(attachment)
        else:
            attachment = f"вложением является файл «{archive}»"
            if exe and exe != archive:
                if exe.startswith("."):
                    attachment += f", содержащий файл с расширением «{exe}»"
                else:
                    attachment += f", содержащий файл «{exe}»"
            details.append(attachment)
    elif exe:
        if exe.startswith("."):
            number = "расширениями" if "," in exe else "расширением"
            details.append(f"вложением являются файлы с {number} «{exe}»")
        else:
            details.append(f"вложением является файл «{exe}»")
    if malware and kind != "malware":
        if malware.lower().startswith("по "):
            details.append(malware)
        else:
            details.append(f"\u0442\u0438\u043f \u0412\u041f\u041e \u2014 {malware}")
    if compact_phishing:
        details = []
    tail = ("; ".join(details)) if details else ""
    if tail:
        tail = ", " + tail
    return f"{subject}, {verb} {activity}{tail}"


_HEADER_NETWORK_DETAIL_RE = re.compile(
    r"\s*[,;]\s*(?:\u0441\u0435\u0442\u0435\u0432\u043e\u0439|\u0441\u0435\u0442\u0435\u0432\u044b\u0435)"
    r"\s+\u0438\u043d\u0434\u0438\u043a\u0430\u0442\u043e\u0440(?:\u044b)?\s*[:\u2014-]\s*[^;]+",
    re.IGNORECASE,
)


def _strip_header_network_details(text: str) -> str:
    cleaned = _HEADER_NETWORK_DETAIL_RE.sub("", text or "")
    return " ".join(cleaned.split()).rstrip(" ,;")


def _apply_llm_plan(llm_plan: dict | None, lib_by_id: dict, frag_by_key: dict,
                    blocks: list[dict], addr_count: int,
                    library: list[dict] | None = None,
                    letter_number: str = "", letter_type: str = "") -> dict:
    """Нормализация LLM-плана: валидация id/фрагментов + склонение мер."""
    if not llm_plan:
        return None
    core = _core_sorted([m for m in (library or [])
                         if "core" in [t.strip() for t in (m.get("tags") or "").split(",") if t.strip()]])
    built: dict[int, dict] = {}
    by_index = {i: b for i, b in enumerate(blocks)}
    for entry in llm_plan["blocks"] or []:
        if not isinstance(entry, dict):
            continue
        n = entry.get("n")
        if n is None:
            continue
        idx = int(n) - 1
        if idx in built:
            continue
        src = by_index.get(idx)
        if src is None:
            continue
        if (src.get("threat_type") or "").lower() == "vulnerability":
            frag = frag_by_key.get(entry.get("fragment_id") or "") if entry.get("fragment_id") else None
            intro = _render_fragment(frag["template"], _extract_ctx(src)) if frag else ""
            if not intro:
                intro = "реализуемыми угрозами безопасности информации"
            frag_key = frag["key"] if frag and intro else ""
        elif _llm_intro_priority_enabled():
            frag = frag_by_key.get(entry.get("fragment_id") or "") if entry.get("fragment_id") else None
            intro = _render_fragment(frag["template"], _extract_ctx(src)) if frag else ""
            if not intro:
                intro = _template_intro(src)
            frag_key = frag["key"] if frag and intro else ""
        else:
            intro = _template_intro(src)
            frag_key = ""
        measures = []
        seen = set()
        sw = (src.get("software") or "").strip()
        for mid in entry.get("measure_ids") or []:
            m = lib_by_id.get(int(mid)) if isinstance(mid, int) else lib_by_id.get(str(mid))
            if not m or m["text"] in seen:
                continue
            seen.add(m["text"])
            measures.append({"text": _inflect_measure(m["text"], addr_count, sw),
                             "source": "library", "measure_id": m["id"]})
        new_measures = []
        for nm in entry.get("new_measures") or []:
            if not isinstance(nm, dict):
                continue
            text = (nm.get("text") or "").strip()
            if not text or text in seen or text.lower() in {x["text"].lower() for x in measures}:
                continue
            if len(text) > 300:
                continue
            seen.add(text)
            new_measures.append({"text": _inflect_measure(text, addr_count, sw),
                                 "source": "new", "note": (nm.get("note") or "")[:300]})
            measures.append({"text": _inflect_measure(text, addr_count, sw),
                             "source": "new", "measure_id": None})
        if src.get("threat_type") == "vulnerability":
            # Для писем-уязвимостей: только базовые/«vulnerability» меры, максимум 2,
            # чтобы не раздувать письмо (модель любит назначить все 10 мер сразу).
            kept, kept_ids = [], set()
            for mm in measures:
                srcm = lib_by_id.get(mm.get("measure_id"))
                tags = (srcm or {}).get("tags") or []
                if mm["source"] == "new" or (srcm or {}).get("threat_type") == "vulnerability" \
                        or "base" in tags:
                    kept.append(mm)
                    kept_ids.add(mm.get("measure_id"))
                if len(kept) >= 2:
                    break
            measures = kept
            new_measures = [nm for nm in new_measures
                            if nm.get("measure_id") in kept_ids or nm["source"] == "new"][:1]
        elif core and letter_type == "hacker" and not _llm_priority_enabled():
            # Hacker-письма: распределение мер как в эталонах (полный core для
            # фишинговых блоков и сокращённый набор для повторов), а не полный
            # core в каждом блоке. Иначе модель раздувает письмо повторами.
            reference_plan = _reference_measure_plan(blocks, library, addr_count)
            if reference_plan and idx < len(reference_plan):
                measures = reference_plan[idx]
                new_measures = []
            else:
                seen_core = {_norm_measure(m["text"]) for m in measures}
                merged = []
                for m in core:
                    txt = _inflect_measure(m["text"], addr_count, sw)
                    key = _norm_measure(txt)
                    if key in seen_core:
                        continue
                    seen_core.add(key)
                    merged.append({"text": txt, "source": "library", "measure_id": m.get("id")})
                measures = merged
        elif core:
            # Для остальных типов сохраняем прежнее поведение: ядро библиотеки
            # добавляется к выбору модели без дублей.
            seen_core = {_norm_measure(m["text"]) for m in measures}
            merged = []
            for m in core:
                txt = _inflect_measure(m["text"], addr_count, sw)
                key = _norm_measure(txt)
                if key in seen_core:
                    continue
                seen_core.add(key)
                merged.append({"text": txt, "source": "library", "measure_id": m.get("id")})
            measures = merged
        built[idx] = {
            "number": src.get("number") or int(n), "threat_id": src.get("id"),
            "fragment_key": frag_key, "intro": intro, "threat_type": src.get("threat_type", ""),
            "description": src.get("description", ""), "measures": measures,
            "new_measures": new_measures,
            "software": src.get("software", ""),
            "group_name": src.get("group_name", ""), "malware_type": src.get("malware_type", ""),
            "bdu_id": src.get("bdu_id", ""), "cve_id": src.get("cve_id", ""),
            "severity": src.get("severity", ""), "cvss_score": src.get("cvss_score"),
            "cvss_version": src.get("cvss_version", ""),
            "recommendation": src.get("recommendation", ""),
        }
    for idx, src in by_index.items():
        if idx in built:
            continue
        sw = (src.get("software") or "").strip()
        ttype = src.get("threat_type") or ""
        intro = _template_intro(src)
        if ttype == "vulnerability":
            texts = [m["text"] for m in (library or [])
                     if m.get("threat_type") == "vulnerability"][:2]
        else:
            texts = [m["text"] for m in core][:9]
        measures = [{"text": _inflect_measure(t, addr_count, sw),
                     "source": "library", "measure_id": None} for t in texts]
        built[idx] = {
            "number": src.get("number") or idx + 1, "threat_id": src.get("id"),
            "fragment_key": "", "intro": intro, "threat_type": ttype,
            "description": src.get("description", ""),
            "measures": measures,
            "new_measures": [],
            "software": src.get("software", ""),
            "group_name": src.get("group_name", ""), "malware_type": src.get("malware_type", ""),
            "bdu_id": src.get("bdu_id", ""), "cve_id": src.get("cve_id", ""),
            "severity": src.get("severity", ""), "cvss_score": src.get("cvss_score"),
            "cvss_version": src.get("cvss_version", ""),
            "recommendation": src.get("recommendation", ""),
        }
    out_blocks = [built[i] for i in sorted(built)]
    _append_letter_extras(out_blocks, letter_number, addr_count)
    if not out_blocks:
        return None
    return {"template_key": llm_plan["template_key"], "blocks": out_blocks, "llm": True}


# --- главный планировщик ------------------------------------------------------

def _backfill_empty_blocks(plan: dict, letter_type: str, addr_count: int = 1,
                           library: list[dict] | None = None,
                           letter_number: str = "") -> None:
    """Заполняет fallback-мерами блоки с пустым measures (после LLM-плана)."""
    library = library or []
    core = _core_texts(library)
    plan_blocks = plan.get("blocks") or []
    selected = (_reference_measure_plan(plan_blocks, library, addr_count)
                if letter_type == "hacker" else None)
    minimal_idx = 0
    for idx, blk in enumerate(plan_blocks):
        if blk.get("measures"):
            continue
        if selected is not None and idx < len(selected):
            blk["measures"] = selected[idx]
            blk["new_measures"] = []
            continue
        desc_low = (blk.get("description") or "").lower()
        ttype = blk.get("threat_type") or ""
        if letter_type == "compromise":
            measures = _measures_for_tag(library, "compromise")
        elif ttype != "vulnerability" and core:
            measures = list(core)
        elif ttype == "phishing" or "фишинг" in desc_low:
            measures = _measures_for_tag(library, "phishing")
        else:
            minimal_idx += 1
            measures = _vary_minimal_measures(library, minimal_idx)
        blk["measures"] = [{"text": _inflect_measure(m, addr_count),
                             "source": "library", "measure_id": None} for m in measures]
        blk["new_measures"] = []
    _append_letter_extras(plan.get("blocks") or [], letter_number, addr_count)


async def _llm_plan_async(provider, letter_type: str, blocks: list[dict], library: list[dict],
                          fragments: list[dict]) -> dict | None:
    """Асинхронный twin _llm_plan: один вызов LLM на всё письмо."""
    import asyncio

    fn = getattr(provider, "plan_reply_async", None)
    try:
        if fn is not None:
            raw = await fn(letter_type=letter_type, blocks=blocks,
                           library=library, fragments=fragments)
        else:
            raw = await asyncio.to_thread(
                provider.plan_reply, letter_type=letter_type, blocks=blocks,
                library=library, fragments=fragments)
        decoded = raw or {}
        if not isinstance(decoded, dict) or not isinstance(decoded.get("blocks"), list):
            return None
        return {"template_key": letter_type, "blocks": decoded["blocks"], "llm": True}
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM plan_reply failed: %s", e)
        return None


async def plan_reply_async(*, db, letter_type: str, blocks: list[dict], addr_count: int,
                           use_llm: bool | None = None, letter_number: str = "") -> dict:
    """Асинхронный twin plan_reply(): тот же план, но ожидание vLLM не блокирует
    event loop, поэтому воркер может держать несколько писем в работе одновременно."""
    _refresh_static_caches()
    if letter_type not in {"hacker", "compromise", "vulnerability", "other"}:
        letter_type = "hacker" if blocks else "other"
    library, fragments, _ = load_reply_resources(db)

    llm_plan = None
    if use_llm is None:
        use_llm = _use_llm_for_reply(letter_type, letter_number)
    cache_key = _plan_cache_key(letter_type, blocks, addr_count, letter_number,
                                bool(use_llm), library, fragments)
    cached = _plan_cache_get(cache_key)
    if cached is not None:
        logger.info("plan_reply cache hit")
        return cached
    provider = _plugin_provider() if use_llm is not False else None
    if provider is None:
        logger.warning("LLM-план отключён: провайдер не создан "
                       "(FSTEC_LLM_PROVIDER=%s) — используется шаблонный план", LLM_PROVIDER)
    elif getattr(provider, "kind", None) != "vllm":
        logger.warning("LLM-план отключён: kind=%s, требуется vllm — "
                       "используется шаблонный план", getattr(provider, "kind", None))
    else:
        llm_plan = await _llm_plan_async(provider, letter_type, blocks, library, fragments)

    plan = _finalize_plan(llm_plan, db, letter_type, blocks, addr_count, library, fragments,
                          letter_number=letter_number)
    _plan_cache_put(cache_key, plan)
    return plan


def _finalize_plan(llm_plan: dict | None, db, letter_type: str, blocks: list[dict],
                   addr_count: int, library: list[dict], fragments: list[dict],
                   letter_number: str = "") -> dict:
    """Нормализация плана (LLM → шаблон → backfill) + явные меры. Общая часть
    синхронного и асинхронного plan_reply."""
    frag_by_key = {f["key"]: f for f in fragments}
    lib_by_id = {m["id"]: m for m in library}

    if not blocks and letter_type != "vulnerability":
        override = _load_letter_measures().get((letter_number or "").replace("/", "-"))
        if override:
            measures = [{"text": _inflect_measure(t, addr_count), "source": "library",
                         "measure_id": None} for t in override]
            return {"template_key": "compromise", "llm": False, "blocks": [{
                "number": 1, "threat_id": None, "fragment_key": "", "intro": "",
                "threat_type": "compromise", "description": "", "fixed_header": True,
                "measures": measures, "new_measures": [],
            }]}

    explicit = {}
    from shared.extractor.letter_analyzer import (_build_measure_catalog,
                                                  _expand_measure_refs)
    all_descriptions = "\n".join((b.get("description") or "") for b in (blocks or []))
    measure_catalog = _build_measure_catalog(all_descriptions)
    for b in blocks:
        values = [m.strip() for m in (b.get("explicit_measures") or []) if m.strip()]
        if not values:
            continue
        description = b.get("description") or ""
        if measure_catalog:
            values = _expand_measure_refs(values, description, measure_catalog)
        block_addr_count = len(_address_keys(description)) or addr_count
        prepared: list[str] = []
        seen_measures: set[str] = set()
        for value in values:
            if _explicit_measure_is_fragment(value):
                continue
            canonical = _canonical_source_measure(
                value, block_addr_count, (b.get("software") or "").strip())
            text = (canonical if canonical is not None
                    else _inflect_measure(value, block_addr_count,
                                          (b.get("software") or "").strip()))
            text = " ".join((text or "").split()).strip(" ;.")
            key = text.casefold()
            if text and key not in seen_measures:
                seen_measures.add(key)
                prepared.append(text)
        if prepared:
            explicit[b.get("id")] = prepared

    plan = None
    if llm_plan:
        plan = _apply_llm_plan(llm_plan, lib_by_id, frag_by_key, blocks, addr_count, library,
                               letter_number=letter_number, letter_type=letter_type)
    if plan is None:
        if letter_type == "vulnerability":
            # LLM недоступен/пусто → пустой план, рендер пойдёт по BDU-описаниям (_vuln_paragraph)
            plan = {"template_key": "vulnerability", "blocks": [], "llm": False}
        else:
            plan = _fallback_plan(letter_type, blocks, fragments, addr_count, library,
                                  letter_number=letter_number)

    if letter_type != "vulnerability":
        _backfill_empty_blocks(plan, letter_type, addr_count, library,
                               letter_number=letter_number)

    if explicit and not (_llm_priority_enabled() and plan.get("llm")):
        for blk in plan.get("blocks") or []:
            chosen = explicit.get(blk.get("threat_id"))
            if chosen is None:
                chosen = explicit.get(blk.get("number"))
            if chosen is not None:
                blk["measures"] = [{"text": t, "source": "source", "measure_id": None}
                                   for t in chosen]
                blk["new_measures"] = []
    return plan


def plan_reply(*, db, letter_type: str, blocks: list[dict], addr_count: int,
               use_llm: bool | None = None, letter_number: str = "") -> dict:
    """Точка входа: LLM (если включён/доступен) или детерминированный fallback."""
    _refresh_static_caches()
    if letter_type not in {"hacker", "compromise", "vulnerability", "other"}:
        letter_type = "hacker" if blocks else "other"
    library, fragments, _ = load_reply_resources(db)

    llm_plan = None
    if use_llm is None:
        use_llm = _use_llm_for_reply(letter_type, letter_number)
    cache_key = _plan_cache_key(letter_type, blocks, addr_count, letter_number,
                                bool(use_llm), library, fragments)
    cached = _plan_cache_get(cache_key)
    if cached is not None:
        logger.info("plan_reply cache hit")
        return cached
    provider = _plugin_provider() if use_llm is not False else None
    if provider is None:
        logger.warning("LLM-план отключён: провайдер не создан "
                       "(FSTEC_LLM_PROVIDER=%s) — используется шаблонный план", LLM_PROVIDER)
    elif getattr(provider, "kind", None) != "vllm":
        logger.warning("LLM-план отключён: kind=%s, требуется vllm — "
                       "используется шаблонный план", getattr(provider, "kind", None))
    else:
        llm_plan = _llm_plan(provider, letter_type, blocks, library, fragments)

    plan = _finalize_plan(llm_plan, db, letter_type, blocks, addr_count, library, fragments,
                          letter_number=letter_number)
    _plan_cache_put(cache_key, plan)
    return plan


# --- рендер текста ------------------------------------------------------------

_SEV_RU = {"critical": "критический", "high": "высокий", "medium": "средний",
           "low": "низкий", "unknown": "не определён"}

_NOMINATIVE = (
    ("программного обеспечения", "Программное обеспечение"),
    ("программного средства", "Программное средство"),
    ("программных средств", "Программные средства"),
    ("пакетного менеджера", "Пакетный менеджер"),
    ("операционной системы", "Операционная система"),
    ("операционных систем", "Операционные системы"),
    ("централизованной системы", "Централизованная система"),
    ("почтового сервера", "Почтовый сервер"),
    ("графического", "Графический"),
    ("защитника", "Защитник"),
    ("кроссплатформенного приложения", "Кроссплатформенное приложение"),
    ("веб-интерфейса", "Веб-интерфейс"),
    ("веб-приложения", "Веб-приложение"),
    ("веб-сервера", "Веб-сервер"),
    ("веб-сервер", "Веб-сервер"),
    ("межсетевого экрана", "Межсетевой экран"),
    ("межсетевых экранов", "Межсетевые экраны"),
    ("почтового сервера", "Почтовый сервер"),
    ("сервера", "Сервер"),
    ("серверов", "Серверы"),
    ("библиотеки", "Библиотека"),
    ("библиотек", "Библиотеки"),
    ("пакета", "Пакет"),
    ("пакетов", "Пакеты"),
    ("системы", "Система"),
    ("систем", "Системы"),
    ("компонента", "Компонент"),
    ("компонентов", "Компоненты"),
    ("функции", "Функция"),
    ("функций", "Функции"),
    ("ядра", "Ядро"),
    ("ядер", "Ядра"),
    ("службы", "Служба"),
    ("служб", "Службы"),
    ("утилиты", "Утилита"),
    ("утилит", "Утилиты"),
    ("редактора", "Редактор"),
    ("редакторов", "Редакторы"),
    ("платформы", "Платформа"),
    ("платформ", "Платформы"),
    ("приложения", "Приложение"),
    ("приложений", "Приложения"),
    ("средства", "Средство"),
    ("средств", "Средства"),
    ("модуля", "Модуль"),
    ("модулей", "Модули"),
    ("расширения", "Расширение"),
    ("расширений", "Расширения"),
    ("набора", "Набор"),
    ("наборов", "Наборы"),
    ("класса", "Класс"),
    ("метода", "Метод"),
    ("фреймворка", "Фреймворк"),
    ("менеджера", "Менеджер"),
    ("драйвера", "Драйвер"),
    ("контроллера", "Контроллер"),
    ("процесса", "Процесс"),
    ("конфигурации", "Конфигурация"),
    ("инициализации", "Инициализация"),
)
_COMPONENT_PREFIXES = (
    "компонента ", "компонентов ", "функции ", "функций ", "метода ", "методов ",
    "класса ", "классов ", "модуля ", "модулей ", "драйвера ", "драйверов ",
    "службы ", "служб ", "файла ", "файлов ", "расширения ", "расширений ",
    "конфигурации ", "подсистемы ", "процесса ", "процессов ", "упаковщика ",
    "декодера ", "механизма ", "библиотеки ", "библиотек ", "пакета ", "пакетов ",
)
_STATUS_PREFIXES = ("управления ", "мониторинга ", "обеспечения ", "построения ",
                    "создания ", "обработки ", "хранения ", "передачи ", "защиты ",
                    "разработки ", "тестирования ", "резервного ", "обнаружения ")


_HEAD_STARTS = (
    "системы ", "платформы ", "приложения ", "фреймворка ", "сервера ",
    "операционной ", "программного ", "программной ", "веб-", "модуля ",
    "службы ", "библиотеки ", "драйвера ", "расширения ", "набора ",
    "класса ", "процесса ", "конфигурации ", "устройства ",
)


def _strip_component_prefix(product: str) -> str:
    low = product.lower()
    for pref in _COMPONENT_PREFIXES:
        if low.startswith(pref):
            rest = product[len(pref):]
            pos = [rest.lower().find(" " + h) for h in _HEAD_STARTS]
            pos = [p for p in pos if p >= 0]
            if pos:
                return rest[min(pos) + 1:]
            return ""
    return product


def _status_subject(software: str, product: str) -> str:
    """Название ПО в именительном падеже для фразы «… не используется»."""
    soft = " ".join((software or "").split()).strip(" .,")
    prod = " ".join((product or "").split()).strip(" .,")
    prod_head = _strip_component_prefix(prod) if prod else ""
    raw = prod_head or soft or "программное обеспечение"
    low = raw.lower()
    for src, dst in _NOMINATIVE:
        if low.startswith(src):
            return (dst + raw[len(src):]).strip()
    if low.startswith(_STATUS_PREFIXES):
        return "Программное средство " + raw
    return raw[:1].upper() + raw[1:] if raw else "Программное обеспечение"



def _has_specific_compensation(text: str) -> bool:
    low = (text or "").lower()
    generic = (
        "использование рекомендаций производителя",
        "обновление программного обеспечения",
        "установка обновлений",
        "обновить по",
        "манипулирование",
        "исчерпание ресурсов",
        "подмена при взаимодействии",
        "нарушение авторизации",
    )
    if not low.strip() or any(marker in low for marker in generic):
        return False
    return bool(re.search(
        r"\b(?:использ|производ|произвест|созда|огранич|настро|осуществ|примен|"
        r"включ|запрет|блокир|установ|обнов|провер|вести|организ|обеспеч|"
        r"задейств|выполн|измен|удал|отключ|перенаправ|регистрац|контрол)",
        low))


def _compensation_items(text: str) -> list[str]:
    items: list[str] = []
    for raw in re.split(r";+|\n+", text or ""):
        item = " ".join(raw.split()).strip(" .,;:")
        item = re.sub(
            r"\s*\.?\s*Использование рекомендаций:?\.?\s*$", "",
            item, flags=re.IGNORECASE).strip(" .,;:")
        if not item:
            continue
        low = item.casefold()
        if low.startswith("использование рекомендаций"):
            continue
        if low in {
            "применены рекомендации производителя",
            "использование рекомендаций производителя",
            "обновление программного обеспечения",
            "установка обновлений",
        }:
            continue
        if item.casefold() not in {existing.casefold() for existing in items}:
            items.append(item)
    for index, item in enumerate(items):
        items[index] = item + ("." if index == len(items) - 1 else ";")
    return items


def _target_update_version(v: dict) -> str:
    for key in ("fixed_version", "target_version"):
        value = " ".join(str(v.get(key) or "").split()).strip(" ,;")
        if value:
            return value
    text = " ".join(str(v.get(key) or "") for key in (
        "action_details", "recommendation", "description"))
    for pattern in (
            r"(?:до|на)\s+верси[ия]\s+([0-9][0-9A-Za-z._-]*)",
            r"(?:обнов\w*|update)\s+до\s+([0-9][0-9A-Za-z._-]*)"):
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).rstrip(".,;")
    return ""


def _vuln_paragraph(v: dict, letter_number: str = "") -> list[str]:
    """Абзац про уязвимость по образцу эталона: описание + один статус/действие."""
    desc = re.sub(r"\s+", " ", (v.get("description") or "")).strip().rstrip(".")
    bdu = _clean_bdu(v.get("bdu_id"))
    sev_key = _clean_severity(v.get("severity"))
    sev = _SEV_RU.get(sev_key, sev_key)
    software = " ".join((v.get("software") or "").split())

    product, tail = "", ""
    m = re.search(r"Уязвимость\s+(.+?)\s+связан\w*\s+с\s+(.+)", desc, re.I)
    if m:
        product = m.group(1).strip().rstrip(",")
        product = re.split(r"\s*\((?:BDU|CVE)\b", product, maxsplit=1, flags=re.I)[0].strip()
        tail = m.group(2).strip().rstrip(",").split(".", 1)[0].strip()
    if not product:
        product = software or "программного обеспечения"
    product = product[:300]

    cvss = _clean_cvss(v.get("cvss_score"))
    cvss_ver = (v.get("cvss_version") or "").strip()
    if not cvss_ver:
        m_cvss = re.search(r"CVSS\s*(\d(?:\.\d)?)", desc, re.I)
        cvss_ver = m_cvss.group(1) if m_cvss else ""
    if not cvss_ver and sev and cvss is not None:
        # BDU-карточки ФСТЭК используют CVSS 3.1; версия в данных отсутствует
        cvss_ver = "3.1"
    parts = [bdu if str(bdu).upper().startswith("BDU") else f"BDU:{bdu}"] if bdu else []
    threat_line = ""
    if sev:
        if cvss_ver:
            threat_line = f"уровень опасности по CVSS {cvss_ver} — {sev}"
        elif cvss is not None:
            threat_line = f"уровень опасности — {sev} (базовая оценка по CVSS — {cvss})"
        else:
            threat_line = f"уровень опасности — {sev}"
    if threat_line:
        parts.append(threat_line)

    info = ", ".join(x for x in parts if x)
    first = f"Уязвимость {product}"
    if info:
        first += f" ({info})"
    if tail:
        first += f", связанная с {tail}."
    else:
        first += "."

    status = ""
    cmdb_match = v.get("cmdb_match")
    not_in_cmdb = cmdb_match is False or str(cmdb_match).strip().lower() in {"false", "0", "no"}
    applicable = v.get("is_applicable")
    applicable_bool = (applicable if isinstance(applicable, bool)
                       else None)
    action = (v.get("action_type") or "").strip().lower()
    compensation = " ".join((v.get("action_details") or v.get("remediation") or "").split())[:1200]
    dlow = desc.lower()
    installed = cmdb_match is True or applicable_bool is True
    if not installed:
        for marker in ("не применяется", "не используется", "не подвержена"):
            if marker in dlow:
                status = _not_used_status(_vulnerability_subject(v))
                break
    comp_items = (_compensation_items(compensation)
                  if _has_specific_compensation(compensation) else [])
    show_comp = False
    if not status:
        if installed:
            recommendation = (v.get("recommendation") or "").lower()
            fixed = _target_update_version(v)
            update_unavailable = action == "update" and not fixed
            can_update = (action == "update" and bool(fixed)) or (
                not action and ("обнов" in recommendation or bool(fixed)))
            if action == "verify":
                status = ("Информация о применимости данной уязвимости требует проверки: "
                          "диапазон уязвимых версий и исправленная версия не заданы.")
            elif action == "compensate" or (update_unavailable and comp_items) or (
                    action == "skip" and comp_items):
                if comp_items:
                    if update_unavailable:
                        status = (f"В целях предотвращения возможности реализации данной "
                                  "уязвимости обновление невозможно, приняты следующие "
                                  "компенсирующие меры:")
                    else:
                        status = (f"В целях предотвращения возможности реализации данной "
                                  "уязвимости приняты следующие компенсирующие меры:")
                    show_comp = True
                else:
                    status = (f"В целях предотвращения возможности реализации данной уязвимости "
                              "ведутся работы по реализации компенсирующих мер.")
            elif update_unavailable:
                status = (f"В целях предотвращения возможности реализации данной уязвимости "
                          f"обновление {product} невозможно; требуется реализация "
                          "компенсирующих мер.")
            elif can_update:
                status = (f"В целях предотвращения возможности реализации данной уязвимости "
                          f"ведутся работы по обновлению {product} до "
                          "неуязвимой версии.")
            elif comp_items:
                status = (f"В целях предотвращения возможности реализации данной уязвимости "
                          "приняты следующие компенсирующие меры:")
                show_comp = True
            elif action == "skip" and v.get("current_version"):
                current = " ".join((v.get("current_version") or "").split())
                status = (f"Используемая версия {product} {current} "
                          "не подвержена данной уязвимости.")
            elif not_in_cmdb and action == "skip":
                current = " ".join((v.get("current_version") or "").split())
                status = (f"По <{product}> {current} отсутствует в GLPI (список ПО); "
                          "остальные данные об уязвимости отсутствуют, требуется их проверка.")
            elif not_in_cmdb:
                status = (f"Производится регулярное обновление {product} "
                          "с предварительным тестированием обновлений.")
            elif action == "skip":
                status = ("Используемая версия ПО не подвержена данной уязвимости.")
        elif applicable_bool is False and not_in_cmdb:
            status = _not_used_status(_vulnerability_subject(v))
        elif not_in_cmdb:
            status = _not_used_status(_vulnerability_subject(v))
        elif action == "update" and not _target_update_version(v):
            if comp_items:
                status = (f"В целях предотвращения возможности реализации данной уязвимости "
                          f"обновление {product} невозможно, приняты следующие "
                          "компенсирующие меры:")
                show_comp = True
            else:
                status = (f"В целях предотвращения возможности реализации данной уязвимости "
                          f"обновление {product} невозможно; требуется реализация "
                          "компенсирующих мер.")
        elif action == "update":
            status = ("В целях предотвращения возможности эксплуатации данной уязвимости "
                      f"ведутся работы по обновлению {product} до неуязвимой версии.")
    if not status:
        status = ("В целях предотвращения возможности эксплуатации данной уязвимости "
                  f"ведутся работы по обновлению {product} до неуязвимой версии.")
    result = [f"{first} {status}"]
    if show_comp:
        result.extend(comp_items)
    source_measures = v.get("source_measures") or []
    existing = _norm_measure(" ".join(result))
    for measure in source_measures:
        text = " ".join(str(measure or "").split()).strip(" .,;:")
        if not text:
            continue
        if _norm_measure(text) in existing:
            continue
        text = _inflect_measure(text, 1, product)
        if _norm_measure(text) in existing:
            continue
        result.append("- " + text + ("" if text.endswith((".", ";")) else ";"))
        existing += " " + _norm_measure(text)
    return result



_VULN_SOURCE_MARKER_RE = re.compile(
    r"(в случае невозможности|рекомендуется принять|компенсир|огранич|запрет|"
    r"использовать|настро|обеспеч|минимизир|отключ|сегмент|монитор|"
    r"системы обнаружения|произвести|создать|замкнут|обновить)",
    re.IGNORECASE,
)


def _vulnerability_source_measures(text: str, bdu_id: str) -> list[str]:
    """Извлекает только компенсирующие меры конкретной BDU-уязвимости."""
    if not text or not bdu_id:
        return []
    sections = re.split(r"(?m)(?=^\s*\d+\.\s+)", text)
    section = next((item for item in sections if bdu_id in item), "")
    if not section:
        pos = text.find(bdu_id)
        if pos < 0:
            return []
        section = text[max(0, pos - 1400):pos + 2200]
    flat = re.sub(r"\s+", " ", section.replace("\xa0", " ")).strip()
    sentences = re.split(r"(?<=[.!?;:])\s+", flat)
    blocked = re.compile(
        r"(^\s*(?:\d+\.\s*)?Уязвимост|Эксплуатация уязвимости|Анализ сведений|"
        r"В соответствии с подпунктом|На №|ФСТЭК РОССИИ|"
        r"О мерах по повышению|просим обратить внимание|"
        r"может позволить нарушителю|связанная с)",
        re.IGNORECASE,
    )
    result: list[str] = []
    seen: set[str] = set()
    for sentence in sentences:
        value = " ".join(sentence.split()).strip(" .;:")
        if not value or len(value) < 15:
            continue
        low = value.lower()
        if "http://" in low or "https://" in low or low.startswith("www."):
            continue
        if blocked.search(value) or _measure_has_ioc(value):
            continue
        if not _VULN_SOURCE_MARKER_RE.search(value):
            continue
        if re.search(r"(принять|принимаются)\s+следующие\s+"
                     r"(компенсирующие\s+)?меры\s*:?$", low):
            continue
        if low.endswith(("меры:", "мер:")):
            continue
        if (re.search(r"(рекомендуется|необходимо)\s+(установить|осуществить|"
                      r"обновить)|обновить\s+пакет|установить\s+обновление|"
                      r"обновление\s+программного\s+обеспечения", low)
                and not re.search(r"(в случае невозможности|компенсир|огранич|"
                                  r"запрет|отключ|минимиз|использовать|настро|"
                                  r"сегмент|монитор)", low)):
            continue
        value = re.sub(r"^\d{1,3}\s+(?=[а-яёa-z])", "", value, count=1)
        key = _norm_measure(value)
        if key and key not in seen:
            seen.add(key)
            result.append(value[:1200])
    return result[:8]


def _attach_vulnerability_source_fallbacks(db, doc_id: int, vulns: list[dict]) -> None:
    if not vulns:
        return
    from shared.models import Document

    doc = db.query(Document).filter(Document.id == doc_id).first()
    text = ((doc.all_text if doc else "") or (doc.original_text if doc else "") or "")
    if not text:
        return
    for vuln in vulns:
        action = str(vuln.get("action_type") or "").strip().lower()
        if action not in {"update", "compensate"}:
            continue
        if action == "update" and _target_update_version(vuln):
            continue
        if _has_specific_compensation(
                " ".join((vuln.get("action_details") or vuln.get("remediation") or "").split())):
            continue
        bdu_id = _clean_bdu(vuln.get("bdu_id"))
        if not bdu_id:
            continue
        measures = _vulnerability_source_measures(text, bdu_id)
        if measures:
            vuln["source_measures"] = measures

def _vuln_block_lines(blk: dict, sender: str = "") -> list[str]:
    """Один абзац про уязвимость (как в эталоне), без перечня мер и CVE."""
    return _vuln_paragraph(blk)

def render_reply(*, plan: dict, templates: dict | None = None, letter_number: str = "",
                 letter_date: str = "", org_name: str = ORG_NAME, addr_count: int = 1,
                 active_vulns: list[dict] | None = None,
                 addresses: list[str] | None = None) -> tuple[str, dict]:
    """Рендер ответа из плана (+ блок уязвимостей для vulnerability-писем)."""
    key = plan.get("template_key") or "hacker"
    skel = (templates or {}).get(key) or {}
    if not skel and key != "other":
        key = "other"
        skel = (templates or {}).get("other") or {}
    header = (skel.get("header") or "Ответ на письмо {{num}} от {{date}}").replace(
        "{{num}}", letter_number or "").replace("{{date}}", _norm_date(letter_date) or "")
    intro = (skel.get("intro") or "Сообщаем о принятых мерах по повышению защищенности инфраструктуры {{org}}.").replace(
        "{{org}}", org_name)
    block_tpl = skel.get("block_template") or "{{n}}. В целях предотвращения возможности реализации угроз безопасности информации, связанных с {{intro}}, приняты следующие меры защиты:"

    lines = [header, "", intro]
    key_num = (letter_number or "").replace("/", "-")

    if key == "vulnerability":
        plan_vulns = [b for b in (plan.get("blocks") or [])
                      if b.get("threat_type") == "vulnerability"]
        vulns = active_vulns or plan_vulns
        vulns = [v for v in vulns
                 if v.get("bdu_id") or v.get("cve_id") or v.get("software")]
        if vulns:
            # NVD-дубли уже обогащённой BDU-записи (тот же CVE) не выводим дважды.
            bdu_cves = {_norm_cve_key(v.get("cve_id"))
                        for v in vulns if v.get("bdu_id")}
            vulns = [v for v in vulns
                     if v.get("bdu_id")
                     or _norm_cve_key(v.get("cve_id")) not in bdu_cves]
        if vulns:
            for idx, v in enumerate(vulns, 1):
                parts = _vuln_paragraph(v, key_num)
                if idx > 1:
                    lines.append("")
                lines.append(parts[0])
                lines.extend(parts[1:])
        else:
            lines.append("")
            lines.append(NO_RISK_TEXT_C)
    elif key == "other":
        lines.append("")
        lines.append(skel.get("no_risk_text") or
                     "Сообщаем, что используемое программное обеспечение не подвержено риску, указанному в обращении, и предпринятые меры достаточны для обеспечения защиты информации.")
    else:
        numbered = bool(skel.get("number_blocks", key == "hacker"))
        plan_blocks = list(plan.get("blocks") or [])
        intro_overrides = ({} if (_llm_intro_priority_enabled() and plan.get("llm"))
                           else _load_letter_intros().get(key_num, {}))
        for i, blk in enumerate(plan_blocks, 1):
            intro_phrase = blk.get("intro") or "реализуемыми угрозами безопасности информации"
            if str(i) in intro_overrides:
                intro_phrase = " ".join(intro_overrides[str(i)].split())
            intro_phrase = _strip_header_network_details(intro_phrase)
            if blk.get("fixed_header"):
                override = _load_letter_headers().get((letter_number or "").replace("/", "-"))
                head = override or (skel.get("empty_block_text")
                        or "В целях предотвращения реализации угроз, связанных со случаем компрометации "
                           "(скомпрометированные интернет-ресурсы, веб-сайты и программное обеспечение), "
                           "приняты следующие меры защиты:")
            elif numbered:
                if "{{n}}" in block_tpl:
                    head = block_tpl.replace("{{n}}", str(i)).replace("{{intro}}", intro_phrase)
                else:
                    head = f"{i}. " + block_tpl.replace("{{intro}}", intro_phrase)
            else:
                head = block_tpl.replace("{{n}}", "").replace("{{n}}. ", "").replace("{{intro}}", intro_phrase).strip()
            if blk.get("bdu_header_suffix"):
                suffix = " ".join(str(blk["bdu_header_suffix"]).split())
                head = head.replace("приняты следующие меры защиты:", suffix)
            if i > 1:
                lines.append("")
            lines.append(head)
            sender = ", ".join(addresses[:8]) if addresses else ""
            measure_texts = []
            for m in blk.get("measures") or []:
                t = m['text'].replace("{{sender}}", sender) if sender else m['text']
                t = " ".join(str(t).split()).strip().rstrip(" ;.")
                if t:
                    measure_texts.append(t)
            for j, t in enumerate(measure_texts):
                suffix = "." if j == len(measure_texts) - 1 else ";"
                lines.append(f"- {t}{suffix}")
            compensation_statuses: set[str] = set()
            for compensation in blk.get("bdu_compensations") or []:
                status = " ".join(str(compensation.get("status") or "").split())
                if status:
                    if status not in compensation_statuses:
                        lines.append("")
                        lines.append(status)
                        compensation_statuses.add(status)
                    continue
                header = " ".join(str(compensation.get("header") or "").split())
                items = [
                    " ".join(str(item).split()).strip()
                    for item in (compensation.get("measures") or [])
                    if str(item).strip()
                ]
                if not header or not items:
                    continue
                lines.append("")
                lines.append(header)
                for j, item in enumerate(items):
                    if item.endswith((".", ":", ";")):
                        rendered = item
                    else:
                        rendered = item + ("." if j == len(items) - 1 else ";")
                    lines.append(f"- {rendered}")
        if not plan_blocks:
            lines.append("")
            if any(v.get("cmdb_error") for v in (active_vulns or [])):
                lines.append("Проверка применимости уязвимостей не завершена: CMDB недоступна. Требуется ручная проверка.")
            else:
                lines.append(NO_RISK_TEXT_C)

    # Защита от неразрешённых плейсхолдеров (LLM иногда копирует {{...}} из шаблонов)
    lines = [ln for ln in lines if "{{" not in ln]
    text = "\n".join(lines)
    return text, {"template_key": key, "header": header, "intro": intro}


NO_RISK_TEXT_C = "Сообщаем, что используемое программное обеспечение не подвержено риску, указанному в обращении, и предпринятые меры достаточны для обеспечения защиты информации."


# --- интеграция для worker/gateway --------------------------------------------

def _reply_result(plan: dict, templates: dict | None, letter_number: str, letter_date: str,
                  org_name: str, addr_count: int, active_vulns: list[dict],
                  addresses: list[str] | None) -> dict:
    """Рендер текста/docx + сборка plan_json. Общая часть generate_reply*."""
    if not (_llm_priority_enabled() and plan.get("llm")):
        _apply_letter_measure_plan(plan, letter_number, addr_count)
    _sanitize_plan_measures(plan)
    _remove_empty_measure_blocks(plan)
    text, _meta = render_reply(plan=plan, templates=templates, letter_number=letter_number,
                              letter_date=letter_date, org_name=org_name,
                              addr_count=addr_count, active_vulns=active_vulns or [],
                              addresses=addresses)
    plan_blocks = [
        {
            "number": b.get("number"), "threat_id": b.get("threat_id"), "fragment_key": b.get("fragment_key"),
            "intro": b.get("intro"), "threat_type": b.get("threat_type"),
            "description": (b.get("description") or "")[:500],
            "measures": b.get("measures") or [],
        }
        for b in plan.get("blocks") or []
    ]
    plan_json = json.dumps({"template_key": plan.get("template_key"), "llm": plan.get("llm", False),
                            "blocks": plan_blocks}, ensure_ascii=False)
    return {
        "text": text,
        "plan": plan,
        "plan_json": plan_json,
        "docx": render_reply_docx(text),
        "candidates": [m for b in plan.get("blocks") or [] for m in (b.get("new_measures") or [])],
        "llm_used": bool(plan.get("llm")),
    }


def _plan_inputs(db, doc_id: int, letter_type: str | None, blocks: list[dict] | None,
                 active_vulns: list[dict] | None, letter_number: str, letter_date: str):
    """Достраивает letter_type/number/date из документа и готовит блоки плана."""
    from shared.models import Document
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if doc:
        letter_type = letter_type or doc.letter_type
        letter_number = letter_number or doc.letter_number
        letter_date = letter_date or doc.letter_date
    plan_in = blocks or []
    if (letter_type or "hacker").lower() == "vulnerability" and active_vulns:
        plan_in = _vulns_to_blocks(active_vulns)
    return letter_type, letter_number, letter_date, plan_in


def generate_reply(db, doc_id: int, *, letter_type: str | None = None, blocks: list[dict] | None = None,
                   active_vulns: list[dict] | None = None, addr_count: int = 1,
                   letter_number: str = "", letter_date: str = "", org_name: str = ORG_NAME,
                   use_llm: bool | None = None, addresses: list[str] | None = None) -> dict:
    """Полная генерация: план (LLM/fallback) → текст + docx + план-json + кандидаты."""
    letter_type, letter_number, letter_date, plan_in = _plan_inputs(
        db, doc_id, letter_type, blocks, active_vulns, letter_number, letter_date)
    plan = plan_reply(db=db, letter_type=letter_type or "hacker", blocks=plan_in,
                      addr_count=addr_count, use_llm=use_llm, letter_number=letter_number)
    library = load_reply_resources(db)[0]
    llm_priority = _llm_priority_enabled() and bool(plan.get("llm"))
    if not llm_priority:
        _apply_reference_measure_policy(plan, plan_in, addr_count, library,
                                        letter_type or "hacker", letter_number)
    if _source_measure_policy_enabled() and not llm_priority:
        _apply_global_measure_policy(plan, plan_in, letter_type or "hacker",
                                     library, addr_count)
    _apply_general_measure_policy(plan, plan_in, library, addr_count, letter_number)
    _apply_live_bdu_measures(active_vulns or [])
    _apply_live_bdu_block_measures(plan, plan_in, active_vulns or [])
    if (letter_type or "").lower() == "vulnerability":
        _attach_vulnerability_source_fallbacks(db, doc_id, active_vulns or [])
    _normalize_block_address_forms(plan, plan_in)
    _enforce_network_measure_policy(plan, plan_in)
    _remove_empty_measure_blocks(plan)
    templates = load_reply_resources(db)[2]
    return _reply_result(plan, templates, letter_number, letter_date, org_name,
                         addr_count, active_vulns or [], addresses)


async def generate_reply_async(db, doc_id: int, *, letter_type: str | None = None,
                               blocks: list[dict] | None = None,
                               active_vulns: list[dict] | None = None, addr_count: int = 1,
                               letter_number: str = "", letter_date: str = "",
                               org_name: str = ORG_NAME, use_llm: bool | None = None,
                               addresses: list[str] | None = None) -> dict:
    """Асинхронный twin generate_reply() для воркеров конвейера.

    Отличие ровно одно: план строится через plan_reply_async, поэтому ожидание
    ответа vLLM не блокирует event loop. БД здесь по-прежнему синхронная
    (SQLAlchemy Session) — она работает в потоке обработчика, а конкурентность
    писем обеспечивается шиной и семафором LLM."""
    letter_type, letter_number, letter_date, plan_in = _plan_inputs(
        db, doc_id, letter_type, blocks, active_vulns, letter_number, letter_date)
    plan = await plan_reply_async(db=db, letter_type=letter_type or "hacker", blocks=plan_in,
                                  addr_count=addr_count, use_llm=use_llm,
                                  letter_number=letter_number)
    library = load_reply_resources(db)[0]
    llm_priority = _llm_priority_enabled() and bool(plan.get("llm"))
    if not llm_priority:
        _apply_reference_measure_policy(plan, plan_in, addr_count, library,
                                        letter_type or "hacker", letter_number)
    if _source_measure_policy_enabled() and not llm_priority:
        _apply_global_measure_policy(plan, plan_in, letter_type or "hacker",
                                     library, addr_count)
    _apply_general_measure_policy(plan, plan_in, library, addr_count, letter_number)
    await _apply_live_bdu_measures_async(active_vulns or [])
    await _apply_live_bdu_block_measures_async(plan, plan_in, active_vulns or [])
    if (letter_type or "").lower() == "vulnerability":
        _attach_vulnerability_source_fallbacks(db, doc_id, active_vulns or [])
    _normalize_block_address_forms(plan, plan_in)
    _enforce_network_measure_policy(plan, plan_in)
    _remove_empty_measure_blocks(plan)
    templates = load_reply_resources(db)[2]
    return _reply_result(plan, templates, letter_number, letter_date, org_name,
                         addr_count, active_vulns or [], addresses)


def persist_candidates(db, document_id: int, candidates: list[dict]) -> list[int]:
    from shared.models import MeasureCandidate
    ids = []
    for c in candidates:
        snap = MeasureCandidate(document_id=document_id, threat_id=c.get("threat_id"),
                                text=c["text"], note=c.get("note") or "")
        db.add(snap)
        db.flush()
        ids.append(snap.id)
    return ids


def _obj_attr(obj, name, default=""):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def build_annotated_preview(db, response_plan: dict, threats, addr_count: int = 1) -> list[dict]:
    """Секции предпросмотра с аннотациями мер (source: library|new, candidate_id)."""
    sections = []
    for i, blk in enumerate(response_plan.get("blocks") or [], 1):
        t = threats[i - 1] if i - 1 < len(threats) else None
        measures = [m["text"] for m in blk.get("measures") or []]
        annotations = [{"text": m["text"], "source": m.get("source", "library"),
                        "candidate_id": m.get("candidate_id")} for m in blk.get("measures") or []]
        from shared.generator.reply_preview import _base_measures_for_threat_type, _inflect
        tt = blk.get("threat_type") or ""
        base = _inflect(_base_measures_for_threat_type(db, tt) or [], addr_count)
        measure_options = list(base)
        for m in annotations:
            if m["source"] == "new" and m["text"] not in measure_options:
                measure_options.append(m["text"])
        intro_text = _strip_header_network_details(
            blk.get("intro") or "угрозой безопасности информации")
        if blk.get("fixed_header"):
            head = ("В целях предотвращения реализации угроз, связанных со случаем компрометации "
                    "(скомпрометированные интернет-ресурсы, веб-сайты и программное обеспечение), "
                    "приняты следующие меры защиты:")
        elif len(response_plan.get("blocks") or []) == 1 and not (t and _obj_attr(t, "id")):
            head = f"В целях предотвращения возможности реализации угроз безопасности информации, связанных с {intro_text}, приняты следующие меры защиты:"
        else:
            head = f"{i}. В целях предотвращения возможности реализации угроз безопасности информации, связанных с {intro_text}, приняты следующие меры защиты:"
        sections.append({
            "threat_id": blk.get("threat_id") or _obj_attr(t, "id", 0),
            "number": blk.get("number") or i,
            "prefix": f"{i}. " if len(response_plan.get("blocks") or []) > 1 else "",
            "description": _obj_attr(t, "theme", "") or intro_text,
            "measures": measures,
            "measures_preview": measures,
            "measure_annotations": annotations,
            "measure_options": measure_options,
            "base_measures": base,
            "threat_type": blk.get("threat_type") or "",
            "intro_text": head,
            "section_text": head + "\n" + "\n".join(f"  {m}" for m in measures),
        })
    return sections
