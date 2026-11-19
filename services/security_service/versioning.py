"""Версионный matching (ТЗ 2.4): нормализация версий, проверка попадания в уязвимый
диапазон, сопоставление по CPE и именам продуктов."""
import re

from security_service.enriched import CpeMatch, RangeSpec

_SEP_RE = re.compile(r"[._\-+ ]+")


def normalize_version(v: str) -> tuple[int, ...] | None:
    """'1.1.1k' / '2.15.0' / '108.0.1462.42' → числовой кортеж (буквенный суффикс отбрасывается)."""
    if not v:
        return None
    parts: list[int] = []
    for token in _SEP_RE.split(v.strip()):
        m = re.match(r"(\d+)", token)
        if m:
            parts.append(int(m.group(1)))
        elif parts:
            break
    return tuple(parts) if parts else None


def compare_versions(a: str, b: str) -> int:
    """-1/0/1; сравниваем числовые компоненты и буквенный суффикс (1.1.1k vs 1.1.1w)."""
    pa, pb = _version_parts(a), _version_parts(b)
    if not pa or not pb:
        return 0
    for (na, sa), (nb, sb) in zip(pa, pb):
        if na != nb:
            return -1 if na < nb else 1
        if sa != sb:
            if not sa:
                return -1
            if not sb:
                return 1
            return -1 if sa < sb else 1
    if len(pa) != len(pb):
        return -1 if len(pa) < len(pb) else 1
    return 0


def _version_parts(v: str) -> list[tuple[int, str]]:
    """Числовые компоненты + буквенный суффикс: 1.1.1k -> (1,''),(1,''),(1,'k')."""
    parts: list[tuple[int, str]] = []
    for token in _SEP_RE.split((v or "").strip()):
        m = re.match(r"(\d+)([A-Za-z][A-Za-z0-9]*)?", token)
        if m:
            parts.append((int(m.group(1)), (m.group(2) or "").lower()))
        elif parts:
            break
    return parts


def in_range(version: str, spec: RangeSpec) -> bool:
    """Версия входит в уязвимый диапазон (>= min [<= max]) по NVD/BDU."""
    t = normalize_version(version)
    if t is None:
        return False
    if spec.min_version:
        cmp_min = compare_versions(version, spec.min_version)
        if cmp_min < 0 or (cmp_min == 0 and not spec.min_inclusive):
            return False
    if spec.max_version:
        cmp_max = compare_versions(version, spec.max_version)
        if cmp_max > 0 or (cmp_max == 0 and not spec.max_inclusive):
            return False
    return True


def _cpe_parts(cpe: str) -> tuple[str, str] | None:
    """'cpe:2.3:a:openssl:openssl:1.1.1k:*...' → (vendor, product) с '*' как 'meant any'."""
    m = re.match(r"cpe:2\.3:[aoh]:([^:]+):([^:]+):", cpe)
    if not m:
        return None
    vendor, product = m.group(1), m.group(2)
    if vendor == "*":
        vendor = ""
    if product == "*":
        product = ""
    return vendor.lower(), product.lower()


def _cpe_has_version(cpe: str) -> bool:
    m = re.match(r"cpe:2\.3:[aoh]:([^:]+):([^:]+):([^:]+)", cpe)
    return bool(m and m.group(3) and m.group(3) != "*")


def match_cpe(vuln_cpes: list[str], item_cpe: str) -> bool:
    """Строгий CPE-матч: одинаковая часть/vendor/product; '*' в vuln CPE = любой."""
    item = _cpe_parts(item_cpe)
    if not item:
        return False
    for cpe in vuln_cpes:
        v = _cpe_parts(cpe)
        if not v:
            continue
        if v == item:
            return True
        # запись уязвимости с '*' по vendor/product покрывает любой инвентарь
        if (not v[0] or not item[0] or v[0] == item[0]) and (not v[1] or not item[1] or v[1] == item[1]):
            ranges_match = _cpe_matches_product(v[0], v[1], item[0], item[1])
            if ranges_match:
                return True
    return False


def _cpe_matches_product(v_vendor: str, v_product: str, i_vendor: str, i_product: str) -> bool:
    vv, vp = v_vendor or "", v_product or ""
    iv, ip = i_vendor or "", i_product or ""
    return (vv == iv or not vv or not iv) and (vp == ip or not vp or not ip)


_GENERIC_PRODUCT_TOKENS = {
    "уязвимость", "уязвимости", "библиотека", "библиотеки", "компонент",
    "компонента", "компоненты", "программное", "обеспечение", "средство",
    "средства", "платформа", "платформы", "приложение", "приложения",
    "модуль", "модуля", "пакет", "пакета", "сервис", "сервиса",
    "http", "https", "vulnerability", "security", "component", "library",
    "extension", "plugin", "module", "package", "software", "system",
    "framework", "application", "project", "the", "and", "for", "with",
    "python", "python2", "python3", "perl", "git",
}
_VENDOR_PRODUCT_TOKENS = {
    "microsoft", "cisco", "sap", "fortinet", "oracle", "jetbrains", "adobe",
    "apache", "google", "apple", "red", "hat", "redhat", "ibm", "vmware",
}
_COMPONENT_PRODUCT_TOKENS = {
    "runner", "update", "updater", "common", "util", "utils",
    "netcat", "library", "libs", "plugin", "extension", "module", "sdk",
    "runtime", "driver", "firmware", "subsystem", "viewer", "tools",
    "kaspersky", "endpoint", "редактор", "конвертер",
}


def _product_tokens(value: str) -> list[str]:
    text = (value or "").lower().replace("ё", "е")
    return [token for token in re.split(r"[^0-9a-zа-я]+", text) if token]


def _is_latin_token(token: str) -> bool:
    return bool(re.fullmatch(r"[0-9A-Za-z]+", token or ""))


def _effective_product_tokens(value: str) -> list[str]:
    tokens = _product_tokens(value)
    latin = [token for token in tokens if _is_latin_token(token)]
    return latin or tokens


def _product_distinctive_tokens(value: str) -> list[str]:
    tokens = _effective_product_tokens(value)
    distinctive = [t for t in tokens if t not in _GENERIC_PRODUCT_TOKENS
                   and t not in _VENDOR_PRODUCT_TOKENS and len(t) >= 2]
    return distinctive or tokens


def _normalize_token(token: str) -> str:
    return re.sub(r"\d+$", "", (token or "").lower().replace("ё", "е"))


def _product_token_hit(expected: str, actual: str) -> bool:
    """Сравнивает токены с учётом пакетных суффиксов (python3 → python)."""
    left = _normalize_token(expected)
    right = _normalize_token(actual)
    if not left or not right:
        return False
    if left == right:
        return True
    return len(right) >= 4 and right in left


def _product_raw_tokens(value: str) -> list[str]:
    return [token for token in re.split(r"[^0-9A-Za-zА-Яа-яЁё]+", value or "") if token]


def product_search_terms(product: str) -> list[str]:
    raw_tokens = _product_raw_tokens(product)
    latin_raw = [token for token in raw_tokens if _is_latin_token(token)]
    raw_tokens = latin_raw or raw_tokens
    selected = [
        raw for raw in raw_tokens
        if raw.lower() not in _GENERIC_PRODUCT_TOKENS
        and raw.lower() not in _VENDOR_PRODUCT_TOKENS
        and len(raw) >= 2
    ] or raw_tokens
    ordered: list[str] = []
    seen: set[str] = set()
    for raw in selected:
        for value in (raw, _normalize_token(raw)):
            key = value.lower()
            if value and key not in seen:
                ordered.append(value)
                seen.add(key)
    return ordered


def _candidate_has_blocking_component(candidate_tokens: list[str],
                                      target_tokens: list[str]) -> bool:
    target_forms = {_normalize_token(token) for token in target_tokens}
    for token in candidate_tokens:
        form = _normalize_token(token)
        if not form or form in target_forms or form in _GENERIC_PRODUCT_TOKENS:
            continue
        if form in _VENDOR_PRODUCT_TOKENS:
            continue
        if form in _COMPONENT_PRODUCT_TOKENS:
            return True
    return False


def _tokens_match_product(candidate_tokens: list[str], target_tokens: list[str]) -> bool:
    if not candidate_tokens or not target_tokens:
        return False
    if _candidate_has_blocking_component(candidate_tokens, target_tokens):
        return False
    return all(any(_product_token_hit(token, actual) for actual in candidate_tokens)
               for token in target_tokens)


_PACKAGING_PREFIXES = {"python", "python2", "python3", "perl"}


def _core_product_tokens(tokens: list[str], *, kind: str) -> list[str]:
    values = [_normalize_token(token) for token in tokens]
    if kind == "library":
        while len(values) > 1 and values[0] in _PACKAGING_PREFIXES:
            values.pop(0)
    elif values and values[0] in _PACKAGING_PREFIXES:
        return []
    generic = _GENERIC_PRODUCT_TOKENS - _PACKAGING_PREFIXES
    return [
        value for value in values
        if value and value not in generic
        and value not in _VENDOR_PRODUCT_TOKENS
    ]


def match_product_strict(inventory_name: str, vuln_software: str,
                         kind: str = "application") -> bool:
    """Строгая проверка GLPI-кандидата с учётом категории продукта.

    Для приложений имя пакета не должно содержать лишних компонентов
    (GitLab Runner, python3-gitlab и т.п.). Для библиотек разрешён только
    языковой префикс пакета (python3-, perl-).
    """
    candidate = _core_product_tokens(_product_tokens(inventory_name), kind=kind)
    target = _core_product_tokens(
        _product_distinctive_tokens(vuln_software) or _product_tokens(vuln_software),
        kind=kind)
    if not candidate or not target:
        return False
    if _candidate_has_blocking_component(candidate, target):
        return False
    if len(candidate) != len(target):
        return False
    return all(
        any(_product_token_hit(left, right) or _product_token_hit(right, left)
            for right in candidate)
        for left in target)


def match_product(inventory_name: str, vuln_software: str | list[str]) -> bool:
    """Сопоставить имя из инвентаря с продуктом уязвимости по нормализованным токенам."""
    names = [inventory_name] if isinstance(inventory_name, str) else inventory_name
    targets = [vuln_software] if isinstance(vuln_software, str) else vuln_software
    for name in names:
        candidate_tokens = _product_tokens(name)
        if not candidate_tokens:
            continue
        for target in targets:
            target_tokens = _product_distinctive_tokens(target)
            if not target_tokens:
                target_tokens = _product_tokens(target)
            if target_tokens and _tokens_match_product(candidate_tokens, target_tokens):
                return True
    return False


def build_range(criteria: str, raw_range: dict | None) -> CpeMatch:
    """Из cpeMatch-узла NVD (versionStart*/versionEnd*) собирает CpeMatch с диапазонами."""
    rr = raw_range or {}
    spec = RangeSpec(
        min_version=rr.get("versionStartIncluding", "") or rr.get("versionStartExcluding", ""),
        min_inclusive=bool(rr.get("versionStartIncluding")),
        max_version=rr.get("versionEndIncluding", "") or rr.get("versionEndExcluding", ""),
        max_inclusive=bool(rr.get("versionEndIncluding")),
    )
    if not spec.is_specified and _cpe_has_version(criteria):
        m = re.match(r"cpe:2\.3:[aoh]:([^:]+):([^:]+):([^:]+)", criteria)
        if m and m.group(3) != "*":
            spec = RangeSpec(min_version=m.group(3), max_version=m.group(3), raw=m.group(3))
    return CpeMatch(criteria=criteria, ranges=[spec])


def vuln_range_hit(version: str, cpe_matches: list[CpeMatch]) -> bool:
    """Версия входит хотя бы в один заданный диапазон CPE-записи (без учёта имени CPE)."""
    for m in cpe_matches:
        for r in m.ranges:
            if r.is_specified and in_range(version, r):
                return True
    return False