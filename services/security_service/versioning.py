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
}
_VENDOR_PRODUCT_TOKENS = {
    "microsoft", "cisco", "sap", "fortinet", "oracle", "jetbrains", "adobe",
    "apache", "google", "apple", "red", "hat", "redhat", "ibm", "vmware",
}
_PRODUCT_ALIASES = {
    "cpython": ("python3", "python"),
    "python": ("python3",),
    "python requests": ("python3-requests", "python-requests"),
    "requests": ("python3-requests", "python-requests"),
    "pillow": ("python3-pillow", "python-pillow"),
    "messagepack": ("python3-msgpack", "python-msgpack"),
    "librsvg": ("librsvg2",),
    "cifs": ("cifs-utils",),
    "cifs cifs utils": ("cifs-utils",),
    "curl": ("curl", "libcurl"),
    "go crypto": ("golang",),
    "go": ("golang",),
    "microsoft office": ("office",),
    "office": ("office",),
    "freerdp": ("freerdp",),
    "php": ("php",),
    "openssl": ("openssl",),
    "gitlab": ("gitlab",),
    "system v": ("sysvinit",),
    "openbsd": ("openbsd",),
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


def _product_token_hit(expected: str, actual: str) -> bool:
    if not expected or not actual:
        return False
    if expected == actual:
        return True
    if len(expected) >= 3 and expected in actual:
        return True
    return False


def _product_raw_tokens(value: str) -> list[str]:
    return [token for token in re.split(r"[^0-9A-Za-zА-Яа-яЁё]+", value or "") if token]


def product_search_terms(product: str) -> list[str]:
    raw_tokens = _product_raw_tokens(product)
    latin_raw = [token for token in raw_tokens if _is_latin_token(token)]
    raw_tokens = latin_raw or raw_tokens
    tokens = [token.lower().replace("ё", "е") for token in raw_tokens]
    full = " ".join(tokens)
    selected = [
        raw for raw in raw_tokens
        if raw.lower() not in _GENERIC_PRODUCT_TOKENS
        and raw.lower() not in _VENDOR_PRODUCT_TOKENS
        and len(raw) >= 2
    ] or raw_tokens
    primary: list[str] = []
    aliases: set[str] = set()
    seen: set[str] = set()
    for raw in selected:
        key = raw.lower()
        if key not in seen:
            primary.append(raw)
            seen.add(key)
        aliases.update(_PRODUCT_ALIASES.get(key, ()))
    aliases.update(_PRODUCT_ALIASES.get(full, ()))
    for key, values in _PRODUCT_ALIASES.items():
        if key == full or key in tokens:
            aliases.update(values)
    ordered = primary + sorted(
        (value for value in aliases if value and value.lower() not in seen),
        key=lambda value: (len(value), value.lower()),
    )
    return ordered


def _product_norm(value: str) -> str:
    return " ".join(_product_tokens(value))


def _product_aliases(product: str) -> set[str]:
    full = " ".join(_effective_product_tokens(product))
    return set(_PRODUCT_ALIASES.get(full, ()))



def match_product(inventory_name: str, vuln_software: str | list[str]) -> bool:
    """Сопоставляет имя из инвентаря с продуктом уязвимости по значимым токенам."""
    names = [inventory_name] if isinstance(inventory_name, str) else inventory_name
    targets = [vuln_software] if isinstance(vuln_software, str) else vuln_software
    for name in names:
        candidate_tokens = _product_tokens(name)
        candidate_norm = _product_norm(name)
        if not candidate_norm:
            continue
        for target in targets:
            target_tokens = _product_distinctive_tokens(target)
            if not target_tokens:
                target_tokens = _product_tokens(target)
            target_norm = " ".join(target_tokens)
            if not target_norm:
                continue
            if candidate_norm == target_norm or target_norm in candidate_norm:
                return True
            aliases = _product_aliases(target)
            if any(_product_norm(alias) == candidate_norm
                   or _product_norm(alias) in candidate_norm for alias in aliases):
                return True
            if all(
                any(_product_token_hit(token, actual) for actual in candidate_tokens)
                for token in target_tokens
            ):
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