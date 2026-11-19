"""Каталог организационных мер BDU для раздела «База мер».

Фильтр BDU: тип ПО «Операционная система» + способ устранения
«Организационные меры». В списке BDU параметры передаются через GET:
``VulFilterForm[softType]=1``, ``VulFilterForm[vul_elimination]=2`` и ``fl=1``.
Без ``fl=1`` BDU показывает весь список, поэтому он обязателен.
"""
from __future__ import annotations

import asyncio
import html
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from security_service.bdu_client import (
    BDUClient,
    _cvss_from_critu,
    _path_id,
    _severity_from_critu,
)
from security_service.cache import MemoryCache
from shared.config import BDU_API_BASE, BDU_TLS_INSECURE_FALLBACK, BDU_USER_AGENT, DATA_DIR

logger = logging.getLogger("fstec.security.bdu_measures")

BDU_FILTER = {
    "VulFilterForm[softType]": "1",
    "VulFilterForm[vul_elimination]": "2",
}
BDU_LIST_PAGE_SIZE = 100
BDU_CATALOG_PATH = DATA_DIR / "generator" / "bdu_org_measures.json"

_FAMILY_ORDER = ("windows", "linux", "apple", "unix", "network", "other")
FAMILY_LABELS = {
    "windows": "Windows",
    "linux": "Linux",
    "apple": "macOS / iOS",
    "unix": "Unix / BSD",
    "network": "Сетевые ОС",
    "other": "Другие ОС",
}

_MEASURE_TYPE_ORDER = ("monitoring", "access", "configuration", "protection", "other")
MEASURE_TYPE_LABELS = {
    "monitoring": "Мониторинг",
    "access": "Ограничение доступа",
    "configuration": "Настройка",
    "protection": "Защита",
    "other": "Прочее",
}

_LIST_TABLE_RE = re.compile(
    r'<table class="table table-striped table-vuls">(.*?)</table>', re.S | re.I)
_LIST_SUMMARY_RE = re.compile(
    r'<div class="summary[^>]*>.*?(?:из|of)\s*([0-9][0-9\s]*).*?</div>', re.S | re.I)
_LIST_ID_RE = re.compile(r'href="/vul/([0-9]{4}-[0-9]{4,})"')

_NETWORK_OS_MARKERS = (
    "cisco ios", "cisco nx-os", "nx-os", "arista eos", "juniper junos", "junos",
    "fortios", "fortigate", "pan-os", "palo alto", "routeros", "mikrotik",
    "screenos", "comware", "vrp", "ios xe", "ios xr",
)
_LINUX_MARKERS = (
    "linux", "ubuntu", "debian", "red hat", "redhat", "rhel", "centos", "fedora",
    "suse", "astra", "red os", "redos", "ред ос", "редос", "alt linux", "альт", "msvsphere",
    "мсвсфера", "oracle linux", "almalinux", "rocky", "arch linux", "gentoo",
    "calculate linux", "роса", "роsa", "основа", "осон", "sberlinux",
)
_APPLE_MARKERS = ("macos", "mac os", "os x", "ios", "ipados", "tvos", "watchos")
_UNIX_MARKERS = (
    "freebsd", "openbsd", "netbsd", "dragonfly", "solaris", "illumos", "aix",
    "hp-ux", "unixware", "unix",
)

_MEASURE_TYPE_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("monitoring", (
        "мониторинг", "обнаружен", "предотвращен", "siem", "ids", "ips",
        "журнал", "логирован", "аудит", "отслеживан",
    )),
    ("access", (
        "доступ", "аутентификац", "авторизац", "acl", "межсетев", "firewall",
        "брандмауэр", "vpn", "сегмент", "изоляц", "огранич",
    )),
    ("configuration", (
        "настрой", "конфигур", "отключ", "параметр", "реестр", "политик",
        "регламент", "инструкц", "рекомендац",
    )),
    ("protection", (
        "защит", "антивирус", " edr", "edr", "средств", "шифрован", "резерв",
        "контрол целост", "обновлен",
    )),
)


def _normal_lines(text: str) -> list[str]:
    text = html.unescape(re.sub(r"<[^>]+>", " ", text or ""))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines()]
    return [line for line in lines if line]


def _is_url(line: str) -> bool:
    low = line.lower()
    return low.startswith(("http://", "https://", "www.")) or "http://" in low or "https://" in low


def os_family(name: str) -> str:
    low = (name or "").strip().lower()
    if not low:
        return "other"
    if "windows" in low:
        return "windows"
    if any(marker in low for marker in _NETWORK_OS_MARKERS):
        return "network"
    if any(marker in low for marker in _LINUX_MARKERS):
        return "linux"
    if any(marker in low for marker in _APPLE_MARKERS):
        return "apple"
    if any(marker in low for marker in _UNIX_MARKERS):
        return "unix"
    return "other"


def os_families(names: list[str]) -> list[str]:
    found = {os_family(name) for name in names if name}
    return [key for key in _FAMILY_ORDER if key in found] or ["other"]


def _os_names(model: dict[str, Any]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        name = str(value or "").strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)

    for item in model.get("osystems") or []:
        if isinstance(item, dict):
            add((item.get("soft") or {}).get("sft_name"))
    if not names:
        for item in model.get("versions") or []:
            if not isinstance(item, dict):
                continue
            soft = item.get("soft") or {}
            potypes = soft.get("potypes") or []
            if any(str((p or {}).get("tpo_id")) == "1" for p in potypes):
                add(soft.get("sft_name"))
    return names


def _measure_types(text: str) -> list[str]:
    low = (text or "").lower()
    found = {
        key
        for key, markers in _MEASURE_TYPE_RULES
        if any(marker in low for marker in markers)
    }
    return [key for key in _MEASURE_TYPE_ORDER if key in found] or ["other"]


def extract_measure_items(vmer: str) -> tuple[str, list[str]]:
    """Возвращает очищенный текст рекомендаций и список организационных мер.

    BDU хранит рекомендации в ``vul_vmer``. Секция «Компенсирующие меры:»
    содержит готовые меры; если её нет, показываем содержательные строки
    рекомендаций до блока ссылок.
    """
    lines = _normal_lines(vmer)
    if not lines:
        return "", []

    start = next(
        (i for i, line in enumerate(lines) if "компенсирующие меры" in line.lower()),
        None,
    )
    inline_items: list[str] = []
    if start is not None:
        _, _, inline = lines[start].partition(":")
        if inline.strip():
            inline_items.append(inline.strip())
        chunk = lines[start + 1:]
        stop = next(
            (i for i, line in enumerate(chunk)
             if line.lower().startswith("использование рекомендаций")),
            len(chunk),
        )
        chunk = chunk[:stop]
    else:
        stop = next(
            (i for i, line in enumerate(lines)
             if line.lower().startswith("использование рекомендаций")),
            len(lines),
        )
        chunk = lines[:stop]

    text_lines = [line for line in lines if not _is_url(line)]
    measure_text = "\n".join(text_lines)[:6000]

    items: list[str] = []
    seen: set[str] = set()
    for raw in [*inline_items, *chunk]:
        if not raw or _is_url(raw):
            continue
        low = raw.lower()
        if low.startswith(("компенсирующие меры", "использование рекомендаций")):
            continue
        if raw.endswith(":") and len(raw) < 140:
            continue
        text = raw.lstrip("-•–— ").strip()
        if not text or text in seen:
            continue
        if len(text) > 600:
            text = text[:597].rstrip() + "..."
        seen.add(text)
        items.append(text)
    return measure_text, items[:40]


def extract_top_level_measures(vmer: str) -> list[str]:
    """Возвращает только верхнеуровневые пункты компенсирующих мер BDU.

    Вложенные нумерованные шаги (1), 2), ...) в результат не попадают.
    """
    lines = _normal_lines(vmer)
    if not lines:
        return []
    start = next(
        (i for i, line in enumerate(lines) if "компенсирующие меры" in line.lower()),
        None,
    )
    inline: list[str] = []
    if start is None:
        return []
    _, _, inline_text = lines[start].partition(":")
    if inline_text.strip():
        inline.append(inline_text.strip())
    chunk = lines[start + 1:]
    stop = next(
        (i for i, line in enumerate(chunk)
         if line.lower().startswith("использование рекомендаций")),
        len(chunk),
    )
    result = []
    for raw in [*inline, *chunk[:stop]]:
        stripped = raw.lstrip()
        if not stripped or _is_url(stripped):
            continue
        if stripped[:1] not in {"-", "•", "–", "—"}:
            continue
        text = stripped.lstrip("-•–— ").strip()
        if text and text not in result:
            result.append(text)
    return result


def _cve_id(model: dict[str, Any], page: str) -> str:
    for item in model.get("idvals") or []:
        match = re.search(r"CVE-\d{4}-\d{4,7}", str(item))
        if match:
            return match.group(0)
    match = re.search(r"CVE-\d{4}-\d{4,7}", page or "")
    return match.group(0) if match else ""


def _date(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    match = re.search(r"\d{4}-\d{2}-\d{2}", text)
    return match.group(0) if match else ""


def parse_detail(page: str, bdu_id: str) -> dict[str, Any] | None:
    model = BDUClient._extract_vmodel(page)
    if not model:
        return None
    if str(model.get("vul_elimination") or "").strip() != "2":
        return None
    names = _os_names(model)
    if not names:
        return None

    critu = str(model.get("vul_critu") or "")
    cvss_score, cvss_version = _cvss_from_critu(critu)
    path_id = _path_id(bdu_id)
    families = os_families(names)
    return {
        "bdu_id": f"BDU:{path_id}",
        "title": str(model.get("vul_name") or f"BDU:{path_id}")[:600],
        "description": str(model.get("vul_desc") or "")[:2500],
        "severity": _severity_from_critu(critu),
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "cve_id": _cve_id(model, page),
        "published_at": _date(model.get("vul_datv")),
        "updated_at": _date(model.get("vul_upddate")),
        "url": f"https://bdu.fstec.ru/vul/{path_id}",
        "os_names": names,
        "os_families": families,
    }


def parse_list_page(page: str) -> tuple[int | None, list[str]]:
    table = _LIST_TABLE_RE.search(page or "")
    if not table:
        return None, []
    ids = _LIST_ID_RE.findall(table.group(1))
    summary = _LIST_SUMMARY_RE.search(page or "")
    total = None
    if summary:
        digits = re.sub(r"\D", "", summary.group(1))
        if digits:
            total = int(digits)
    return total, list(dict.fromkeys(ids))


def _list_params(page: int) -> dict[str, str]:
    return {
        **BDU_FILTER,
        "fl": "1",
        "size": str(BDU_LIST_PAGE_SIZE),
        "page": str(page),
    }


async def _fetch_list_page(client: httpx.AsyncClient, page: int) -> tuple[int | None, list[str]]:
    response = await client.get(f"{BDU_API_BASE.rstrip('/')}/vul", params=_list_params(page))
    response.raise_for_status()
    return parse_list_page(response.text)


async def _collect_ids(client: httpx.AsyncClient) -> tuple[int | None, list[str], list[str]]:
    total, first_ids = await _fetch_list_page(client, 1)
    ids = list(first_ids)
    errors: list[str] = []
    if total and total > len(ids):
        pages = (total + BDU_LIST_PAGE_SIZE - 1) // BDU_LIST_PAGE_SIZE
        for page in range(2, pages + 1):
            try:
                _, page_ids = await _fetch_list_page(client, page)
                ids.extend(page_ids)
            except Exception as exc:  # noqa: BLE001 - build tool keeps partial snapshot
                errors.append(f"page {page}: {type(exc).__name__}: {exc}")
    return total, list(dict.fromkeys(ids)), errors


async def _detail_task(
    bdu_id: str,
    client: BDUClient,
    semaphore: asyncio.Semaphore,
) -> tuple[str, dict[str, Any] | None, str]:
    async with semaphore:
        try:
            page = await client._fetch(f"BDU:{bdu_id}")
            if not page:
                return bdu_id, None, "empty response"
            entry = parse_detail(page, bdu_id)
            return bdu_id, entry, "" if entry else "not OS + organizational"
        except Exception as exc:  # noqa: BLE001 - build tool keeps partial snapshot
            return bdu_id, None, f"{type(exc).__name__}: {exc}"


async def build_catalog(
    *,
    base_url: str = BDU_API_BASE,
    transport: httpx.AsyncBaseTransport | None = None,
    concurrency: int = 4,
) -> dict[str, Any]:
    """Загружает все карточки фильтра и возвращает сериализуемый каталог."""
    verify_values = [True]
    if BDU_TLS_INSECURE_FALLBACK:
        verify_values.append(False)

    last_error: Exception | None = None
    for verify in verify_values:
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(45.0, connect=15.0),
                follow_redirects=True,
                headers={"User-Agent": BDU_USER_AGENT},
                verify=verify,
                transport=transport,
            ) as http:
                total, ids, page_errors = await _collect_ids(http)
                break
        except httpx.TransportError as exc:
            last_error = exc
            if verify and "CERTIFICATE_VERIFY_FAILED" in str(exc):
                continue
            raise
    else:
        raise last_error or RuntimeError("BDU list fetch failed")

    detail_client = BDUClient(cache=MemoryCache(), base_url=base_url, transport=transport)
    semaphore = asyncio.Semaphore(max(1, concurrency))
    results = await asyncio.gather(*(
        _detail_task(bdu_id, detail_client, semaphore) for bdu_id in ids
    ))

    items = [entry for _, entry, _ in results if entry]
    detail_errors = [
        f"{bdu_id}: {error}" for bdu_id, entry, error in results if error and not entry
    ]
    items.sort(key=lambda item: (item["published_at"], item["bdu_id"]), reverse=True)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": f"{BDU_API_BASE.rstrip('/')}/vul",
        "filter": {
            "soft_type": "1",
            "soft_type_label": "Операционная система",
            "vul_elimination": "2",
            "vul_elimination_label": "Организационные меры",
        },
        "bdu_total": total,
        "fetched": len(ids),
        "total": len(items),
        "items": items,
        "errors": page_errors + detail_errors,
    }


def catalog_to_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def write_catalog(path: Path = BDU_CATALOG_PATH, **kwargs: Any) -> Path:
    payload = asyncio.run(build_catalog(**kwargs))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(catalog_to_json(payload), encoding="utf-8")
    return path


_NORMALIZATION_SYSTEM = """Ты — эксперт по безопасности ФСТЭК России.
Преобразуй фрагмент рекомендаций BDU в организационные меры, которые организация
применяет для снижения риска эксплуатации уязвимости.

Требования:
- верни от 1 до 5 самостоятельных мер;
- формулируй от лица организации, в безличной/страдательной форме:
  «используются», «изменены», «ограничены», «применяются», «настроено»;
- не используй повелительное наклонение и слова «необходимо», «следует»,
  «рекомендуется», «требуется»;
- не добавляй URL, команды, версии, названия продуктов и факты, которых нет
  во фрагменте;
- не перечисляй вложенные шаги (1), 2), 3)), пути реестра и технические команды;
- не оставляй фразы «следующим образом», «в случае отсутствия» — формулируй
  только главное действие;
- каждая мера должна быть конкретным организационным или режимным действием;
- если организационных мер во фрагменте нет, верни пустой список.

Ответ строго в JSON: {"measures": ["..."]}.
"""

_NORMALIZATION_SCHEMA = {
    "type": "object",
    "properties": {
        "measures": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 5,
        },
    },
    "required": ["measures"],
}


def _clean_measure_phrase(value: str) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip(" \t-\u2022\u2013\u2014;")
    text = re.sub(r"\s+\u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0438\u043c\s+\u043e\u0431\u0440\u0430\u0437\u043e\u043c\.?.*$", "", text, flags=re.IGNORECASE).strip()
    text = re.sub(r"\s+\u0432\s+\u0441\u043b\u0443\u0447\u0430\u0435\s+\u043e\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0438\u044f.*$", "", text, flags=re.IGNORECASE).strip(" .,;:")
    return text


def _parse_normalized_measures(raw: str) -> list[str]:
    text = (raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.I)
        text = re.sub(r"\s*```$", "", text)
    data: Any = None
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start:end + 1])
            except (TypeError, ValueError):
                data = None
    values = data.get("measures") if isinstance(data, dict) else data
    if not isinstance(values, list):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        measure = re.sub(r"\s+", " ", str(value or "")).strip(" \t-•–—;")
        if not measure or _is_url(measure):
            continue
        measure = re.sub(r"https?://\S+", "", measure).strip()
        if not measure or measure in seen:
            continue
        seen.add(measure)
        result.append(measure[:600])
    return result[:5]


async def normalize_bdu_card(
    bdu_id: str,
    *,
    provider: Any | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Нормализует меры карточки BDU через LLM без сохранения в БД/каталоге."""
    path_id = _path_id(bdu_id)
    if not path_id:
        raise ValueError("Некорректный идентификатор BDU")
    client = BDUClient(cache=MemoryCache(), transport=transport)
    page = await client._fetch(f"BDU:{path_id}")
    if not page:
        raise ValueError("Карточка BDU не найдена")
    model = BDUClient._extract_vmodel(page)
    if not model:
        raise ValueError("Не удалось разобрать карточку BDU")
    measure_text, measure_items = extract_measure_items(str(model.get("vul_vmer") or ""))
    top_items = extract_top_level_measures(str(model.get("vul_vmer") or ""))
    source_items = top_items or measure_items
    source_text = "\n".join(source_items) or measure_text
    source_text = source_text[:6000].strip()
    title = str(model.get("vul_name") or f"BDU:{path_id}")[:500]
    source_url = f"https://bdu.fstec.ru/vul/{path_id}"
    if not source_text:
        return {
            "bdu_id": f"BDU:{path_id}",
            "measures": [],
            "llm_used": False,
            "model": "",
            "source_url": source_url,
            "reason": "в карточке нет текстовых организационных мер",
        }

    fallback = [_clean_measure_phrase(item) for item in source_items]
    fallback = [item for item in fallback if item and not _is_url(item)][:5]
    if provider is None:
        from llm_service.provider import get_provider

        try:
            provider = get_provider()
        except Exception as exc:  # noqa: BLE001 - карточка сама по себе полезна
            logger.warning("BDU LLM provider unavailable for %s: %s", bdu_id, exc)
            return {
                "bdu_id": f"BDU:{path_id}",
                "measures": fallback,
                "llm_used": False,
                "model": "",
                "source_url": source_url,
                "reason": f"LLM unavailable: {exc}",
            }
    if not hasattr(provider, "achat"):
        return {
            "bdu_id": f"BDU:{path_id}",
            "measures": fallback,
            "llm_used": False,
            "model": "",
            "source_url": source_url,
            "reason": "LLM provider has no async normalization",
        }

    try:
        raw = await provider.achat(
            _NORMALIZATION_SYSTEM,
            f"BDU: {path_id}\nНазвание: {title}\nИсходные рекомендации:\n{source_text}",
            max_tokens=700,
            fit=False,
            thinking=False,
            timeout_s=60.0,
            guided_json=_NORMALIZATION_SCHEMA,
        )
    except Exception as exc:  # noqa: BLE001 - оставляем меры карточки как fallback
        logger.warning("BDU LLM normalization failed for %s: %s", bdu_id, exc)
        return {
            "bdu_id": f"BDU:{path_id}",
            "measures": fallback,
            "llm_used": False,
            "model": str(getattr(provider, "model", "") or ""),
            "source_url": source_url,
            "reason": f"LLM fallback: {exc}",
        }

    measures = _parse_normalized_measures(raw)
    return {
        "bdu_id": f"BDU:{path_id}",
        "measures": measures or fallback,
        "llm_used": True,
        "model": str(getattr(provider, "model", "") or ""),
        "source_url": source_url,
        "reason": "" if measures else "ИИ не выделил меры, использован текст карточки",
    }
