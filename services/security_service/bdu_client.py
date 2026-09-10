"""Клиент BDU ФСТЭК (bdu.fstec.ru, ТЗ 2.4). Публичного стабильного JSON-API нет.

Живая интеграция (проверено вручную, 2026):
- GET /vul/print/{id} -- серверный рендер страницы уязвимости; 404 для несуществующих id.
  Данные: server-рендер severity/CVE + встроенный JS-объект `v_model = reactive({...})`
  (vul_name, vul_desc, vul_critu с оценками CVSS, vul_link, vul_vmer).
- GET /vul?unid=... и GET /vul/{id} для машинной обработки НЕ годятся: при любом id
  возвращают общий SPA-шаблон, а описание/ПО рендерятся клиентом ({{v_model.*}}).

BDU_API_BASE настраивается: в тестах указывает на фейковый эндпоинт, в проде — bdu.fstec.ru.
Сбой сети/парсинга → graceful None (данные останутся raw из письма, external_errors пополнятся)."""
import html
import json
import logging
import re

import httpx

from security_service.cache import Cache, MemoryCache
from security_service.enriched import EnrichedVuln
from security_service.resilience import retry_async
from security_service.versioning import build_range
from shared.config import BDU_API_BASE, SECURITY_CACHE_TTL_S

logger = logging.getLogger("fstec.security.bdu")


def _path_id(bdu_id: str) -> str:
    """BDU:2021-05969 / bdu:2021-05969 / 2021-05969 -> 2021-05969."""
    raw = (bdu_id or "").strip()
    if ":" in raw:
        raw = raw.rsplit(":", 1)[-1]
    return raw.strip()

_SEVERITY_RU = {
    "критический": "critical",
    "высокий": "high",
    "средний": "medium",
    "низкий": "low",
}
_CPE_RE = re.compile(r"cpe:2\.3:(?:a|o|h):[^\"'<>;,\s]+")
_STANDARD_RE = re.compile(r"(?:организации|идентификаторы?)\s*[:)]?\s*(.*?)(?:<|$)", re.I)
_FIX_HINT_RE = re.compile(r"(устраняе|до|обновл|рекоменд)", re.I)
_VERS_TOKEN_RE = re.compile(r"верси[ияю]{1,3}\s*([A-Za-z0-9][\w.\-]*)", re.I)
_VERSION_RE = re.compile(r"\b(\d+(?:\.\d+){1,4}(?:[A-Za-z][\d]*)?)\b")
_CVSS_RE = re.compile(r"(\d(?:\.\d)?)", re.I)


def _fixed_from_text(text: str) -> str:
    """Версия из фраз вида «до версии 2.17.0» / «устраняется в версии …» / «обновление до версии …»."""
    text = text or ""
    for m in _VERS_TOKEN_RE.finditer(text):
        tail = text[max(0, m.start() - 40): m.start()]
        candidate = m.group(1)
        if _FIX_HINT_RE.search(tail) and re.match(r"^\d", candidate):
            return candidate.rstrip(".,;:()")
    return ""


def _clean_html_fragment(s: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", " ", s or "")).strip()


class BDUClient:
    def __init__(self, cache: Cache | None = None, base_url: str = BDU_API_BASE, transport=None):
        self.cache = cache or MemoryCache()
        self.base_url = base_url.rstrip("/")
        self.transport = transport

    async def _fetch(self, bdu_id: str) -> str | None:
        url = f"{self.base_url}/vul/print/{_path_id(bdu_id)}"
        for verify, label in ((True, "verify"), (False, "verify=False (TLS fallback)")):
            try:
                return await self._fetch_once(url, bdu_id, verify=verify)
            except httpx.TransportError as e:
                if "CERTIFICATE_VERIFY_FAILED" in str(e) and verify:
                    logger.warning("BDU TLS verify failed (%s), retry without verify", e)
                    continue
                raise
        return None

    async def _fetch_once(self, url: str, bdu_id: str, verify: bool) -> str | None:
        kwargs: dict = {"timeout": httpx.Timeout(10.0, connect=5.0), "follow_redirects": True}
        if not verify:
            kwargs["verify"] = False
        if self.transport is not None:
            kwargs["transport"] = self.transport
        async with httpx.AsyncClient(**kwargs) as client:
            resp = await client.get(url, params={"unid": bdu_id})
        if resp.status_code in (404, 500, 502, 503, 504):
            return None
        resp.raise_for_status()
        return resp.text

    @staticmethod
    def _extract_vmodel(page: str) -> dict | None:
        """Достаёт JS-объект `v_model = reactive({...})` и распарсивает его как JSON."""
        i = page.find("v_model = reactive(")
        if i < 0:
            return None
        start = page.find("{", i)
        if start < 0:
            return None
        depth = 0
        j = start
        in_str = False
        esc = False
        while j < len(page):
            ch = page[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if depth != 0:
            return None
        try:
            return json.loads(page[start:j + 1])
        except (ValueError, json.JSONDecodeError) as e:
            logger.warning("BDU: v_model не JSON (%s)", e)
            return None

    @staticmethod
    def parse_page(page: str, bdu_id: str) -> EnrichedVuln | None:
        """Разбор страницы BDU в EnrichedVuln. Возвращает None при неузнаваемой структуре."""
        model = BDUClient._extract_vmodel(page)
        if model:
            obj = _parse_from_model(model, page, _path_id(bdu_id))
            if obj is not None:
                return obj
        return _parse_legacy(page, bdu_id)

    async def get_bdu(self, bdu_id: str) -> EnrichedVuln | None:
        bdu_id = (bdu_id or "").strip()
        if not bdu_id:
            return None
        key = f"bdu:{bdu_id}"
        cached = await self.cache.get(key)
        if cached is not None:
            if not cached:
                return None
            return EnrichedVuln(**{k: cached[k] for k in cached if k in EnrichedVuln.__dataclass_fields__})

        page = await retry_async(self._fetch, bdu_id)
        if not page:
            await self.cache.set(key, None)
            return None
        obj = self.parse_page(page, bdu_id)
        await self.cache.set(key, obj.normalize() if obj else None)
        return obj


def _severity_from_critu(critu: str) -> str:
    low = (critu or "").lower()
    for ru, en in _SEVERITY_RU.items():
        if ru in low:
            return en
    return "unknown"


def _cvss_from_critu(critu: str) -> tuple[float | None, str]:
    """Ищет оценки вида «CVSS 3.1 составляет 10» в тексте уровня опасности. При равных
    оценках предпочитает старшую версию методики (3.x > 2.0)."""
    best = None
    best_ver = ""
    for m in re.finditer(r"CVSS\s*(\d(?:\.\d)?)\s*[^0-9]{0,24}?(\d{1,2}(?:\.\d)?)", critu or "", re.I):
        try:
            score = float(m.group(2))
        except ValueError:
            continue
        cand_ver = m.group(1)
        if (best is None or score > best or
                (score == best and best_ver and float(cand_ver) > float(best_ver))):
            best, best_ver = score, cand_ver
    return best, best_ver


def _parse_from_model(model: dict, page: str, path_id: str) -> EnrichedVuln | None:
    if not isinstance(model, dict):
        return None
    if not (model.get("vul_name") or model.get("vul_desc") or model.get("vul_critu")):
        return None
    critu = str(model.get("vul_critu", "") or "")
    desc = str(model.get("vul_desc", "") or "")
    name = str(model.get("vul_name", "") or "")
    cvss_score, cvss_ver = _cvss_from_critu(critu)
    fixed = _fixed_from_text((model.get("vul_vmer") and str(model["vul_vmer"])) + "\n" + desc)
    refs = [ln.strip() for ln in re.split(r"[\r\n]+", str(model.get("vul_link", "") or ""))
            if ln.strip().startswith(("http://", "https://"))]
    patch = next((u for u in refs if not u.startswith((BDU_API_BASE, "https://bdu.fstec.ru", "http://fstec.ru"))), "")
    cve = ""
    m_cve = re.search(r"CVE-\d{4}-\d{4,7}", page)
    if m_cve:
        cve = m_cve.group(0)
    return EnrichedVuln(
        source="bdu",
        bdu_id=f"BDU:{path_id}",
        title=(name[:500] or f"BDU:{path_id}"),
        description=(desc or critu)[:2000],
        severity=_severity_from_critu(critu),
        cvss_score=cvss_score,
        cvss_version=cvss_ver,
        cve_id=cve,
        cpe_matches=[],
        fixed_version=fixed,
        patch_url=patch,
        references=[{"source": "bdu", "url": u} for u in refs],
    )


def _parse_legacy(page: str, bdu_id: str) -> EnrichedVuln | None:
    """Фолбек для упрощённых серверных страниц без JS-объекта v_model (фикстуры/старый формат)."""
    text = _clean_html_fragment(page)
    if not text.strip():
        return None
    if "уязвимост" not in text.lower():
        return None
    title = re.search(r"<h[12][^>]*>\s*(.*?)\s*</h[12]>", page, re.S | re.I)
    severity_raw = ""
    m = re.search(r"(Критический|Высокий|Средний|Низкий)", page, re.I)
    if m:
        severity_raw = m.group(1)
    cvss_score: float | None = None
    m_cvss = re.search(r"(?:CVSS[^<>]{0,30}?|базовый[^<>]{0,30}?|составляет)\s*(\d(?:\.\d)?)", page, re.I)
    if m_cvss:
        try:
            cvss_score = float(m_cvss.group(1))
        except ValueError:
            cvss_score = None
    cpes = sorted({c for c in _CPE_RE.findall(page)}, key=len, reverse=True)
    fixed = _fixed_from_text(page)
    patches = [u for u in dict.fromkeys(_clean_html_fragment(a) for a in
               re.findall(r'<a[^>]+href="(https?://[^\"]+)"', page))
               if not u.startswith(("https://bdu.fstec.ru", "http://fstec.ru"))]
    return EnrichedVuln(
        source="bdu",
        bdu_id=bdu_id,
        title=title.group(1) if title else bdu_id,
        description=text[:2000],
        severity=_SEVERITY_RU.get(severity_raw.lower(), "unknown"),
        cvss_score=cvss_score,
        cpe_matches=[build_range(c, None) for c in cpes],
        fixed_version=fixed,
        patch_url=patches[0] if patches else "",
        references=[{"source": "bdu", "url": u} for u in patches],
    )