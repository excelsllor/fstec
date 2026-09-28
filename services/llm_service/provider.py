"""LLM-провайдеры (ТЗ 2.3). Heuristic — dev/CI/MVP; VLLM — продукция
(Qwen3.5-9B на vLLM, OpenAI-совместимый /v1)."""
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from enum import Enum

from shared.config import (LLM_PROVIDER, LLM_TIMEOUT_S, VLLM_BASE_URL,
                           VLLM_MAX_TOKENS, VLLM_MODEL, VLLM_TEMPERATURE,
                           VLLM_TOP_P, CHUNK_MAX_TOKENS, LLM_ENABLE_THINKING,
                           VLLM_THINK_MAX_TOKENS, VLLM_THINK_BUDGET,
                           VLLM_CLASSIFY_MAX_CHARS, VLLM_EXTRACT_IO,
                           VLLM_EXTRACT_MAX_CHARS, VLLM_EXTRACT_MAX_TOKENS)
from shared.extractor.ioc_extractor import INTERNAL_EMAILS, IoCResult, _clean_domain, _valid_domain
from shared.extractor.patterns import (HASH_MD5, HASH_SHA1, HASH_SHA256,
                                       HASH_SHA384, HASH_SHA512, EMAIL_PATTERN)

logger = logging.getLogger("fstec.llm")

_HASH_RE = re.compile(
    r"^(?:" + "|".join(p.pattern for p in (HASH_MD5, HASH_SHA1, HASH_SHA256,
                                           HASH_SHA384, HASH_SHA512)) + r")$",
    re.IGNORECASE)


def _fit(s: str, n: int) -> str:
    """Уплотнённый срез строки для промпта."""
    return re.sub(r"\s+", " ", s or "").strip()[:n]


def _mentions(text: str, value: str) -> bool:
    """Дословное присутствие значения в тексте (допускает обфускацию [.]/(.)/[:]
    и переносы строк/пробелы внутри значения — анти-галлюцинация)."""
    v = value.strip().lower()
    if not v:
        return False
    t = text.lower()
    if v in t:
        return True
    d = (t.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
         .replace("[//]", "//").replace("[/]", "/"))
    if v in d:
        return True
    t_ws = re.sub(r"\s+", "", t)
    v_ws = re.sub(r"\s+", "", v)
    if len(v_ws) >= 8 and v_ws in t_ws:
        return True
    return False


def _norm_ip(value: str) -> str | None:
    s = value.strip()
    try:
        ipaddress.ip_address(s)
        return s.lower()
    except ValueError:
        pass
    # IPv4 с портом (host:port). Обрезать хвост по ':' можно только если
    # остаток не является IPv6 (иначе сломаем валидный адрес вида 2001:db8::1).
    host = s.rsplit(":", 1)[0]
    if ":" in host:
        return None
    try:
        ipaddress.ip_address(host)
        return host.lower()
    except ValueError:
        return None


def _json_chunks(s: str):
    """Генератор кандидатов в JSON: сбалансированный префикс + прогрессивный трим хвоста.

    Модель (Qwen3 и пр.) часто дописывает лишние скобки/текст после закрытия объекта
    («}]}}», «)}» и т.п.) — json.loads такого не принимает. Ищем первый сбалансированный
    объект/массив, не сломав строки и escape-последовательности."""
    import json

    def balanced_prefix(start):
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(s)):
            ch = s[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch in "\"'":
                    in_str = False
            elif ch in "\"'":
                in_str = True
            elif ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
                if depth == 0:
                    return s[start:i + 1]
        return None

    for i, ch in enumerate(s):
        if ch in "{[":
            chunk = balanced_prefix(i)
            if chunk is None:
                continue
            try:
                json.loads(chunk)
            except Exception:
                continue
            yield chunk
            return
    # Fallback: прогрессивно отрезаем хвост у самого длинного фрагмента, начинающегося с '{'.
    i = s.find("{")
    if i < 0:
        return
    for j in range(len(s), i, -1):
        try:
            data = json.loads(s[i:j])
        except Exception:
            continue
        if isinstance(data, dict):
            yield s[i:j]
            return


class ProviderKind(str, Enum):
    HEURISTIC = "heuristic"
    VLLM = "vllm"


@dataclass
class LLMResult:
    classification: str = "other"
    summary: str = ""
    entities: list[dict] = field(default_factory=list)
    threats: list[dict] = field(default_factory=list)
    llm_used: bool = False


class LLMProvider:
    kind: ProviderKind = ProviderKind.HEURISTIC

    def analyze(self, text: str, _hint=None) -> LLMResult:  # noqa: N803
        raise NotImplementedError

    def classify_type(self, text: str) -> str:
        """Тип письма: строго 3 класса (hacker|vulnerability|other), compromise -> hacker.
        Пустая строка — модель недоступна/некорректный ответ (фолбэк на regex)."""
        return ""

    def extract_iocs_llm(self, text: str) -> IoCResult | None:
        """Экстрактивное извлечение IoC моделью после анти-галлюцинации.
        None — модель недоступна (использовать только regex)."""
        return None


class HeuristicProvider(LLMProvider):
    kind = ProviderKind.HEURISTIC

    def analyze(self, text: str, hint=None) -> LLMResult:
        return LLMResult(classification="other", llm_used=False)


class VLLMProvider(LLMProvider):
    kind = ProviderKind.VLLM

    def __init__(self, base_url: str = VLLM_BASE_URL, model: str = VLLM_MODEL,
                 timeout_s: float | None = None, max_tokens: int | None = None,
                 enable_thinking: bool | None = None, think_max_tokens: int | None = None,
                 think_budget: int | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s if timeout_s is not None else LLM_TIMEOUT_S
        self.max_tokens = max_tokens if max_tokens is not None else VLLM_MAX_TOKENS
        self.enable_thinking = LLM_ENABLE_THINKING if enable_thinking is None else enable_thinking
        self.think_max_tokens = think_max_tokens if think_max_tokens is not None else VLLM_THINK_MAX_TOKENS
        self.think_budget = think_budget if think_budget is not None else VLLM_THINK_BUDGET
        self.last_usage: dict = {}

    @property
    def _completion_budget(self) -> int:
        """Бюджет завершения с учётом thinking (reasoning + ответ)."""
        if self.enable_thinking:
            return max(self.max_tokens, self.think_max_tokens)
        return self.max_tokens

    def _fit_context(self, text: str) -> str:
        """Обрезаем «голову» документа, чтобы влезть в контекст (LLM-классификация
        по первым абзацам: источник + тип угрозы указываются в начале письма)."""
        budget_chars = int((CHUNK_MAX_TOKENS - self._completion_budget) * 2.2)
        if budget_chars <= 0 or len(text) <= budget_chars:
            return text
        head = text[:budget_chars]
        cut = max(head.rfind("\n"), head.rfind(". "), head.rfind(";"), 0)
        return head[:cut] if cut > budget_chars // 2 else head

    def _chat(self, system: str, user: str, max_tokens: int | None = None, fit: bool = True,
              thinking: bool | None = None, timeout_s: float | None = None) -> str:
        import json
        import urllib.request

        if fit:
            user = self._fit_context(user)
        effective_max_tokens = max_tokens if max_tokens is not None else self._completion_budget
        enable_thinking = self.enable_thinking if thinking is None else thinking
        tkw = {"enable_thinking": enable_thinking}
        if enable_thinking:
            tkw["thinking_budget"] = self.think_budget
        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": VLLM_TEMPERATURE,
            "top_p": VLLM_TOP_P,
            "max_tokens": effective_max_tokens,
            "chat_template_kwargs": tkw,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout_s if timeout_s is not None else self.timeout_s) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        usage = data.get("usage") or {}
        if usage:
            self.last_usage = usage
            tag = getattr(self, "_usage_tag", None) or "llm"
            logger.info("vllm %s: prompt_tokens=%s completion_tokens=%s (model=%s)",
                        tag, usage.get("prompt_tokens"), usage.get("completion_tokens"),
                        data.get("model") or self.model)
        return data["choices"][0]["message"]["content"] or ""

    _SCHEMA = ("{\"classification\": \"hacker\", \"summary\": \"не более 500 символов\", "
               "\"entities\": [{\"type\": \"organization\", \"value\": \"...\"}]}")
    _VALID_CLASSES = ("hacker", "compromise", "vulnerability", "other")

    def _parse(self, raw: str) -> dict | None:
        import json
        candidates = [raw]
        if raw.startswith("```"):  # допускаем ```json ... ``` от модели
            lines = raw.strip("`").strip().splitlines()
            if lines and lines[0].strip().lower().startswith("json"):
                lines = lines[1:]
            candidates.insert(0, "\n".join(lines).strip())
        # Qwen3 иногда дописывает фигурные/модерные хвосты (]} }  }) или преамбулу —
        # извлекаем первый сбалансированный JSON-объект/массив.
        for cand in candidates:
            for chunk in _json_chunks(cand):
                try:
                    data = json.loads(chunk)
                except Exception:
                    continue
                if isinstance(data, dict):
                    return data
        return None

    def analyze(self, text: str, hint=None) -> LLMResult:
        import json
        out = LLMResult(llm_used=True)
        valid = None
        self._usage_tag = "analyze"
        try:
            for attempt in (0, 1):
                system = (
                    "Ты — подсистема автоматической классификации писем ФСТЭК. "
                    f"Определи тип документа и верни ТОЛЬКО один JSON-объект с ключами: "
                    f"classification (одно значение строго из {','.join(self._VALID_CLASSES)}), "
                    f"summary (краткое содержание письма, до 500 символов), "
                    "entities (массив объектов {\"type\": \"organization|deadline|contact\", \"value\": \"...\"}). "
                    f"Пример: {self._SCHEMA}. Без пояснений и без markdown."
                )
                try:
                    raw = self._chat(system, text).strip()
                except Exception:
                    break
                data = self._parse(raw)
                cls = (data or {}).get("classification", "")
                if cls in self._VALID_CLASSES:
                    valid = data
                    break
                if attempt == 0:
                    system += (" Твой ответ не соответствует схеме: classification обязан быть одним из "
                               f"{','.join(self._VALID_CLASSES)}. Повтори, вернув строго требуемый JSON.")
        finally:
            self._usage_tag = None
        if valid:
            out.classification = str(valid.get("classification", "other"))
            out.summary = str(valid.get("summary", ""))[:500]
            out.entities = [e for e in valid.get("entities", [])
                            if isinstance(e, dict) and e.get("type") in ("organization", "deadline", "contact")
                            and e.get("value")]
        else:
            logger.warning("vLLM analyze failed/invalid schema, fallback to hint: %s", hint)
            if hint:
                out.classification = hint
        return out

    _CLASSIFY_SYSTEM = (
        "Ты — классификатор официальных писем ФСТЭК России. "
        "Определи тип письма: только один из: hacker, vulnerability, other. "
        "hacker — угрозы хакерских группировок, фишинг, вредоносное ПО, "
        "компрометация/фишинговые ресурсы. "
        "vulnerability — сведения о конкретных уязвимостях (BDU, CVE) и меры по их устранению. "
        "other — прочее. "
        'Верни ТОЛЬКО JSON: {"classification": "hacker"|"vulnerability"|"other"}. '
        "Без пояснений и markdown."
    )
    _VALID_LETTER_TYPES = {"hacker", "vulnerability", "other"}

    def classify_type(self, text: str) -> str:
        """Тип письма: строго 3 класса (compromise -> hacker). Голова документа."""
        user = _fit(text, VLLM_CLASSIFY_MAX_CHARS)
        if not user:
            return ""
        self._usage_tag = "classify_type"
        try:
            raw = self._chat(self._CLASSIFY_SYSTEM, user, max_tokens=40,
                             fit=False, thinking=False,
                             timeout_s=max(self.timeout_s, 180)).strip()
            data = self._parse(raw)
            cls = str((data or {}).get("classification", "")).strip().lower()
            if cls == "compromise":
                return "hacker"
            if cls in self._VALID_LETTER_TYPES:
                return cls
            logger.warning("classify_type unexpected schema (raw_head=%r)", raw[:120])
            return ""
        except Exception as exc:
            logger.warning("classify_type error: %s", exc)
            return ""
        finally:
            self._usage_tag = None

    _EXTRACT_SYSTEM = (
        "Ты — модуль извлечения данных из официальных писем ФСТЭК России. "
        "1) Определи тип письма: только один из: hacker, vulnerability, other. "
        "hacker — угрозы хакерских группировок, фишинг, вредоносное ПО, "
        "компрометация/фишинговые ресурсы. "
        "vulnerability — сведения о конкретных уязвимостях (BDU, CVE) и меры по их устранению. "
        "other — прочее. "
        "2) Извлеки IoC: ips (IPv4/IPv6), domains (домены и хосты), hashes (md5/sha1/sha256/sha384/sha512 32-128 hex), "
        "emails (E-mail из письма). "
        "ВЫДЕЛЯЙ ТОЛЬКО значения, которые ДОСЛОВНО ПРИСУТСТВУЮТ в тексте письма. Не перефразируй, "
        "не реконструируй домены из URL, не добавляй ничего от себя. "
        "Один пустой JSON, без пояснений и без обёрток в markdown: "
        '{"classification": "...", "iocs": {"ips": [], "domains": [], "hashes": [], "emails": []}}'
    )

    def extract_iocs_llm(self, text: str) -> IoCResult | None:
        """Извлечение IoC моделью; значения без дословного вхождения в текст
        (и с невалидным форматом) отбрасываются — анти-галлюцинация."""
        if not VLLM_EXTRACT_IO or not text.strip():
            return None
        user = text[:VLLM_EXTRACT_MAX_CHARS]
        self._usage_tag = "extract_iocs"
        try:
            raw = self._chat(self._EXTRACT_SYSTEM, user,
                             max_tokens=VLLM_EXTRACT_MAX_TOKENS,
                             fit=False, thinking=False,
                             timeout_s=max(self.timeout_s, 900)).strip()
            if not raw:
                return None
            obj = self._parse(raw)
        except Exception as exc:
            logger.warning("extract_iocs_llm error: %s", exc)
            return None
        finally:
            self._usage_tag = None
        if not isinstance(obj, dict):
            logger.warning("extract_iocs_llm unexpected raw (len=%s)", len(raw))
            return None
        iocs = obj.get("iocs") or {}
        result = IoCResult()
        seen_ip, seen_ipv6 = set(), set()
        for value in iocs.get("ips") or []:
            raw_v = str(value)
            port = ""
            base = raw_v.strip()
            if ":" in base and _norm_ip(base.split(":", 1)[0]):
                base, port = base.split(":", 1)
                port = ":" + port
            ip = _norm_ip(base)
            if not ip or not _mentions(user, base):
                continue
            key = ip
            if port:
                key = f"{ip}:{port}"
            if ":" in key and key in seen_ipv6:
                continue
            if ":" in key:
                seen_ipv6.add(key)
                result.ipv6.append(key)
            elif key not in seen_ip:
                seen_ip.add(key)
                if key not in result.ips:
                    result.ips.append(key)
        seen_dom = set()
        for value in iocs.get("domains") or []:
            dd = _clean_domain(str(value))
            if (len(dd) >= 4 and _mentions(user, dd) and _valid_domain(dd, obfuscated=False)
                    and dd not in seen_dom):
                seen_dom.add(dd)
                result.domains.append(dd)
        seen_hash = set()
        for value in iocs.get("hashes") or []:
            hh = str(value).strip().lower()
            if _HASH_RE.match(hh) and _mentions(user, hh) and hh not in seen_hash:
                seen_hash.add(hh)
                result.hashes.append(hh)
        seen_mail = set()
        for value in iocs.get("emails") or []:
            ee = str(value).strip().lower()
            if EMAIL_PATTERN.match(ee) and ee not in INTERNAL_EMAILS \
                    and _mentions(user, ee) and ee not in seen_mail:
                seen_mail.add(ee)
                result.emails.append(ee)
        return result

    _PLAN_SYSTEM = (
        "Ты — эксперт по проектам ответов на письма ФСТЭК (тип «hacker»/«compromise»/«vulnerability»). "
        "Тебе дан тип письма, список угроз/уязвимостей, библиотека стандартных мер защиты и реестр "
        "intro-фрагментов «связанных с …». Для КАЖДОГО блока выбери ОДИН подходящий intro-фрагмент "
        "(fragment_id из реестра) и подмножество стандартных мер (measure_ids из библиотеки), уместных "
        "для данного типа угрозы (для фишинга — полный антифишинговый набор, для compromise — "
        "журналы+сканирование+базовые, для прочих атак — базовые). Для писем «vulnerability» каждый "
        "блок — одна уязвимость: выбери intro-фрагмент (или оставь fragment_id пустым) и НЕ БОЛЕЕ 2 "
        "базовых мер; если ПО не используется или уязвимости не подвержено — "
        "measure_ids может быть пустым. Если стандартной меры нет — предложи свою (text, до 200 символов), "
        "она будет помечена источником new. Не выдумывай id, отсутствующие в списках, и не меняй BDU/CVE/CVSS. "
        "Верни ТОЛЬКО один JSON-объект: "
        "{\"blocks\":[{\"n\":1,\"fragment_id\":\"<id>\",\"measure_ids\":[\"<id>\",...],"
        "\"new_measures\":[{\"text\":\"...\",\"note\":\"...\"}]}]}. Без пояснений и без markdown."
    )

    def plan_reply(self, *, letter_type: str, blocks: list[dict], library: list[dict],
                   fragments: list[dict]) -> dict | None:
        """Один вызов на письмо: выбор intro-фрагмента и мер для всех блоков."""
        import json
        payload = {
            "letter_type": letter_type,
            "library": [{"id": m["id"], "type": m["threat_type"], "tags": m["tags"], "text": m["text"]}
                        for m in library],
            "fragments": [{"id": f["key"], "label": f["label"], "template": f["template"]}
                          for f in fragments],
            "blocks": [
                {"n": i + 1, "type": (b.get("threat_type") or "")[:50],
                 "group": (b.get("group_name") or "")[:200], "theme": _fit(b.get("theme") or "", 200),
                 "archive": (b.get("archive_name") or "")[:200], "exe": (b.get("exe_name") or "")[:200],
                 "malware": (b.get("malware_type") or "")[:200],
                 "desc": _fit(b.get("description") or "", 400),
                 "bdu": (b.get("bdu_id") or "")[:50], "cve": (b.get("cve_id") or "")[:50],
                 "severity": (b.get("severity") or "")[:30],
                 "cvss_score": str(b.get("cvss_score") or "")[:10],
                 "cvss_version": (b.get("cvss_version") or "")[:10],
                 "software": (b.get("software") or "")[:150],
                 "recommendation": _fit(b.get("recommendation") or "", 200)}
                for i, b in enumerate(blocks)
            ],
        }
        raw = None
        self._usage_tag = "plan_reply"
        try:
            for attempt in (0, 1):
                sys_msg = self._PLAN_SYSTEM
                if attempt == 1:
                    sys_msg += (". ВНИМАНИЕ: твой предыдущий ответ был некорректным JSON — верни "
                                "ровно один валидный JSON-объект без комментариев.")
                raw = self._chat(sys_msg, json.dumps(payload, ensure_ascii=False),
                                 max_tokens=2048 if not self.enable_thinking else self._completion_budget,
                                 fit=False).strip()
                data = self._parse(raw)
                if isinstance(data, dict) and isinstance(data.get("blocks"), list):
                    return data
        except Exception as exc:
            logger.warning("vLLM plan_reply error: %s", exc)
            return None
        finally:
            self._usage_tag = None
        logger.warning("vLLM plan_reply invalid schema (raw_len=%s, raw_head=%r, raw_tail=%r)",
                       len(raw or ""), (raw or "")[:200], (raw or "")[-200:])
        return None


def get_provider() -> LLMProvider:
    if LLM_PROVIDER == ProviderKind.VLLM.value:
        return VLLMProvider()
    return HeuristicProvider()