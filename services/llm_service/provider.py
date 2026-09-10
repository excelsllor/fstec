"""LLM-провайдеры (ТЗ 2.3). Heuristic — dev/CI/MVP; VLLM — продукция
(Qwen3-14B-Instruct-Q4 на vLLM, OpenAI-совместимый /v1)."""
import logging
import re
from dataclasses import dataclass, field
from enum import Enum

from shared.config import (LLM_PROVIDER, LLM_TIMEOUT_S, VLLM_BASE_URL,
                           VLLM_MAX_TOKENS, VLLM_MODEL, VLLM_TEMPERATURE,
                           VLLM_TOP_P, CHUNK_MAX_TOKENS)

logger = logging.getLogger("fstec.llm")


def _fit(s: str, n: int) -> str:
    """Уплотнённый срез строки для промпта."""
    return re.sub(r"\s+", " ", s or "").strip()[:n]


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


class HeuristicProvider(LLMProvider):
    kind = ProviderKind.HEURISTIC

    def analyze(self, text: str, hint=None) -> LLMResult:
        return LLMResult(classification="other", llm_used=False)


class VLLMProvider(LLMProvider):
    kind = ProviderKind.VLLM

    def __init__(self, base_url: str = VLLM_BASE_URL, model: str = VLLM_MODEL,
                 timeout_s: float | None = None, max_tokens: int | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s if timeout_s is not None else LLM_TIMEOUT_S
        self.max_tokens = max_tokens if max_tokens is not None else VLLM_MAX_TOKENS
        self.last_usage: dict = {}

    @staticmethod
    def _fit_context(text: str) -> str:
        """Обрезаем «голову» документа, чтобы влезть в контекст (LLM-классификация
        по первым абзацам: источник + тип угрозы указываются в начале письма)."""
        budget_chars = int((CHUNK_MAX_TOKENS - VLLM_MAX_TOKENS) * 2.2)  # ~2.2 символа/токен
        if budget_chars <= 0 or len(text) <= budget_chars:
            return text
        head = text[:budget_chars]
        cut = max(head.rfind("\n"), head.rfind(". "), head.rfind(";"), 0)
        return head[:cut] if cut > budget_chars // 2 else head

    def _chat(self, system: str, user: str, max_tokens: int | None = None, fit: bool = True) -> str:
        import json
        import urllib.request

        if fit:
            user = self._fit_context(user)
        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": VLLM_TEMPERATURE,
            "top_p": VLLM_TOP_P,
            "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
            "chat_template_kwargs": {"enable_thinking": False},  # Qwen3: без преамбулы-размышлений
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
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

    _PLAN_SYSTEM = (
        "Ты — эксперт по проектам ответов на письма ФСТЭК (тип «hacker»/«compromise»/«vulnerability»). "
        "Тебе дан тип письма, список угроз, библиотека стандартных мер защиты и реестр intro-фрагментов "
        "«связанных с …». Для КАЖДОГО блока выбери ОДИН подходящий intro-фрагмент (fragment_id из реестра) "
        "и подмножество стандартных мер (measure_ids из библиотеки), уместных для данного типа угрозы "
        "(для фишинга — полный антифишинговый набор, для compromise — журналы+сканирование+базовые, "
        "для прочих атак — базовые). Если стандартной меры нет — предложи свою (text, до 200 символов), "
        "она будет помечена источником new. Не выдумывай id, отсутствующие в списках. "
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
                 "desc": _fit(b.get("description") or "", 400)}
                for i, b in enumerate(blocks)
            ],
        }
        raw = None
        self._usage_tag = "plan_reply"
        try:
            raw = self._chat(self._PLAN_SYSTEM, json.dumps(payload, ensure_ascii=False),
                             max_tokens=1500, fit=False).strip()
        except Exception as exc:
            logger.warning("vLLM plan_reply error: %s", exc)
            return None
        finally:
            self._usage_tag = None
        data = self._parse(raw)
        if not isinstance(data, dict) or not isinstance(data.get("blocks"), list):
            logger.warning("vLLM plan_reply invalid schema")
            return None
        return data


def get_provider() -> LLMProvider:
    if LLM_PROVIDER == ProviderKind.VLLM.value:
        return VLLMProvider()
    return HeuristicProvider()