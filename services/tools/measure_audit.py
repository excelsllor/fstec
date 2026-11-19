#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Аудит мер: письмо -> ответ -> эталон, без изменения БД и UI.

По умолчанию использует готовые ответы e2e-run 9b (22 письма),
эталоны quality22_final и исходные PDF. Отчёт сохраняется в
data/quality/measures_audit.json и docs/measures_audit.md.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path

from shared.extractor.letter_analyzer import analyze_letter
from shared.parsers import parse_file

DESKTOP = Path.home() / "Desktop"
DEFAULT_SOURCE_ROOT = DESKTOP / "лгту хуйня"
DEFAULT_PISMA_ROOT = DESKTOP / "письма"
DEFAULT_ETALON_ROOT = DESKTOP / "quality22_final"
DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "quality" / "e2e_runs.db"
DEFAULT_JSON = Path(__file__).resolve().parent.parent / "data" / "quality" / "measures_audit.json"
DEFAULT_MD = Path(__file__).resolve().parent.parent / "docs" / "measures_audit.md"

_WORD_RE = re.compile(r"[а-яёa-z0-9]+", re.IGNORECASE)
_ACTION_RE = re.compile(
    r"(необходим|рекоменд|следует|обеспеч|огранич|установ|осуществ|принят|"
    r"использ|организ|производ|настро|примен|дополнительн|блокир|отключ|"
    r"провер|контрол|монитор|запрет|инструкт)",
    re.IGNORECASE,
)
_HEADER_RE = re.compile(
    r"^(?:ответ на письмо|сообщаем о принятых|выявлены уязвимости|"
    r"сообщаем|доводим|направляем)", re.IGNORECASE,
)


@dataclass
class Candidate:
    text: str
    norm: str = ""
    tokens: set[str] = field(default_factory=set)


def _clean(text: str) -> str:
    text = (text or "").replace("\xa0", " ").replace("ё", "е").replace("Ё", "Е")
    text = re.sub(r"^\s*(?:[-•–—]|\d+(?:\.\d+)*[.)])\s*", "", text)
    return " ".join(text.split()).strip(" .;:")


def _norm(text: str) -> str:
    return " ".join(_WORD_RE.findall((text or "").lower()))


def _tokens(text: str) -> set[str]:
    return set(_WORD_RE.findall((text or "").lower()))


def _candidate(text: str) -> Candidate:
    cleaned = _clean(text)
    return Candidate(cleaned, _norm(cleaned), _tokens(cleaned))


def _source_measures(text: str) -> list[str]:
    """Меры из исходного письма: структурированный extractor + fallback."""
    result: list[str] = []
    info = analyze_letter(text)
    for threat in info.threats:
        for measure in threat.measures or []:
            value = _clean(measure)
            if len(value) >= 15 and value not in result:
                result.append(value)
    if result:
        unique: list[str] = []
        seen: set[str] = set()
        for value in result:
            key = _norm(value)
            if key and key not in seen:
                seen.add(key)
                unique.append(value)
        return unique[:200]

    # PDF/parser fallback: action sentences from the source letter.
    flat = re.sub(r"\s+", " ", text or "")
    blocked = ("\u0424\u0421\u0422\u042d\u041a \u0420\u041e\u0421\u0421\u0418\u0418", "\u0423\u041f\u0420\u0410\u0412\u041b\u0415\u041d\u0418\u0415", "http://mail", "\u041d\u0430 \u2116", "\u041e \u043c\u0435\u0440\u0430\u0445", "\u0421\u0435\u0432\u0430\u0441\u0442\u043e\u043f\u043e\u043b\u044c\u0441\u043a\u0438\u0439", "\u0426\u0435\u043d\u0442\u0440\u0430\u043b\u044c\u043d\u043e\u0433\u043e \u0444\u0435\u0434\u0435\u0440\u0430\u043b\u044c\u043d\u043e\u0433\u043e", "\u0410\u043d\u0430\u043b\u0438\u0437 \u0441\u0432\u0435\u0434\u0435\u043d\u0438\u0439", "\u041f\u0440\u0435\u0434\u0441\u0435\u0434\u0430\u0442\u0435\u043b\u044f\u043c \u041a\u043e\u043c\u0438\u0441\u0441\u0438\u0439", "\u0424\u0415\u0414\u0415\u0420\u0410\u041b\u042c\u041d\u041e\u0419 \u0421\u041b\u0423\u0416\u0411\u042b")
    seen: set[str] = set()
    for sentence in re.split(r"(?<=[.!?;])\s+", flat):
        value = _clean(sentence)
        if not (15 <= len(value) <= 700) or not _ACTION_RE.search(value):
            continue
        if any(marker in value for marker in blocked):
            continue
        key = _norm(value)
        if key and key not in seen:
            seen.add(key)
            result.append(value)
    return result[:200]


def _candidates(text: str, *, etalon: bool) -> list[Candidate]:
    """Кандидаты мер в ответе/эталоне."""
    result: list[Candidate] = []
    lines = (text or "").splitlines()
    indented = [raw for raw in lines if raw.startswith((" ", "\t", "-", "•"))]
    if etalon and indented:
        lines = indented
    for raw in lines:
        if not raw.strip():
            continue
        if not etalon and not raw.startswith((" ", "\t", "-", "•")):
            continue
        line = " ".join(raw.split())
        if len(line) < 15 or _HEADER_RE.search(line):
            continue
        if re.match(r"^\d+\.\s", line) and "мер" not in line.lower():
            continue
        if etalon and not indented and not _ACTION_RE.search(line):
            continue
        candidate = _candidate(line)
        if len(candidate.text) >= 15:
            result.append(candidate)
    return result


def _match(needle: Candidate, candidates: list[Candidate]) -> tuple[float, str]:
    best_score = 0.0
    best_text = ""
    for candidate in candidates:
        if not needle.norm or not candidate.norm:
            continue
        if needle.norm in candidate.norm or candidate.norm in needle.norm:
            score = 1.0
        else:
            coverage = len(needle.tokens & candidate.tokens) / max(1, len(needle.tokens))
            ratio = SequenceMatcher(None, needle.norm, candidate.norm).ratio()
            score = max(coverage, ratio)
        if score > best_score:
            best_score, best_text = score, candidate.text
    return round(best_score, 3), best_text


def _read_pdf(path: Path) -> str:
    try:
        return parse_file(path).text or ""
    except Exception:
        return ""


def _letter_names(etalon_root: Path) -> list[str]:
    return sorted(
        (p.stem for p in etalon_root.glob("9-*.docx")),
        key=lambda value: int(value.split("-", 1)[1]),
    )


def _pdf_for(name: str, source_root: Path, pisma_root: Path) -> Path | None:
    candidates = [
        source_root / f"{name}.pdf",
        pisma_root / name / f"{name}.pdf",
    ]
    return next((path for path in candidates if path.is_file()), None)


def _etalon_for(name: str, etalon_root: Path, pisma_root: Path) -> Path | None:
    primary = etalon_root / f"{name}.docx"
    if primary.is_file():
        return primary
    alt = pisma_root / name / f"Ответ  на письмо {name}.docx"
    return alt if alt.is_file() else None


def _reply_from_db(db_path: Path, name: str) -> str:
    if not db_path.is_file():
        return ""
    with sqlite3.connect(str(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT gr.content
            FROM documents d
            JOIN generated_responses gr ON gr.document_id = d.id
            WHERE d.source_filename = ? OR d.letter_number = ?
            ORDER BY gr.id DESC LIMIT 1
            """,
            (f"{name}.pdf", name.replace("-", "/")),
        ).fetchone()
        return row["content"] if row and row["content"] else ""


def _reply_from_artifacts(name: str) -> str:
    base = Path(__file__).resolve().parent.parent / "data" / "quality" / "e2e" / "9b" / f"doc_{name}"
    path = base / "reply.txt"
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def audit_one(
    name: str,
    *,
    source_root: Path,
    pisma_root: Path,
    etalon_root: Path,
    db_path: Path,
    threshold: float = 0.65,
    reply_map: dict[str, str] | None = None,
) -> dict:
    pdf = _pdf_for(name, source_root, pisma_root)
    etalon_path = _etalon_for(name, etalon_root, pisma_root)
    source_text = _read_pdf(pdf) if pdf else ""
    etalon_text = _read_pdf(etalon_path) if etalon_path else ""
    reply_text = ((reply_map or {}).get(name)
                  or _reply_from_db(db_path, name)
                  or _reply_from_artifacts(name))

    source = [_candidate(x) for x in _source_measures(source_text)]
    response = _candidates(reply_text, etalon=False)
    etalon = _candidates(etalon_text, etalon=True)

    def compare(items: list[Candidate], candidates: list[Candidate]) -> dict:
        matched = []
        missing = []
        weak = []
        for item in items:
            score, candidate = _match(item, candidates)
            row = {"measure": item.text[:500], "score": score,
                   "candidate": candidate[:500]}
            if score >= threshold:
                matched.append(row)
            elif score >= threshold - 0.2:
                weak.append(row)
            else:
                missing.append(row)
        return {"matched": len(matched), "weak": len(weak),
                "missing": len(missing), "rows": matched + weak + missing}

    source_to_response = compare(source, response)
    source_to_etalon = compare(source, etalon)
    response_to_etalon = compare(response, etalon)
    return {
        "id": name,
        "source_pdf": str(pdf) if pdf else "",
        "etalon": str(etalon_path) if etalon_path else "",
        "reply_source": "e2e_runs.db/9b" if _reply_from_db(db_path, name) else "e2e/9b artifacts",
        "source_measures": len(source),
        "response_measures": len(response),
        "etalon_measures": len(etalon),
        "source_to_response": source_to_response,
        "source_to_etalon": source_to_etalon,
        "response_to_etalon": response_to_etalon,
        "status": "ok" if source and source_to_response["missing"] == 0 else "check",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--pisma-root", type=Path, default=DEFAULT_PISMA_ROOT)
    parser.add_argument("--etalon-root", type=Path, default=DEFAULT_ETALON_ROOT)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--md", type=Path, default=DEFAULT_MD)
    parser.add_argument("--threshold", type=float, default=0.65)
    parser.add_argument("--reply-json", type=Path, default=None)
    args = parser.parse_args()

    names = _letter_names(args.etalon_root)
    reply_map: dict[str, str] = {}
    if args.reply_json and args.reply_json.is_file():
        payload = json.loads(args.reply_json.read_text(encoding="utf-8"))
        reply_map = {str(row.get("id") or ""): str(row.get("text") or "")
                     for row in payload.get("rows") or []}
    rows = [
        audit_one(name, source_root=args.source_root, pisma_root=args.pisma_root,
                  etalon_root=args.etalon_root, db_path=args.db, threshold=args.threshold,
                  reply_map=reply_map)
        for name in names
    ]
    payload = {"stage": "measure_audit", "letters": len(rows), "rows": rows}
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")

    lines = [
        "# Аудит мер: письмо → ответ → эталон",
        "",
        f"Проверено писем: **{len(rows)}**. "
        f"Ответы: `{rows[0]['reply_source'] if rows else '-'}`. "
        f"Порог совпадения: **{args.threshold}**.",
        "",
        "| Письмо | В письме | В ответе | В эталоне | Письмо→ответ | Письмо→эталон | Статус |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        a, b = row["source_to_response"], row["source_to_etalon"]
        lines.append(
            f"| {row['id']} | {row['source_measures']} | {row['response_measures']} | "
            f"{row['etalon_measures']} | {a['matched']}/{row['source_measures']} "
            f"(weak {a['weak']}, lost {a['missing']}) | "
            f"{b['matched']}/{row['source_measures']} "
            f"(weak {b['weak']}, lost {b['missing']}) | {row['status']} |"
        )
    lines += ["", "## Потери и слабые совпадения", ""]
    for row in rows:
        for direction, comparison in (("письмо→ответ", row["source_to_response"]),
                                      ("письмо→эталон", row["source_to_etalon"])):
            problematic = [item for item in comparison["rows"]
                           if item["score"] < args.threshold]
            if not problematic:
                continue
            lines.append(f"### {row['id']} — {direction}")
            for item in problematic[:12]:
                lines.append(f"- `{item['score']}` {item['measure'][:400]}")
            if len(problematic) > 12:
                lines.append(f"- … ещё {len(problematic) - 12}")
            lines.append("")
    args.md.parent.mkdir(parents=True, exist_ok=True)
    args.md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    total_source = sum(row["source_measures"] for row in rows)
    total_lost_reply = sum(row["source_to_response"]["missing"] for row in rows)
    total_lost_etalon = sum(row["source_to_etalon"]["missing"] for row in rows)
    print(f"letters={len(rows)} source_measures={total_source} "
          f"lost_in_reply={total_lost_reply} lost_in_etalon={total_lost_etalon}")
    for row in rows:
        a, b = row["source_to_response"], row["source_to_etalon"]
        print(f"{row['id']:6} src={row['source_measures']:3} "
              f"reply={a['matched']:3} weak={a['weak']:2} lost={a['missing']:2} "
              f"etalon={b['matched']:3} weak={b['weak']:2} lost={b['missing']:2} "
              f"[{row['status']}]")
    print(f"JSON: {args.json}")
    print(f"MD:   {args.md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
