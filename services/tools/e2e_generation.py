#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""E2E-генерация (ТЗ 2.5): документ → completed → карточка + ответ по всем 12 письмам.

Цепочка: documents.uploaded → parse → analyze (LLM vllm) → assess (BDU/NVD live)
        → reporting (карточка 2.5.1 + ответ 2.5.2).
Результаты по каждому письму сохраняются в data/quality/e2e/ и check_e2e.json
(+ сравнение ответа с эталоном «Ответ на письмо 9-XX.docx»).
"""
import asyncio
import json
import os
import re
import sys
import tempfile
import time
import difflib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_RESUME = os.environ.get("FSTEC_E2E_DIR")
_TMP = Path(_RESUME) if _RESUME else Path(tempfile.mkdtemp(prefix="fstec_e2e_"))
os.environ["FSTEC_DATA_DIR"] = str(_TMP)
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP / 'e2e.db'}"
os.environ["FSTEC_EVENT_BUS"] = "memory"
os.environ["FSTEC_OCR_ENABLED"] = "false"
os.environ["FSTEC_LLM_PROVIDER"] = "vllm"
os.environ["VLLM_BASE_URL"] = os.environ.get("VLLM_BASE_URL", "http://127.0.0.1:8000/v1")
os.environ["VLLM_MODEL"] = os.environ.get("VLLM_MODEL", "Qwen3-8B")
os.environ["FSTEC_LLM_TIMEOUT_S"] = "600"
os.environ["FSTEC_SECURITY_MODE"] = "live"

from shared.bus import get_event_bus  # noqa: E402
from shared.config import UPLOAD_DIR  # noqa: E402
from shared.db import SessionLocal, init_db  # noqa: E402
from shared.models import Attachment, Document, GeneratedResponse, Report, Threat  # noqa: E402
from shared.parsers import parse_file  # noqa: E402
from shared.worker import register_handlers  # noqa: E402
from ingest_service.worker import handle_uploaded as ingest_handler  # noqa: E402
from llm_service.worker import handle_parsed as llm_handler  # noqa: E402
from security_service.worker import handle_analyzed as security_handler  # noqa: E402
from reporting_service.worker import handle_assessed as reporting_handler  # noqa: E402

init_db()

register_handlers(get_event_bus(), {
    "documents.uploaded": ingest_handler,
    "document.parsed": llm_handler,
    "document.analyzed": security_handler,
    "security.assessed": reporting_handler,
})

MEASURE_KEYWORDS = ["вложени", "открывать", "загружать", "url", "фишинг", "песочниц",
                    "sandbox", "антивирус", "учетных записей", "привилегиями", "домен",
                    "ограничение обращений", "мониторинг", "инструктаж", "сертифицированн"]
WORD = re.compile(r"[а-яёa-z0-9]+")
NORM = re.compile(r"[^а-яёa-z0-9 ]+", re.IGNORECASE | re.UNICODE)


def norm(s):
    return NORM.sub(" ", s.lower())


def tok(s):
    return " ".join(WORD.findall(s.lower()))


def create_doc(pdf_bytes: bytes, filename: str) -> int:
    with SessionLocal() as db:
        doc = Document(source_filename=filename, letter_type="other",
                       status="uploaded", processing_stage="uploaded")
        db.add(doc)
        db.flush()
        fpath = UPLOAD_DIR / f"doc_{doc.id}" / filename
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_bytes(pdf_bytes)
        db.add(Attachment(document_id=doc.id, filename=filename, file_path=str(fpath),
                          file_type=".pdf", parse_status="pending", is_main=True))
        db.commit()
        return doc.id


async def run_chain(doc_id: int):
    bus = get_event_bus()
    await bus.publish("documents.uploaded", str(doc_id),
                      {"document_id": doc_id,
                       "main_file": {"filename": "letter.pdf", "path": "", "size": 0}})


def evaluate(n: str, ref_text: str, ref_alt_text: str = ""):
    row = {}
    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.source_filename == f"{n}.pdf").first()
        threats = db.query(Threat).filter(Threat.document_id == doc.id).order_by(Threat.number).all()
        resp = db.query(GeneratedResponse).filter(GeneratedResponse.document_id == doc.id) \
            .order_by(GeneratedResponse.id.desc()).first()
        rep = db.query(Report).filter(Report.document_id == doc.id).first()
        row = {
            "id": n, "status": doc.status, "stage": doc.processing_stage,
            "letter_type": doc.letter_type, "letter_number": doc.letter_number,
            "letter_date": doc.letter_date, "sla": doc.sla, "routing": doc.routing,
            "n_threats": len(threats),
            "threats": [{"number": t.number, "threat_type": t.threat_type,
                         "theme": t.theme, "group_name": t.group_name} for t in threats],
            "report_file": rep.file_path if rep else None,
            "reply": resp.content if resp else "",
            "reply_chars": len(resp.content) if resp else 0,
        }
    if ref_text and row["reply"]:
        rn, un = norm(ref_text), norm(row["reply"])
        rw = WORD.findall(rn)
        uw = WORD.findall(un)
        ratio = round(difflib.SequenceMatcher(None, uw, rw).ratio(), 3)
        row["ratio"] = ratio
        if ref_alt_text:
            rn2 = norm(ref_alt_text)
            ratio2 = round(difflib.SequenceMatcher(
                None, uw, WORD.findall(rn2)).ratio(), 3)
            row["ratio_alt"] = ratio2
            if ratio2 > ratio:
                rn, ratio = rn2, ratio2
                row["ratio"] = ratio
        row["num_ok"] = bool(row["letter_number"]) and tok(row["letter_number"]) in rn
        date_cands = [tok(row["letter_date"])]
        d = row["letter_date"]
        if d and re.fullmatch(r"\d{4}-\d{2}-\d{2}", d):
            date_cands.append(tok(f"{d[8:10]}.{d[5:7]}.{d[0:4]}"))
        row["date_ok"] = bool(d) and any(c in rn for c in date_cands)
        kw_hit = [k for k in MEASURE_KEYWORDS if k in rn]
        kw_miss = [k for k in kw_hit if k not in un]
        row["kw_overlap"] = f"{len(kw_hit) - len(kw_miss)}/{len(kw_hit)}"
        row["kw_missing"] = kw_miss
        row["reply_has_compromise_measures"] = ("контроль журналов" in row["reply"]) or (
            "внеплановое сканирование" in row["reply"])
        row["reply_sections"] = len(re.findall(r"(?m)^\d+\. В целях предотвращения", row["reply"]))
    return row


def _find_cases(root: Path) -> list[tuple[str, Path, Path, Path]]:
    """Кейсы = папки 9-N либо «рассыпные» 9-N.pdf в корне с эталоном рядом."""
    casedirs = {p.name for p in root.iterdir()
                if p.is_dir() and re.fullmatch(r"9-\d+", p.name)}
    result = []
    for p in root.iterdir():
        if p.is_dir():
            m = re.fullmatch(r"9-\d+", p.name)
            if not m:
                continue
            n = p.name
            pdf = p / f"{n}.pdf"
            ref = p / f"Ответ  на письмо {n}.docx"
        else:
            m = re.fullmatch(r"(9-\d+)\.pdf", p.name)
            if not m or m.group(1) in casedirs:
                continue
            n = m.group(1)
            pdf = p
            ref = root / f"Ответ на письмо {n}.docx"
        if not pdf.is_file():
            continue
        ref_alt = None
        alt = root / f"!Ответ на письмо {n}.docx"
        if not ref.is_file() and alt.is_file():
            ref, ref_alt = alt, ref
        elif alt.is_file():
            ref_alt = alt
        result.append((n, pdf, ref, ref_alt))
    return sorted(result, key=lambda t: int(t[0].split("-")[1]))


def main():
    root = Path(r"C:\Users\artyom\Desktop\лгту хуйня")
    out_dir = ROOT / "data" / "quality" / "e2e"
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = ROOT / "data" / "quality" / "check_e2e.json"
    only = set(sys.argv[1:]) or None
    force = {x for x in os.environ.get("FSTEC_E2E_FORCE", "").split(",") if x}
    cases = _find_cases(root)
    if only:
        cases = [c for c in cases if c[0] in only]
    rows = []
    if report_path.is_file():
        try:
            rows = json.loads(report_path.read_text(encoding="utf-8")).get("rows", [])
        except Exception:
            rows = []
        # Строки для only/force не выкидываем заранее: при abort старые данные остаются
        # в файле и мерджатся в конце (upsert по id при перегенерации).

    total = len(cases)
    for i, (n, pdf, ref, ref_alt) in enumerate(cases):
        remaining = total - i - 1
        print(f"[{i + 1}/{total}] {n} ... (осталось: {remaining})", flush=True)
        ref_text = ""
        if ref.is_file():
            ref_text = parse_file(ref).text or ""
        ref_alt_text = ""
        if ref_alt and ref_alt.is_file():
            ref_alt_text = parse_file(ref_alt).text or ""

        with SessionLocal() as db:
            existing = (db.query(Document).filter(Document.source_filename == f"{n}.pdf")
                        .order_by(Document.id.desc()).first())
            has_reply = bool(existing and db.query(GeneratedResponse)
                             .filter(GeneratedResponse.document_id == existing.id).first())
        if existing and has_reply and n not in force and only is None:
            try:
                row = evaluate(n, ref_text, ref_alt_text)
                row["error"] = None
                row["resumed"] = True
            except Exception as e:
                row = {"id": n, "error": str(e), "resumed": True}
            rows.append(row)
            _save_row(n, row, out_dir, report_path, rows)
            print(f"[{i + 1}/{total}] {n} OK ratio={row.get('ratio')} (осталось: {remaining})",
                  flush=True)
            continue
        if existing:
            with SessionLocal() as db:
                db.delete(existing)
                db.commit()

        try:
            t0 = time.time()
            print(f"[{i + 1}/{total}] {n} запуск перегенерации (осталось: {remaining})", flush=True)
            doc_id = create_doc(pdf.read_bytes(), f"{n}.pdf")
            asyncio.run(asyncio.wait_for(run_chain(doc_id), timeout=1800))
            row = evaluate(n, ref_text, ref_alt_text)
            row["error"] = None
            row["elapsed_s"] = round(time.time() - t0)
        except Exception as e:
            row = {"id": n, "error": str(e)}
        rows.append(row)
        _save_row(n, row, out_dir, report_path, rows)
        print(f"[{i + 1}/{total}] {n} DONE ratio={row.get('ratio')} err={row.get('error')} "
              f"sec={row.get('elapsed_s')} (осталось: {remaining})", flush=True)

    print(f"\nReport: {report_path}")


def _save_row(n, row, out_dir, report_path, rows):
    if row.get("reply"):
        sub = out_dir / f"doc_{n}"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "reply.txt").write_text(row["reply"], encoding="utf-8")
        if row.get("report_file") and Path(row["report_file"]).is_file():
            (sub / "card.docx").write_bytes(Path(row["report_file"]).read_bytes())
    rows[:] = [r for r in rows if r.get("id") != n] + [row]
    report_path.write_text(json.dumps({"stage": "e2e_generation", "rows": rows},
                                      ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()