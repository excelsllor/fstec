#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Перегенерировать ответы для 22 e2e-документов в отдельный JSON.

Запуск выполняется против копии e2e_runs.db, production-БД не меняется.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from shared.db import SessionLocal
from shared.generator.addresses import unique_addresses
from shared.generator.reply_blocks import build_reply_blocks
from shared.generator.templated_reply import generate_reply
from shared.models import Document, IoC, Vulnerability
from shared.vulnerability_payload import vulnerability_payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("/tmp/audit_current_replies.json"))
    parser.add_argument("--use-llm", action="store_true")
    args = parser.parse_args()

    rows = []
    with SessionLocal() as db:
        docs = (db.query(Document)
                .filter(Document.status.in_(("completed", "assessed")))
                .order_by(Document.id).all())
        for doc in docs:
            name = (doc.source_filename or "").removesuffix(".pdf")
            if not name.startswith("9-"):
                continue
            try:
                blocks = build_reply_blocks(db, doc)
                iocs = db.query(IoC).filter(IoC.document_id == doc.id).all()
                addresses = unique_addresses(iocs)
                vulns = [vulnerability_payload(v) for v in
                         db.query(Vulnerability)
                         .filter(Vulnerability.document_id == doc.id)
                         .order_by(Vulnerability.id).all()]
                rep = generate_reply(
                    db, doc.id,
                    letter_type=doc.letter_type,
                    blocks=blocks,
                    active_vulns=vulns,
                    addr_count=max(1, len(addresses)),
                    addresses=addresses,
                    use_llm=True if args.use_llm else None,
                )
                rows.append({
                    "id": name,
                    "document_id": doc.id,
                    "letter_number": doc.letter_number,
                    "letter_type": doc.letter_type,
                    "text": rep["text"],
                    "llm_used": rep.get("llm_used", False),
                    "error": "",
                })
                print(f"{name}: {len(rep['text'])} chars", flush=True)
            except Exception as exc:  # noqa: BLE001 - audit keeps partial results
                rows.append({
                    "id": name,
                    "document_id": doc.id,
                    "letter_number": doc.letter_number,
                    "letter_type": doc.letter_type,
                    "text": "",
                    "llm_used": False,
                    "error": f"{type(exc).__name__}: {exc}",
                })
                print(f"{name}: ERROR {type(exc).__name__}: {exc}", flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps({"stage": "regen_audit_replies", "rows": rows}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
