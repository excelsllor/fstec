#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Перегенерировать ответы по JSON из export_e2e_payload.py.

Использует текущие настройки LLM/BDU и текущую БД ресурсов, но не создаёт
документы и не изменяет production-данные.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from shared.db import SessionLocal
from shared.generator.templated_reply import generate_reply_async


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    payload = json.loads(args.input.read_text(encoding="utf-8"))
    rows = []

    async def run() -> None:
        import asyncio
        from shared.db import SessionLocal
        from shared.generator.templated_reply import generate_reply_async

        with SessionLocal() as db:
            for row in payload.get("rows") or []:
                name = str(row.get("id") or "")
                try:
                    rep = await generate_reply_async(
                        db, -1,
                        letter_type=row.get("letter_type") or "other",
                        blocks=row.get("blocks") or [],
                        active_vulns=row.get("active_vulns") or [],
                        addr_count=max(1, len(row.get("addresses") or [])),
                        addresses=row.get("addresses") or [],
                        letter_number=row.get("letter_number") or "",
                        letter_date=row.get("letter_date") or "",
                    )
                    rows.append({
                        "id": name,
                        "document_id": row.get("document_id"),
                        "letter_number": row.get("letter_number") or "",
                        "text": rep.get("text") or "",
                        "llm_used": bool(rep.get("llm_used")),
                        "error": "",
                    })
                    print(f"{name}: {len(rep.get('text') or '')} chars", flush=True)
                except Exception as exc:  # noqa: BLE001 - audit keeps partial results
                    rows.append({
                        "id": name,
                        "document_id": row.get("document_id"),
                        "letter_number": row.get("letter_number") or "",
                        "text": "",
                        "llm_used": False,
                        "error": f"{type(exc).__name__}: {exc}",
                    })
                    print(f"{name}: ERROR {type(exc).__name__}: {exc}", flush=True)

    import asyncio
    asyncio.run(run())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps({"stage": "regen_from_payload", "rows": rows}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
