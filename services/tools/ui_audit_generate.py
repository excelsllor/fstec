#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сгенерировать 22 ответа через реальный UI/API (upload + reply/generate)."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import httpx

from shared.auth import create_access_token


def _token() -> str:
    return create_access_token({"sub": "admin"})


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _upload(client: httpx.Client, token: str, path: Path) -> dict:
    response = client.post(
        "/upload",
        headers=_auth(token),
        files={"files": (path.name, path.read_bytes(), "application/pdf")},
        timeout=120,
    )
    response.raise_for_status()
    return response.json()


def _wait(client: httpx.Client, token: str, doc_id: int) -> dict:
    deadline = time.time() + 1800
    while time.time() < deadline:
        response = client.get(f"/documents/{doc_id}", headers=_auth(token), timeout=60)
        response.raise_for_status()
        data = response.json()
        stage = str(data.get("processing_stage") or "")
        status = str(data.get("status") or "")
        if stage in {"done", "completed", "failed", "error"} or status in {"completed", "failed", "error"}:
            return data
        time.sleep(5)
    return {"id": doc_id, "status": "timeout", "processing_stage": "timeout"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pdf-dir", type=Path, default=Path("/tmp/quality22"))
    parser.add_argument("--out", type=Path, default=Path("/tmp/ui_audit_replies.json"))
    parser.add_argument("--base-url", default="http://127.0.0.1:8666")
    args = parser.parse_args()

    token = _token()
    rows = []
    with httpx.Client(base_url=args.base_url, verify=False, follow_redirects=True) as client:
        for pdf in sorted(args.pdf_dir.glob("9-*.pdf"), key=lambda p: int(p.stem.split("-")[1])):
            name = pdf.stem
            print(f"{name}: upload", flush=True)
            try:
                uploaded = _upload(client, token, pdf)
                doc_id = int(uploaded["id"])
                doc = _wait(client, token, doc_id)
                status = doc.get("status")
                stage = doc.get("processing_stage")
                print(f"{name}: doc={doc_id} status={status} stage={stage}", flush=True)
                if status != "completed":
                    rows.append({
                        "id": name, "document_id": doc_id,
                        "letter_number": doc.get("letter_number") or "",
                        "letter_type": doc.get("letter_type") or "",
                        "source_filename": pdf.name,
                        "text": "", "response_id": None,
                        "error": f"pipeline {status}/{stage}",
                    })
                    continue
                generated = client.post(
                    "/reply/generate",
                    params={"doc_id": doc_id},
                    headers=_auth(token),
                    timeout=600,
                )
                generated.raise_for_status()
                reply = generated.json()
                rows.append({
                    "id": name,
                    "document_id": doc_id,
                    "letter_number": doc.get("letter_number") or "",
                    "letter_type": doc.get("letter_type") or "",
                    "source_filename": pdf.name,
                    "text": reply.get("text") or "",
                    "response_id": reply.get("id"),
                    "error": "",
                })
                print(f"{name}: reply {reply.get('id')} {len(reply.get('text') or '')} chars", flush=True)
            except Exception as exc:  # noqa: BLE001 - keep partial batch
                rows.append({
                    "id": name,
                    "document_id": None,
                    "letter_number": "",
                    "letter_type": "",
                    "source_filename": pdf.name,
                    "text": "",
                    "response_id": None,
                    "error": f"{type(exc).__name__}: {exc}",
                })
                print(f"{name}: ERROR {type(exc).__name__}: {exc}", flush=True)
    args.out.write_text(
        json.dumps({"stage": "ui_audit_replies", "rows": rows}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
