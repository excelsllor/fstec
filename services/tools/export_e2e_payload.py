#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Экспортирует входные данные 22 e2e-документов в JSON для повторной генерации."""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

ADDRESS_TYPES = {"ip", "ipv6", "ip_cidr", "domain", "url"}


def _rows(con: sqlite3.Connection, sql: str, params=()):
    con.row_factory = sqlite3.Row
    return [dict(row) for row in con.execute(sql, params)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path,
                        default=Path(__file__).resolve().parent.parent / "data" / "quality" / "e2e_runs.db")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).resolve().parent.parent / "data" / "quality" / "e2e_audit_payload.json")
    args = parser.parse_args()

    con = sqlite3.connect(str(args.db))
    docs = _rows(con, "SELECT * FROM documents WHERE status IN ('completed','assessed') ORDER BY id")
    rows = []
    for doc in docs:
        name = (doc.get("source_filename") or "").removesuffix(".pdf")
        if not name.startswith("9-"):
            continue
        threats = _rows(con, "SELECT * FROM threats WHERE document_id=? ORDER BY number", (doc["id"],))
        vulnerabilities = _rows(con, "SELECT * FROM vulnerabilities WHERE document_id=? ORDER BY id", (doc["id"],))
        iocs = _rows(con, "SELECT * FROM iocs WHERE document_id=? ORDER BY id", (doc["id"],))
        blocks = []
        for threat in threats:
            blocks.append({
                "id": threat.get("id"),
                "number": threat.get("number"),
                "threat_type": threat.get("threat_type") or "",
                "theme": threat.get("theme") or "",
                "group_name": threat.get("group_name") or "",
                "archive_name": threat.get("archive_name") or "",
                "exe_name": threat.get("exe_name") or "",
                "malware_type": threat.get("malware_type") or "",
                "description": threat.get("description") or "",
                "explicit_measures": [line.strip() for line in
                                      (threat.get("measures") or "").splitlines() if line.strip()],
            })
        active = [{
            "cve_id": v.get("cve_id") or "",
            "bdu_id": v.get("bdu_id") or "",
            "description": v.get("description") or "",
            "software": v.get("software") or "",
            "severity": v.get("severity") or "unknown",
            "cvss_score": v.get("cvss_score"),
            "cvss_version": v.get("cvss_version") or "",
            "affected_range": v.get("affected_range") or "",
            "cpe": v.get("cpe") or "",
            "fixed_version": v.get("fixed_version") or "",
            "patch_url": v.get("patch_url") or "",
            "current_version": v.get("current_version") or "",
            "target_version": v.get("target_version") or "",
            "cmdb_match": bool(v.get("cmdb_match")),
            "cmdb_error": v.get("cmdb_error") or "",
            "recommendation": v.get("recommendation") or "",
            "is_applicable": v.get("is_applicable"),
            "applicability_notes": v.get("applicability_notes") or "",
            "action_type": v.get("action_type") or "",
            "action_details": v.get("action_details") or "",
            "source": v.get("source") or "bdu",
        } for v in vulnerabilities]
        addresses = sorted({
            str(ioc.get("value") or "").strip()
            for ioc in iocs
            if ioc.get("ioc_type") in ADDRESS_TYPES and str(ioc.get("value") or "").strip()
        })
        rows.append({
            "id": name,
            "document_id": doc["id"],
            "letter_number": doc.get("letter_number") or "",
            "letter_date": doc.get("letter_date") or "",
            "letter_type": doc.get("letter_type") or "other",
            "blocks": blocks,
            "active_vulns": active,
            "addresses": addresses,
        })
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    con.close()
    print(f"exported {len(rows)} rows to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
