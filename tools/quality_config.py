"""Общий конфиг выверенных действий по уязвимостям для gen_all.py и audit_quality.py."""

# bdu_id -> {"action": ..., "software": ...}
# action: "update" | "skip" | "exclude" | "exclude"
ACTIONS = {
    "9-70": {"BDU:2025-15156": {"action": "skip", "software": "next.js"}},
    "9-81": {"BDU:2025-10114": {"action": "skip"}},
    "9-99": {"BDU:2026-06823": {"action": "skip"}, "BDU:2018-00096": {"action": "exclude"}},
    "9-104": {"BDU:2018-00246": {"action": "update"}},
    "9-113": {"BDU:2026-00828": {"action": "update"}},
}

# ручные записи уязвимостей (bdu, software, action) — нет в выгрузке PDF
MANUAL = {
    "9-89": [("", "DAEMON Tools", "skip")],
}
