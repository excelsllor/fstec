# BDU-card fix: UI test and etalon comparison

## Scope
- 22 letters: `9-70`, `9-77`, `9-78`, `9-81`, `9-85`, `9-89`, `9-93`,
  `9-99`, `9-104`, `9-107`, `9-113`, `9-114`, `9-118`, `9-119`, `9-121`,
  `9-126`, `9-132`, `9-137`, `9-145`, `9-148`, `9-152`, `9-157`.
- Generation path: existing UI/API documents `679`, `698-719`, endpoint
  `/reply/generate`.
- Final responses: `1098-1119`.
- Old generator backup: `services/shared/generator/templated_reply.pre_bdu_fix_20261115_093458.bak.py`.

## Code changes
- `assessment.py`: `update` only when `fixed_version`/`target_version` exists;
  otherwise `compensate`.
- `templated_reply.py`: BDU card is requested for `compensate` and for
  `update` without a version; `skip`/`verify` do not request it.
- `_vuln_paragraph()`: update without a version is rendered as
  "обновление невозможно", not as an active update.
- `bdu_measures.py`: if LLM normalization fails, card text is used as fallback.
- `templated_reply.py`: if the BDU card is empty for an update-without-target,
  explicit compensation measures from the source letter are used as a fallback.

## Etalon result

| Letter | Final response | Result |
|---|---:|---|
| `9-145` | `1116` | 3/3 etalon measures restored from source fallback; BDU card itself has no organizational measures |
| `9-114` | `1109` | update has target `4.24.3`; `%J` / `smb.conf` measure remains absent |
| `9-121` | `1112` | card `BDU:2022-02730` exists, but `action_type=skip`; 2 etalon measures remain absent |
| `9-137` | `1115` | card `BDU:2025-10524` exists, but `action_type=skip`; etalon measures remain absent |
| `9-119`, `9-148`, `9-157` | `1111`, `1117`, `1119` | status changed to update impossible; no explicit etalon measures |

The source fallback is deliberately limited to `update` without a version or
`compensate`; it is not used for `skip`/`verify` and not used when a target
version exists.

## Checks
- Target tests: `79 passed`.
- `9/208` unchanged: responses `965`/`966`, length `20383`,
  SHA-256 `b996279cc5725589d374656a6b6569b6b9c7e6f3cbbc824a879c694d97c08f5f`.
- Data: `services/data/quality/ui_audit_replies_bdu_fix.json`,
  `services/data/quality/bdu_fix_comparison.json`.
