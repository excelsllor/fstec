"""Assessment (ТЗ 2.4): keep-all, версионный match, source, SLA-эскалация, рекомендация,
external_errors, вывод fixed_version по регексу."""
import asyncio

from security_service.assessment import _product_for_cmdb, assess_document
from security_service.cmdb_mock import MockCMDB
from security_service.enriched import CpeMatch, EnrichedVuln, RangeSpec
from tests.fakes import (BDU_ENRICHED, NVD_CRITICAL, VULN_RAW, FakeBDUClient,
                         FakeNVDClient)


async def _assess(vulns, nvd=None, bdu=None, cmdb=None, enrich=True):
    return await assess_document(vulns, cmdb=cmdb or MockCMDB(),
                                 enrich=enrich, nvd=nvd, bdu=bdu)


def test_keep_all_and_match():
    raw = dict(VULN_RAW)
    raw["cve_id"] = ""
    ass = asyncio.run(_assess([raw], nvd=FakeNVDClient(None), bdu=FakeBDUClient(BDU_ENRICHED)))
    assert len(ass.assessed) == 1
    a = ass.assessed[0]
    assert a["cmdb_match"] is True                 # Log4j 2.15.0 в уязвимом диапазоне/продукт
    assert a["current_version"] == "2.15.0"
    assert a["target_version"] == "2.17.0"         # fixed_version из BDU
    assert a["source"] == "bdu"
    assert a["severity"] == "critical"
    assert "с 2.15.0 до 2.17.0" in a["recommendation"]


def test_bdu_is_authoritative_for_cvss_and_severity():
    nvd = EnrichedVuln(source="nvd", cve_id="CVE-2026-0001", severity="high",
                       cvss_version="2.0", cvss_score=10.0)
    bdu = EnrichedVuln(source="bdu", bdu_id="BDU:2026-0001", cve_id="CVE-2026-0001",
                       severity="critical", cvss_version="3.1", cvss_score=8.8)
    raw = {"bdu_id": "BDU:2026-0001", "cve_id": "CVE-2026-0001",
           "description": "Уязвимость тест", "software": "Test", "severity": "unknown"}
    ass = asyncio.run(_assess([raw], nvd=FakeNVDClient(nvd), bdu=FakeBDUClient(bdu)))
    a = ass.assessed[0]
    assert a["source"] == "bdu"
    assert a["severity"] == "critical"
    assert a["cvss_version"] == "3.1"


def test_no_match_kept():
    raw = {"cve_id": "CVE-2026-0001", "bdu_id": "", "description": "CVE без ПO",
           "software": "Неведомый софт", "severity": "critical"}
    ass = asyncio.run(_assess([raw], nvd=FakeNVDClient(None), bdu=FakeBDUClient(None)))
    assert len(ass.assessed) == 1                     # keep-all: no-match НЕ выбрасывается
    a = ass.assessed[0]
    assert a["cmdb_match"] is False
    assert a["current_version"] == ""
    assert a["source"] == "manual"


def test_sla_escalation_on_match():
    no_match = {"cve_id": "", "bdu_id": "", "description": "", "software": "Foo",
                "severity": "low"}
    ass = asyncio.run(_assess([no_match], nvd=None, bdu=None))
    assert ass.sla == "normal" and ass.routing == "default"
    ass2 = asyncio.run(_assess([dict(VULN_RAW)], nvd=FakeNVDClient(NVD_CRITICAL),
                               bdu=FakeBDUClient()))
    assert ass2.sla == "critical" and ass2.routing == "infosec"


def test_range_does_not_match():
    """OpenSSL 1.1.1k в инвентаре, но диапазон CVE = >=3.0 → no match."""
    openssl = {
        "cve_id": "CVE-2026-9999", "bdu_id": "", "description": "OpenSSL >=3.0",
        "software": "OpenSSL", "severity": "high",
    }
    nvd_openssl = EnrichedVuln(
        source="nvd", cve_id="CVE-2026-9999", severity="high", cvss_score=7.5,
        cpe_matches=[CpeMatch(criteria="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                              ranges=[RangeSpec(min_version="3.0", min_inclusive=True, raw=">=3.0")])],
    )
    ass = asyncio.run(_assess([openssl], nvd=FakeNVDClient(nvd_openssl), bdu=FakeBDUClient(None)))
    a = ass.assessed[0]
    assert a["cmdb_match"] is False                  # 1.1.1k < 3.0 (вне диапазона)
    assert a["current_version"] == "1.1.1k"
    assert a["is_applicable"] is True
    assert a["action_type"] == "skip"


def test_vulnerability_payload_keeps_assessment_fields():
    from shared.vulnerability_payload import vulnerability_payload
    payload = vulnerability_payload({
        "bdu_id": "BDU:2026-0001", "software": "Windows",
        "cmdb_match": False, "is_applicable": True, "action_type": "update",
        "applicability_notes": "note",
    })
    assert payload["is_applicable"] is True
    assert payload["action_type"] == "update"
    assert payload["applicability_notes"] == "note"


def test_linux_without_glpi_is_not_assumed_installed():
    raw = {
        "bdu_id": "", "cve_id": "", "software": "Linux",
        "description": "?????????? Linux",
        "severity": "high",
    }
    ass = asyncio.run(_assess([raw], enrich=False))
    a = ass.assessed[0]
    assert a["cmdb_match"] is False
    assert a["is_applicable"] is False
    assert a["action_type"] == "skip"
    assert "RED OS" not in a["applicability_notes"]

def test_missing_product_is_derived_before_glpi_lookup():
    from security_service.cmdb import InventoryItem

    class CMDB:
        async def find_many(self, product):
            if product == "Node.js":
                return [InventoryItem(name="Node.js", version="18.14.0")]
            return []

    raw = {
        "bdu_id": "BDU:2026-17395", "cve_id": "",
        "description": (
            "Уязвимость алгоритма сжатия данных Brotli программной платформы "
            "Node.js связана с отсутствием проверки возвращаемого значения."),
        "software": "", "severity": "critical", "fixed_version": "26.12.1",
    }
    ass = asyncio.run(_assess([raw], cmdb=CMDB(), enrich=False))
    a = ass.assessed[0]
    assert a["software"] == "Node.js"
    assert a["current_version"] == "18.14.0"
    assert a["cmdb_match"] is True
    assert a["action_type"] == "update"


def test_gitlab_glab_vendor_alias_is_accepted():
    from security_service.cmdb import InventoryItem

    class CMDB:
        async def find_many(self, product):
            return [InventoryItem(name="glab", version="1.53.0-1", vendor="GitLab")]

    raw = {
        "bdu_id": "BDU:2026-17391", "cve_id": "",
        "description": (
            "Уязвимость программной платформы на базе git для совместной работы "
            "над кодом GitLab связана с целочисленным переполнением."),
        "software": "GitLab", "severity": "critical", "fixed_version": "19.5.1",
    }
    ass = asyncio.run(_assess([raw], cmdb=CMDB(), enrich=False))
    a = ass.assessed[0]
    assert a["current_version"] == "1.53.0-1"
    assert a["cmdb_match"] is True
    assert a["action_type"] == "update"


def test_gitlab_client_package_is_not_gitlab_server():
    from security_service.cmdb import InventoryItem

    class CMDB:
        async def find_many(self, product):
            return [
                InventoryItem(name="python3-gitlab", version="1:2.0.1-1"),
                InventoryItem(name="gitlab-runner", version="17.2.0-1", vendor="GitLab"),
            ]

    raw = {
        "bdu_id": "BDU:2026-17391", "cve_id": "",
        "description": (
            "Уязвимость программной платформы на базе git для совместной работы "
            "над кодом GitLab связана с целочисленным переполнением."),
        "software": "GitLab", "severity": "critical", "fixed_version": "19.5.1",
    }
    ass = asyncio.run(_assess([raw], cmdb=CMDB(), enrich=False))
    a = ass.assessed[0]
    assert a["cmdb_match"] is False
    assert a["is_applicable"] is False
    assert a["action_type"] == "skip"


def test_installed_without_range_or_fix_requires_verification():
    from security_service.cmdb import InventoryItem

    class CMDB:
        async def find_many(self, product):
            return [InventoryItem(name="Windows", version="22H2")]

    raw = {
        "bdu_id": "BDU:2021-02715", "cve_id": "",
        "description": "Уязвимость сетевого стека Microsoft Windows связана с ошибкой.",
        "software": "Windows", "severity": "high",
    }
    bdu = EnrichedVuln(
        source="bdu", bdu_id="BDU:2021-02715",
        description="Уязвимость сетевого стека Microsoft Windows связана с ошибкой.",
        severity="high",
    )
    ass = asyncio.run(_assess(
        [raw], cmdb=CMDB(), enrich=True, nvd=FakeNVDClient(None),
        bdu=FakeBDUClient(bdu)))
    a = ass.assessed[0]
    assert a["cmdb_match"] is False
    assert a["is_applicable"] is True
    assert a["action_type"] == "verify"


def test_product_for_cmdb_derives_name_from_description():
    cases = [
        ("Уязвимость алгоритма сжатия данных Brotli программной платформы Node.js связана с ошибкой.",
         "Node.js"),
        ("Уязвимость компонента API программного обеспечения Airflow связана с ошибкой.",
         "Airflow"),
        ("Уязвимость службы RAW-печати устройства EPSON L14150 связана с ошибкой.",
         "EPSON L14150"),
        ("Уязвимость библиотеки для анализа XML-файлов libexpat связана с ошибкой.",
         "libexpat"),
        ("Уязвимость интерпретатора языка программирования Python (CPython) связана с ошибкой.",
         "CPython"),
    ]
    for description, expected in cases:
        assert _product_for_cmdb(description, "")[0] == expected


def test_raw_description_wins_when_bdu_description_names_other_product():
    bdu = EnrichedVuln(
        source="bdu", bdu_id="BDU:2026-16531",
        description="Уязвимость библиотеки сериализации MessagePack",
        severity="medium", cvss_score=5.0, cvss_version="3.1",
    )
    raw = {
        "bdu_id": "BDU:2026-16531", "cve_id": "",
        "software": "Windows",
        "description": "Уязвимость командной оболочки Shell операционных систем Windows",
        "severity": "high",
    }
    ass = asyncio.run(_assess([raw], nvd=None, bdu=FakeBDUClient(bdu)))
    description = ass.assessed[0]["description"]
    assert "Windows" in description
    assert "MessagePack" not in description
    assert ass.assessed[0]["severity"] == "high"


def test_external_errors_collected():
    raw = dict(VULN_RAW)
    raw["bdu_id"] = ""
    ass = asyncio.run(_assess([raw], nvd=FakeNVDClient(fail=True), bdu=FakeBDUClient()))
    assert ass.external_errors                     # NVD недоступен → ошибка записана
    # BDU-обогащение не вызывалось (cve_id первым, но упал) — raw-дубль остаётся, keep-all работает
    assert len(ass.assessed) >= 1


def test_mock_mode_no_enrich():
    """enrich=False (mock/dev): внешние БД не вызываются, источник manual."""
    ass = asyncio.run(_assess([dict(VULN_RAW)], nvd=None, bdu=None, enrich=False))
    a = ass.assessed[0]
    assert a["source"] == "manual"
    assert a["cmdb_match"] is True
    assert a["target_version"] == "2.17.0"          # fixed_version выведен регексом из описания
    assert "2.17.0" in a["recommendation"]