import asyncio
import json

from security_service.bdu_client import BDUClient
from security_service.bdu_measures import (
    _parse_normalized_measures,
    extract_measure_items,
    extract_top_level_measures,
    normalize_bdu_card,
    os_families,
    os_family,
    parse_detail,
    parse_list_page,
)


def _page(model: dict) -> str:
    return "<html><script>v_model = reactive(" + json.dumps(model, ensure_ascii=False) + ")</script></html>"


def test_parse_list_page_only_table_rows():
    page = """
    <div class="summary pull-right">Элементы с 1 по 10 из 174</div>
    <table class="table table-striped table-vuls">
      <tr><td><a href="/vul/2024-03571">BDU:2024-03571</a></td></tr>
      <tr><td><a href="/vul/2026-08086">BDU:2026-08086</a></td></tr>
    </table>
    <div class="list-news"><a href="/vul/2026-19122">recent</a></div>
    """
    total, ids = parse_list_page(page)
    assert total == 174
    assert ids == ["2024-03571", "2026-08086"]


def test_extract_inline_and_bulleted_measures():
    vmer = """Компенсирующие меры: изменение прав доступа.
- использование межсетевого экранирования;
- ведение журнала событий безопасности.

Использование рекомендаций:
Для Windows:
https://example.test/advisory
"""
    text, items = extract_measure_items(vmer)
    assert "https://example.test" not in text
    assert items[0] == "изменение прав доступа."
    assert "использование межсетевого экранирования;" in items
    assert "ведение журнала событий безопасности." in items
    assert all(not item.startswith("Для ") for item in items)


def test_parse_detail_has_only_card_metadata():
    model = {
        "vul_elimination": 2,
        "vul_name": "Уязвимость тестовой ОС",
        "vul_desc": "Описание",
        "vul_critu": "Высокий уровень опасности (базовая оценка CVSS 3.1 составляет 7.5)",
        "vul_datv": "2024-05-06",
        "vul_upddate": "2025-11-19",
        "vul_vmer": "Компенсирующие меры:\n- ограничить сетевой доступ;\n- включить журналирование.",
        "osystems": [
            {"soft": {"sft_name": "Windows 10"}, "vendor": {"vnd_name": "Microsoft Corp"}},
            {"soft": {"sft_name": "Astra Linux Special Edition"}, "vendor": {"vnd_name": "Астра"}},
        ],
        "idvals": ['CVE: <a href="https://example.test">CVE-2024-3661</a>'],
    }
    item = parse_detail(_page(model), "BDU:2024-03571")
    assert item is not None
    assert item["bdu_id"] == "BDU:2024-03571"
    assert item["os_families"] == ["windows", "linux"]
    assert "measure_items" not in item
    assert "measure_text" not in item
    assert item["cve_id"] == "CVE-2024-3661"
    assert item["severity"] == "high"
    assert item["cvss_score"] == 7.5


def test_parse_detail_skips_update_only_card():
    model = {
        "vul_elimination": 1,
        "vul_name": "Уязвимость",
        "vul_desc": "Описание",
        "vul_critu": "Высокий уровень опасности",
        "osystems": [{"soft": {"sft_name": "Windows"}}],
    }
    assert parse_detail(_page(model), "BDU:2024-00001") is None


def test_parse_normalized_measures_json_and_fences():
    assert _parse_normalized_measures('{"measures": ["мера 1", "мера 2"]}') == ["мера 1", "мера 2"]
    assert _parse_normalized_measures('```json\n{"measures": ["мера"]}\n```') == ["мера"]
    assert _parse_normalized_measures('{"measures": []}') == []


def test_normalize_on_the_fly_uses_llm(monkeypatch):
    model = {
        "vul_elimination": 2,
        "vul_name": "Уязвимость тестовой ОС",
        "vul_vmer": (
            "Компенсирующие меры:\n"
            "- ограничить сетевой доступ;\n"
            "- включить журналирование;\n"
            "- провести инструктаж сотрудников."
        ),
    }

    async def fake_fetch(self, bdu_id):
        return _page(model)

    class FakeProvider:
        model = "fake-llm"

        async def achat(self, *_args, **_kwargs):
            return '{"measures": ["ограничивается сетевой доступ;", "осуществляется журналирование событий;"]}'

    monkeypatch.setattr(BDUClient, "_fetch", fake_fetch)
    result = asyncio.run(normalize_bdu_card("BDU:2024-03571", provider=FakeProvider()))
    assert result["bdu_id"] == "BDU:2024-03571"
    assert result["llm_used"] is True
    assert result["model"] == "fake-llm"
    assert result["measures"] == [
        "ограничивается сетевой доступ",
        "осуществляется журналирование событий",
    ]


def test_top_level_two_measures_are_kept_without_nested_steps():
    vmer = """Компенсирующие меры:
- использование SIEM-систем для отслеживания попыток эксплуатации уязвимости.
- изменение ключей реестра следующим образом:
1) создание резервной копии реестра;
2) завершение процессов, связанных с работой приложений Microsoft Office;
3) запуск приложений Microsoft Office.

Использование рекомендаций:
https://example.test
"""
    assert extract_top_level_measures(vmer) == [
        "использование SIEM-систем для отслеживания попыток эксплуатации уязвимости.",
        "изменение ключей реестра следующим образом:",
    ]


def test_live_bdu_measures_replace_compensation(monkeypatch):
    from shared.generator import templated_reply as tr

    async def fake_normalize(bdu_id, **_kwargs):
        return {"bdu_id": bdu_id, "measures": ["ограничивается сетевой доступ"]}

    monkeypatch.setattr("security_service.bdu_measures.normalize_bdu_card", fake_normalize)
    monkeypatch.setattr(tr, "_live_bdu_measures_enabled", lambda: True)
    tr._LIVE_BDU_MEASURE_CACHE.clear()
    vuln = {
        "bdu_id": "BDU:2024-03571",
        "action_type": "compensate",
        "action_details": "старые меры",
        "remediation": "старые меры",
    }
    asyncio.run(tr._apply_live_bdu_measures_async([vuln]))
    assert vuln["action_details"] == "ограничивается сетевой доступ;"
    assert vuln["remediation"] == "ограничивается сетевой доступ;"


def test_live_bdu_block_measures_are_added(monkeypatch):
    from shared.generator import templated_reply as tr

    async def fake_normalize(bdu_id, **_kwargs):
        return {"bdu_id": bdu_id, "measures": ["осуществляется мониторинг событий"]}

    monkeypatch.setattr("security_service.bdu_measures.normalize_bdu_card", fake_normalize)
    monkeypatch.setattr(tr, "_live_bdu_measures_enabled", lambda: True)
    tr._LIVE_BDU_MEASURE_CACHE.clear()
    blocks = [{
        "number": 10,
        "description": (
            "Эксплуатация уязвимости Microsoft Office (BDU:2026-00828, "
            "уровень опасности по CVSS 3.1 — высокий)."
        ),
    }]
    plan = {"blocks": [{"number": 10, "description": blocks[0]["description"], "measures": []}]}
    asyncio.run(tr._apply_live_bdu_block_measures_async(plan, blocks))
    compensation = plan["blocks"][0]["bdu_compensations"][0]
    assert compensation["header"] == (
        "В целях предотвращения возможности эксплуатации данной уязвимости "
        "приняты следующие компенсирующие меры:"
    )
    assert compensation["measures"] == ["осуществляется мониторинг событий"]


def test_live_bdu_measures_skip_update_cards_with_fixed_version(monkeypatch):
    from shared.generator import templated_reply as tr

    called = []

    async def fake_normalize(bdu_id, **_kwargs):
        called.append(bdu_id)
        return {"bdu_id": bdu_id, "measures": ["не нужно подменять"]}

    monkeypatch.setattr("security_service.bdu_measures.normalize_bdu_card", fake_normalize)
    monkeypatch.setattr(tr, "_live_bdu_measures_enabled", lambda: True)
    vuln = {"bdu_id": "BDU:2024-03571", "action_type": "update",
            "target_version": "1.2.3", "action_details": "обновить продукт"}
    asyncio.run(tr._apply_live_bdu_measures_async([vuln]))
    assert called == []
    assert vuln["action_details"] == "обновить продукт"


def test_live_bdu_measures_use_card_when_update_has_no_target(monkeypatch):
    from shared.generator import templated_reply as tr

    called = []

    async def fake_normalize(bdu_id, **_kwargs):
        called.append(bdu_id)
        return {"bdu_id": bdu_id, "measures": ["ограничить сетевой доступ"]}

    monkeypatch.setattr("security_service.bdu_measures.normalize_bdu_card", fake_normalize)
    monkeypatch.setattr(tr, "_live_bdu_measures_enabled", lambda: True)
    tr._LIVE_BDU_MEASURE_CACHE.clear()
    vuln = {"bdu_id": "BDU:2024-03571", "action_type": "update",
            "target_version": "", "fixed_version": "", "action_details": ""}
    asyncio.run(tr._apply_live_bdu_measures_async([vuln]))
    assert called == ["BDU:2024-03571"]
    assert "ограничить сетевой доступ" in (vuln["action_details"] or "")


def test_os_family_types():
    assert os_family("Windows Server 2019") == "windows"
    assert os_family("Astra Linux Special Edition") == "linux"
    assert os_family("РЕД ОС") == "linux"
    assert os_family("Cisco IOS") == "network"
    assert os_family("MacOS") == "apple"
    assert os_family("FreeBSD") == "unix"
    assert os_families(["Windows", "Linux"]) == ["windows", "linux"]


def test_normalize_on_the_fly_falls_back_to_card_text(monkeypatch):
    model = {
        "vul_elimination": 2,
        "vul_name": "Тестовая карточка",
        "vul_vmer": (
            "Организационные меры:\n"
            "- ограничить сетевой доступ;\n"
            "- включить журналирование;\n"
            "- обновить правила межсетевого экрана."
        ),
    }

    async def fake_fetch(self, bdu_id):
        return _page(model)

    class BrokenProvider:
        model = "broken"

        async def achat(self, *_args, **_kwargs):
            raise RuntimeError("llm unavailable")

    monkeypatch.setattr(BDUClient, "_fetch", fake_fetch)
    result = asyncio.run(normalize_bdu_card("BDU:2024-03571", provider=BrokenProvider()))
    assert result["llm_used"] is False
    assert "ограничить сетевой доступ" in result["measures"]
    assert "включить журналирование" in result["measures"]
