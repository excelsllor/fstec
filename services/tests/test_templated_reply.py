"""Тесты: шаблонный проект ответа (библиотека мер + LLM/fallback-подбор)."""
import pytest

from shared.db import SessionLocal
from shared.generator.templated_reply import (
    _address_keys, _apply_global_measure_policy, _backfill_empty_blocks, _extract_ctx,
    _inflect_measure, _normalize_block_address_forms, _remove_empty_measure_blocks,
    _template_intro, _vuln_paragraph, _vulnerability_card_status,
    _vulns_to_blocks, build_annotated_preview, generate_reply, load_reply_resources,
    persist_candidates, plan_reply, render_reply,
)


def test_9_200_uses_global_measure_policy():
    from shared.generator.templated_reply import _load_letter_measure_plans
    plans = _load_letter_measure_plans()
    assert "9-200" not in plans
    assert "9-208" not in plans
    assert "9-70" not in plans


def test_measure_infinitive_is_rendered_as_impersonal():
    assert _inflect_measure("Производить проверку вложений", 1).startswith("Производится")
    assert _inflect_measure("Осуществлять проверку ссылок", 1).startswith("Осуществляется")
    assert _inflect_measure("Не открывать и не загружать вложения", 1).startswith(
        "Не допускается открывать и загружать")


def test_address_keys_treat_each_indicator_separately():
    assert len(_address_keys("к адресу hxxps[:]//nagl[.]com[.]pg/zhZDoKTxnjAFPNusz93[.]bin")) == 1
    assert len(_address_keys("maximalmaxing[.]com; hxxps[:]//maximalmaxing[.]com/windlass")) == 2
    assert len(_address_keys("hxxps[:]//nagl[.]com[.]pg/zhZDoK\\nTxnjAFPNusz93[.]bin")) == 1
    assert len(_address_keys("198[.]54[.]117[.]242; 199[.]247[.]25[.]29")) == 2


def test_address_normalization_applies_to_source_measures():
    plan = {"blocks": [{
        "number": 5,
        "measures": [{"text": "ограничение обращений к указанным адресам;",
                      "source": "source"}],
    }, {
        "number": 15,
        "measures": [{"text": "ограничение обращений к указанному адресу;",
                      "source": "source"}],
    }]}
    blocks = [
        {"number": 5, "description": (
            "к адресу hxxps[:]//nagl[.]com[.]pg/zhZDoKTxnjAFPNusz93[.]bin")},
        {"number": 15, "description": (
            "maximalmaxing[.]com; hxxps[:]//maximalmaxing[.]com/windlass")},
    ]
    _normalize_block_address_forms(plan, blocks)
    assert "к указанному адресу" in plan["blocks"][0]["measures"][0]["text"]
    assert "к указанным адресам" in plan["blocks"][1]["measures"][0]["text"]


def test_compensation_when_installed_but_no_fixed_version():
    vuln = {
        "bdu_id": "BDU:2026-99999", "software": "Samba",
        "description": "Уязвимость Samba связана с ошибкой.",
        "cmdb_match": True, "is_applicable": None,
        "action_type": "compensate",
        "current_version": "4.20.0",
        "action_details": "использовать SIEM; ограничить сетевой доступ",
    }
    parts = _vuln_paragraph(vuln, "9-999")
    assert parts[0].endswith("приняты следующие компенсирующие меры:")
    assert parts[1] == "использовать SIEM;"
    assert parts[2] == "ограничить сетевой доступ."
    assert "неуязвимой версии" not in parts[0]


def test_update_with_compensation_does_not_add_compensation():
    vuln = {
        "bdu_id": "BDU:2026-99996", "software": "Systemd",
        "description": "Уязвимость Systemd связана с ошибкой.",
        "cmdb_match": True, "is_applicable": True,
        "action_type": "update",
        "fixed_version": "1.2.3",
        "action_details": (
            "ограничен доступ к командной строке для недоверенных пользователей; "
            "создание файлов вне домашней директории пользователя запрещено"
        ),
    }
    parts = _vuln_paragraph(vuln, "9-999")
    assert len(parts) == 1
    assert parts[0].endswith("до неуязвимой версии.")
    assert "компенсирующие меры" not in parts[0]
    assert "Дополнительно" not in parts[0]


def test_compensation_lines_are_rendered_without_numbers():
    vuln = {
        "bdu_id": "BDU:2026-99995", "software": "Systemd",
        "description": "Уязвимость Systemd связана с ошибкой.",
        "cmdb_match": True, "is_applicable": True,
        "action_type": "compensate",
        "action_details": "ограничен доступ к командной строке; создание файлов запрещено",
    }
    text, _ = render_reply(
        plan={"template_key": "vulnerability", "blocks": []},
        templates={"vulnerability": {"header": "Ответ на письмо {{num}} от {{date}}",
                                     "intro": "Вводный текст"}},
        letter_number="9/999", letter_date="2026-11-13", active_vulns=[vuln])
    assert "\nУязвимость Systemd" in text
    assert "приняты следующие компенсирующие меры:" in text
    assert "\nограничен доступ к командной строке;" in text
    assert "\nсоздание файлов запрещено." in text
    assert "\n2. ограничен доступ" not in text
    assert "\n- ограничен доступ" not in text


def test_verify_action_is_not_reported_as_safe_or_update():
    vuln = {
        "bdu_id": "BDU:2021-02715", "software": "Windows",
        "description": "Уязвимость Microsoft Windows связана с ошибкой.",
        "cmdb_match": False, "is_applicable": True,
        "action_type": "verify", "current_version": "22H2",
    }
    text = _vuln_paragraph(vuln, "9-209")[0]
    assert "требует проверки" in text
    assert "не подвержена" not in text
    assert "ведутся работы по обновлению" not in text


def test_generic_action_details_are_not_compensation():
    vuln = {
        "bdu_id": "BDU:2026-99998", "software": "Samba",
        "description": "Уязвимость Samba связана с ошибкой.",
        "cmdb_match": True, "is_applicable": True,
        "action_type": "update",
        "current_version": "4.20.0",
        "target_version": "4.21.0",
        "action_details": "Манипулирование структурами данных",
    }
    text = _vuln_paragraph(vuln, "9-999")[0]
    assert "компенсирующие меры" not in text
    assert "ведутся работы по обновлению" in text


def test_cmdb_match_overrides_not_used_description():
    vuln = {
        "bdu_id": "BDU:2026-17517", "software": "Pillow",
        "description": "Уязвимость библиотеки Pillow связана с обработкой JPEG. ПО не используется.",
        "cmdb_match": True, "is_applicable": True, "action_type": "update",
        "current_version": "12.3.0", "target_version": "12.4.0",
    }
    text = _vuln_paragraph(vuln, "9-209")[0]
    assert "по обновлению" in text
    assert "установленная версия вне уязвимого диапазона" not in text


def test_vulnerable_version_uses_generic_update_target():
    vuln = {
        "bdu_id": "BDU:2026-99997", "software": "Samba",
        "description": "Уязвимость Samba связана с ошибкой.",
        "cmdb_match": True, "is_applicable": True,
        "action_type": "update",
        "current_version": "4.20.0",
        "fixed_version": "4.21.0",
        "target_version": "4.21.0",
        "recommendation": "Обновить Samba до версии 4.21.0",
    }
    text = _vuln_paragraph(vuln, "9-999")[0]
    assert "до неуязвимой версии" in text
    assert "4.21.0" not in text


def test_installed_but_not_affected_is_reported_as_such():
    vuln = {
        "bdu_id": "BDU:2023-03874", "software": "Python Requests",
        "description": "Уязвимость HTTP-клиента Python Requests связана с обработкой ответа.",
        "cmdb_match": False, "is_applicable": True, "action_type": "skip",
        "current_version": "2.32.4",
    }
    text = _vuln_paragraph(vuln, "9-209")[0]
    assert "Используемая версия HTTP-клиента Python Requests 2.32.4" in text
    assert "не подвержена данной уязвимости" in text
    assert "установленная версия вне уязвимого диапазона" not in text


def test_empty_measure_blocks_are_removed():
    plan = {"blocks": [
        {"number": 1, "measures": [{"text": "ok"}]},
        {"number": 2, "measures": []},
        {"number": 3, "measures": [{"text": "ok"}]},
    ]}
    _remove_empty_measure_blocks(plan)
    assert [b["number"] for b in plan["blocks"]] == [1, 3]


def test_vulnerability_paragraphs_are_unnumbered():
    vulns = [
        {"bdu_id": "BDU:2026-0001", "software": "Samba", "severity": "high",
         "cvss_version": "3.1",
         "description": "Уязвимость Samba (BDU:2026-0001, уровень опасности по CVSS 3.1 — высокий), связанная с ошибкой.",
         "cmdb_match": False, "is_applicable": False},
        {"bdu_id": "BDU:2026-0002", "software": "cURL", "severity": "medium",
         "cvss_version": "3.1",
         "description": "Уязвимость cURL (BDU:2026-0002, уровень опасности по CVSS 3.1 — средний), связанная с ошибкой.",
         "cmdb_match": False, "is_applicable": False},
    ]
    text, _ = render_reply(
        plan={"template_key": "vulnerability", "blocks": []},
        templates={"vulnerability": {"header": "Ответ на письмо {{num}} от {{date}}",
                                     "intro": "Вводный текст"}},
        letter_number="9/201", letter_date="2026-10-22", active_vulns=vulns)
    assert "\nУязвимость Samba" in text
    assert "\nУязвимость cURL" in text
from shared.models import (
    Document, IntroFragment, Measure, MeasureCandidate,
    ReplyTemplate, Threat,
)


def test_vuln_paragraph_keeps_bdu_description_with_connected_adjective():
    vuln = {
        "bdu_id": "BDU:2026-07317",
        "software": "Samba",
        "severity": "critical",
        "cvss_version": "3.1",
        "description": (
            "Уязвимость подсистемы печати (printing subsystem) программ\n"
            "сетевого взаимодействия Samba (BDU:2026-07317, уровень опасности\n"
            "по CVSS 3.1 — критический), связанная с непринятием мер по нейтрализации\n"
            "специальных элементов при обработке параметра %J."
        ),
        "is_applicable": True,
        "cmdb_match": True,
        "action_type": "update",
        "target_version": "4.24.3",
        "recommendation": "обновить до актуальной версии, исправить уязвимость",
    }
    line = _vuln_paragraph(vuln, "9-114")[0]
    assert "Уязвимость подсистемы печати" in line
    assert line.count("BDU:2026-07317") == 1
    assert "ведутся работы по обновлению подсистемы печати" in line


def _threat(db, doc, number, ttype, **kw):
    row = Threat(document_id=doc.id, number=number, threat_type=ttype,
                 theme=kw.get("theme", ""), group_name=kw.get("group_name", ""),
                 archive_name=kw.get("archive_name", ""), exe_name=kw.get("exe_name", ""),
                 malware_type=kw.get("malware_type", ""), description=kw.get("description", ""))
    db.add(row)
    return row


@pytest.fixture()
def doc_db():
    with SessionLocal() as db:
        doc = Document(source_filename="t.eml", letter_number="9/85",
                       letter_date="2026-04-29", letter_type="hacker")
        db.add(doc)
        db.flush()
        threats = [
            _threat(db, doc, 1, "phishing", theme="Договор",
                    group_name="Vortex Werewolf", archive_name="ishod.zip",
                    description="Фишинговая рассылка с архивом ishod.zip"),
            _threat(db, doc, 2, "malware_attack", group_name="NGC8211",
                    malware_type="DCRat",
                    description="Атака с применением трояна удаленного доступа (DCRat)"),
        ]
        db.commit()
        yield db, doc, threats
        db.close()


def test_seed_resources():
    with SessionLocal() as db:
        assert db.query(Measure).count() > 0
        assert db.query(IntroFragment).count() > 0
        tpls = {t.key for t in db.query(ReplyTemplate).all()}
        assert {"hacker", "compromise", "vulnerability", "other"} <= tpls


def test_fallback_plan_phishing(doc_db):
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, **{k: getattr(threats[0], k) for k in
               ("number", "threat_type", "theme", "group_name", "archive_name")}}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    assert plan["llm"] is False
    assert len(plan["blocks"]) == 1
    blk = plan["blocks"][0]
    assert "деятельностью хакерской группировки «Vortex Werewolf»" in blk["intro"]
    assert blk["measures"], "должны быть выбраны меры из библиотеки"


def test_render_no_double_number_no_duplicate(doc_db):
    db, doc, threats = doc_db
    _, _, tpl = load_reply_resources(db)
    blocks = [{"id": t.id, "number": t.number, "threat_type": t.threat_type,
               "theme": t.theme, "group_name": t.group_name,
               "archive_name": t.archive_name, "exe_name": "", "malware_type": "",
               "description": t.description} for t in threats]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    text, _ = render_reply(plan=plan, templates=tpl, letter_number="9/85",
                           letter_date="2026-04-29",
                           org_name="Правительства Липецкой области", addr_count=1)
    assert "1. 1." not in text
    assert "2. 2." not in text
    assert "связанных с связанных с" not in text
    assert "Ответ на письмо 9/85 от 29.04.2026" in text
    assert "Правительства Липецкой области" in text
    assert "С уважением" not in text
    assert text.count("\n1. В целях") >= 1
    assert "\n2. В целях" in text
    measure_lines = [line for line in text.splitlines() if line.startswith("- ")]
    assert measure_lines
    assert any(line.endswith(";") for line in measure_lines)
    assert measure_lines[-1].endswith(".")


def test_compromise_single_unnumbered_block(doc_db):
    db, doc, _ = doc_db
    doc.letter_type = "compromise"
    db.commit()
    blocks = [{"id": 0, "number": 1, "threat_type": "compromise", "theme": "",
               "group_name": "Орхидея", "archive_name": "", "exe_name": "",
               "malware_type": "", "description": "использование интернет-сайта"}]
    plan = plan_reply(db=db, letter_type="compromise", blocks=blocks,
                      addr_count=3, use_llm=False)
    text, _ = render_reply(plan=plan, templates=load_reply_resources(db)[2],
                           letter_number="9/77", letter_date="2026-04-29",
                           org_name="Правительства Липецкой области", addr_count=3)
    assert "1. В целях" not in text
    assert "В целях предотвращения" in text
    assert "адресам" in text or "адресу" in text


def test_compromise_empty_blocks_fixed_header(doc_db):
    db, doc, _ = doc_db
    doc.letter_type = "compromise"
    db.commit()
    plan = plan_reply(db=db, letter_type="compromise", blocks=[], addr_count=1,
                      use_llm=False)
    assert plan["blocks"]
    text, _ = render_reply(plan=plan, templates=load_reply_resources(db)[2],
                           letter_number="9/999", letter_date="2026-05-13",
                           org_name="Правительства Липецкой области", addr_count=1)
    assert "не подвержено риску" not in text
    assert "со случаем компрометации" in text
    assert "ограничение обращений" in text


def test_explicit_measures_override(doc_db):
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, "number": 1, "threat_type": "phishing",
               "theme": "Договор", "group_name": "Vortex Werewolf",
               "archive_name": "ishod.zip", "description": "фишинг",
               "explicit_measures": ["Своя мера первая", "Своя мера вторая"]}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    texts = [m["text"] for m in plan["blocks"][0]["measures"]]
    assert texts == ["Своя мера первая", "Своя мера вторая"]


def test_source_directive_explicit_measures_do_not_override(doc_db):
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, "number": 1, "threat_type": "phishing",
               "theme": "Договор", "group_name": "Vortex Werewolf",
               "archive_name": "ishod.zip", "description": "фишинг",
               "explicit_measures": [
                   "Производить проверку почтовых вложений",
                   "Осуществлять проверку URL-адресов",
               ]}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    texts = [m["text"].lower() for m in plan["blocks"][0]["measures"]]
    assert not any(t.startswith(("производить", "осуществлять")) for t in texts)


def test_fragment_explicit_measures_do_not_override(doc_db):
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, "number": 1, "threat_type": "phishing",
               "theme": "Договор", "group_name": "Vortex Werewolf",
               "archive_name": "ishod.zip", "description": "фишинг",
               "explicit_measures": [
                   "необходимо реализовать меры защиты, указанные в пунктах 1.1-1.7",
                   "Обеспечить ограничение обращений к указанным адресам",
               ]}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    _apply_global_measure_policy(plan, blocks, "hacker")
    texts = [m["text"] for m in plan["blocks"][0]["measures"]]
    assert "необходимо реализовать меры защиты, указанные в пунктах 1.1-1.7" not in texts
    assert any("обеспечивается ограничение обращений к указанным адресам" in t.lower()
               for t in texts)
    assert not any("песочниц" in t for t in texts)


def test_hacker_uses_source_measures_as_primary(doc_db):
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, "number": 1, "threat_type": "phishing",
               "theme": "Договор", "group_name": "Vortex Werewolf",
               "archive_name": "ishod.zip", "description": "фишинг",
               "explicit_measures": [
                   "Обеспечить ограничение обращений к указанным адресам",
                   "Проводить проверку почтовых вложений антивирусным средством",
                   "Необходимо ограничить доступ к указанным адресам",
                   "Не открывать и не загружать почтовые вложения писем с тематикой, "
                   "относящейся к деятельности органа",
                   "Кроме того, необходимо осуществить настройку правил мониторинга, "
                   "нацеленной на органы государственной власти, во вложениях указанных писем",
               ]}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    _apply_global_measure_policy(plan, blocks, "hacker")
    texts = [m["text"].lower() for m in plan["blocks"][0]["measures"]]
    assert texts[0] == "обеспечивается ограничение обращений к указанным адресам;"
    assert any("проводится проверка почтовых вложений" in t for t in texts)
    assert any("ограничивается доступ к указанным адресам" in t for t in texts)
    assert any("тематикой, не относящейся к деятельности органа" in t for t in texts)
    assert not any("нацеленной на органы государственной власти" in t for t in texts)
    assert not any("песочниц" in t for t in texts)


def test_hacker_does_not_render_ioc_from_measures_or_intro(doc_db, monkeypatch):
    monkeypatch.setenv("FSTEC_MEASURE_POLICY", "source")
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, "number": 1, "threat_type": "phishing",
               "theme": "Договор", "group_name": "Vortex Werewolf",
               "archive_name": "ishod.zip",
               "description": "фишинг; сетевой индикатор — 10[.]20[.]30[.]40; "
                              "хэш 2e1f4cc2f8a267028ad903f61c1fe046a379f2be953ba9638ea1f011a56dc864",
               "explicit_measures": [
                   "Обеспечить ограничение обращений к указанным адресам: 10[.]20[.]30[.]40",
                   "Осуществлять мониторинг событий по хэшу "
                   "2e1f4cc2f8a267028ad903f61c1fe046a379f2be953ba9638ea1f011a56dc864",
                   "Проводить проверку почтовых вложений антивирусным средством",
               ]}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    _apply_global_measure_policy(plan, blocks, "hacker")
    texts = [m["text"].lower() for m in plan["blocks"][0]["measures"]]
    assert not any("10[.]20[.]30[.]40" in t or "2e1f4cc2" in t for t in texts)
    assert "10[.]20[.]30[.]40" not in (plan["blocks"][0]["intro"] or "").lower()
    assert any("ограничение обращений" in t for t in texts)
    assert any("мониторинг" in t for t in texts)
    assert any("проверка почтовых вложений" in t for t in texts)


def test_hacker_does_not_append_active_vulnerability_section(doc_db):
    db, doc, _ = doc_db
    plan = {"template_key": "hacker", "blocks": [{
        "number": 1, "threat_id": 1, "intro": "фишинг",
        "threat_type": "phishing",
        "measures": [{"text": "проверка вложений;", "source": "library",
                      "measure_id": None}],
    }]}
    vulns = [{
        "bdu_id": "BDU:2026-0001", "software": "Samba", "severity": "high",
        "description": "Уязвимость Samba связана с ошибкой.",
        "cmdb_match": False, "is_applicable": False,
    }]
    text, _ = render_reply(plan=plan, templates=load_reply_resources(db)[2],
                           letter_number="9/combined", active_vulns=vulns)
    assert "2. Уязвимость" not in text
    assert "BDU:2026-0001" not in text
    assert "Samba не используется." not in text
    assert "Уязвимости программного обеспечения:" not in text


def test_hacker_header_omits_network_indicator(doc_db):
    db, doc, _ = doc_db
    plan = {"template_key": "hacker", "blocks": [{
        "number": 1, "threat_id": 1,
        "intro": "сетевая группировка Watch Wolf, тема — «Договор», "
                 "вложением является файл «Договор.7z», "
                 "сетевой индикатор — 198[.]54[.]117[.]242",
        "threat_type": "phishing",
        "measures": [{"text": "проверка вложений;", "source": "library",
                      "measure_id": None}],
    }]}
    text, _ = render_reply(plan=plan, templates=load_reply_resources(db)[2],
                           letter_number="9/header", active_vulns=[])
    heading = next(line for line in text.splitlines() if line.startswith("1."))
    assert "сетевой индикатор" not in heading.lower()
    assert "198[.]54[.]117[.]242" not in heading


def test_template_intro_keeps_malware_type_from_description(doc_db):
    db, doc, _ = doc_db
    blocks = [{
        "id": 1, "number": 1, "threat_type": "phishing",
        "description": (
            "1. Сетевой группировки Watch Wolf, действующей на территории "
            "Российской Федерации, в результате эксплуатации вредоносного "
            "программного обеспечения <ВПО> (GrimGazer)."
        ),
    }]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    intro = plan["blocks"][0]["intro"]
    assert "<ВПО> (GrimGazer)" in intro


def test_generate_reply_plan_json_and_candidates(doc_db):
    from shared.generator.templated_reply import plan_reply as _p
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, "number": 1, "threat_type": "phishing",
               "theme": "Договор", "group_name": "Vortex Werewolf",
               "archive_name": "ishod.zip", "exe_name": "", "malware_type": "",
               "description": "фишинг с архивом"}]
    plan = _p(db=db, letter_type="hacker", blocks=blocks, addr_count=1, use_llm=False)
    plan["blocks"][0]["measures"].append(
        {"text": "новая мера от LLM;", "source": "new", "measure_id": None})
    rep = generate_reply(db, doc.id, letter_type="hacker", blocks=blocks, addr_count=1)
    assert rep["text"].startswith("Ответ на письмо 9/85")
    assert rep["docx"].startswith(b"PK")
    assert plan["llm"] is False
    ids = persist_candidates(db, doc.id, [{"text": "новая мера от LLM;",
                                           "note": "тест", "threat_id": threats[0].id}])
    c = db.query(MeasureCandidate).filter(MeasureCandidate.id == ids[0]).first()
    assert c.status == "pending"
    ann = build_annotated_preview(db, plan, blocks, addr_count=1)
    assert ann[0]["measure_annotations"][-1]["source"] == "new"
    assert ann[0]["section_text"].startswith("1. В целях")
    # обратная совместимость для редактора ответа: measure_options/base_measures обязательны
    assert ann[0]["measure_options"]
    assert ann[0]["base_measures"]
    assert "новая мера от LLM;" in ann[0]["measure_options"]
    assert "новая мера от LLM;" not in ann[0]["base_measures"]


def test_accept_candidate_adds_to_library(doc_db):
    from datetime import datetime, timezone
    db, doc, _ = doc_db
    c = MeasureCandidate(document_id=doc.id, text="одобренная мера;", note="")
    db.add(c)
    db.commit()
    with SessionLocal() as admin_db:
        row = admin_db.query(MeasureCandidate).filter(MeasureCandidate.id == c.id).first()
        row.status = "approved"
        row.reviewed_at = datetime.now(timezone.utc)
        admin_db.flush()
        if not admin_db.query(Measure).filter(Measure.text == row.text).first():
            admin_db.add(Measure(text=row.text, threat_type="",
                                 tags="", addr_inflection=False, source="llm"))
        admin_db.commit()
        assert admin_db.query(Measure).filter(Measure.text == "одобренная мера;").count() == 1


def test_gateway_admin_and_generate(client, doc_db):
    from conftest import headers
    db, doc, threats = doc_db
    doc.letter_type = "hacker"
    db.commit()
    h = headers(client)
    r = client.post("/admin/measures", json={"text": "контролируемая тестовая мера;"},
                    headers=h)
    assert r.status_code == 200
    r = client.get("/admin/measures", headers=h)
    assert r.status_code == 200
    texts = [m["text"] for m in r.json()]
    assert "контролируемая тестовая мера;" in texts
    row = next(m for m in r.json() if m["text"] == "контролируемая тестовая мера;")
    r = client.put(f"/admin/measures/{row['id']}", headers=h, json={
        "text": "контролируемая тестовая мера (изменена);",
        "threat_type": "phishing", "tags": "тест, api", "addr_inflection": True,
    })
    assert r.status_code == 200
    assert r.json()["text"] == "контролируемая тестовая мера (изменена);"
    assert r.json()["threat_type"] == "phishing"
    assert r.json()["tags"] == "тест, api"
    assert r.json()["addr_inflection"] is True
    r = client.delete(f"/admin/measures/{row['id']}", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "deleted"

    # генерация через gateway (threat уже в БД)
    r = client.post("/reply/generate", params={"doc_id": doc.id}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "generated" and "Ответ на письмо 9/85" in body["text"]

    # кандидат → accept добавляет в библиотеку
    from shared.models import MeasureCandidate
    with SessionLocal() as s:
        c = MeasureCandidate(document_id=doc.id, threat_id=threats[0].id,
                             text="кандидатская тестовая мера;", note="", status="pending")
        s.add(c)
        s.commit()
        cid = c.id
    r = client.post(f"/admin/measures/candidates/{cid}/accept", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "approved"
    with SessionLocal() as s:
        assert s.query(Measure).filter(Measure.text == "кандидатская тестовая мера;").count() == 1
        c = s.query(MeasureCandidate).filter(MeasureCandidate.id == cid).first()
        assert c.status == "approved"
    r = client.post(f"/admin/measures/candidates/{cid}/reject", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert client.get("/admin/measures/candidates", params={"status": "pending"}, headers=h).status_code == 200


def test_inflection_addr_singular_plural(doc_db):
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, "number": 1, "threat_type": "phishing",
               "theme": "Договор", "group_name": "Vortex Werewolf",
               "description": "фишинг"}]
    p_one = plan_reply(db=db, letter_type="hacker", blocks=blocks, addr_count=1, use_llm=False)
    p_many = plan_reply(db=db, letter_type="hacker", blocks=blocks, addr_count=4, use_llm=False)
    m1 = " ".join(m["text"] for m in p_one["blocks"][0]["measures"])
    mN = " ".join(m["text"] for m in p_many["blocks"][0]["measures"])
    assert "к указанному адресу" in m1
    assert "к указанным адресам" in mN


def test_group_name_falls_back_to_description(doc_db):
    db, doc, _ = doc_db
    blocks = [{"id": 0, "number": 16, "threat_type": "malware_attack",
               "group_name": "",
               "description": "Угроза группировки Invincible Werewolf, "
                              "нацеленной на органы государственной власти"}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    assert "Invincible Werewolf" in plan["blocks"][0]["intro"]

    blocks[0]["description"] = (
        "Угроза безопасности информации, связанных с деятельностью "
        "хакерских группировок, осуществляющих фишинговые рассылки")
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    assert "хакерских группировок" in plan["blocks"][0]["intro"]
    assert "Invincible Werewolf" not in plan["blocks"][0]["intro"]


def test_malware_types_extraction_9_70(doc_db):
    """«возможно применение … типов «червь» (CMoon) и «стилер» (WhiteSnake)» (9-70)."""
    db, doc, _ = doc_db
    desc = ("Хакерской группировкой «White Werewolf» возможно применение вредоносного "
            "программного обеспечения типов «червь» (CMoon) и «стилер» (WhiteSnake).")
    blocks = [{"id": 0, "number": 1, "threat_type": "malware_attack",
               "group_name": "White Werewolf", "description": desc}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks, addr_count=1, use_llm=False)
    intro = plan["blocks"][0]["intro"]
    assert "«червь» (CMoon) и «стилер» (WhiteSnake)" in intro
    assert "White Werewolf" in intro


def test_vuln_exploit_priority_9_70(doc_db):
    """Эксплуатация уязвимости → intro vuln_exploit с функцией + BDU + CVSS."""
    db, doc, _ = doc_db
    desc = ("Осуществляется эксплуатация уязвимости функции requireModule() пакетов "
            "react-server-dom-webpack JavaScript библиотеки построения пользовательских "
            "интерфейсов React (BDU:2025-15156, уровень опасности по CVSS 3.1 - критический).")
    blocks = [{"id": 0, "number": 2, "threat_type": "malware_attack", "description": desc}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks, addr_count=1, use_llm=False)
    blk = plan["blocks"][0]
    assert blk["fragment_key"] == ""
    assert "requireModule()" in blk["intro"]
    assert "BDU:2025-15156" in blk["intro"]
    assert "критический" in blk["intro"]


def test_vuln_block_patch_tail(doc_db):
    """Vulnerability-угроза в hacker-письме: intro содержит фразу про обновление (тест pipeline)."""
    db, doc, _ = doc_db
    desc = ("Осуществляется эксплуатация уязвимости BDU:2024-12345 (CVE-2021-44228) "
            "в программном обеспечении Apache Log4j, уровень опасности по CVSS 9.8 — критический. "
            "Необходимо произвести обновление до версии 2.17.0 до 01.06.2025.")
    blocks = [{"id": 0, "number": 1, "threat_type": "vulnerability", "description": desc}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks, addr_count=1, use_llm=False)
    intro = plan["blocks"][0]["intro"]
    assert "BDU:2024-12345" in intro
    assert "обновление до версии" not in intro


def test_measure_variance_repetitive_blocks(doc_db):
    db, doc, _ = doc_db
    desc = ("Осуществляется рассылка вредоносного программного обеспечения; "
            "необходимо ограничить обращения к адресам.")
    blocks = [{"id": 0, "number": i, "threat_type": "malware_attack", "description": desc}
              for i in range(1, 5)]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks, addr_count=1, use_llm=False)
    from shared.generator.templated_reply import load_reply_resources
    core_n = len([m for m in load_reply_resources(db)[0]
                  if "core" in (m.get("tags") or "")])
    assert core_n >= 7, "ядровый набор мер должен быть собран"
    assert len(plan["blocks"][0]["measures"]) == core_n, "полный core — в первом блоке"
    assert len(plan["blocks"][1]["measures"]) < core_n, "повторы не дублируют весь core"
    unique = {m["text"] for b in plan["blocks"] for m in b["measures"]}
    assert unique, "уникальные меры не должны потеряться"


def test_vuln_not_in_cmdb_says_not_used(doc_db):
    """ПО отсутствует в БД заказчика (cmdb_match=False) → «не используется»."""
    db, doc, _ = doc_db
    vulns = [{
        "bdu_id": "BDU:2026-10166",
        "description": ("Уязвимость компонента WebView HTTP Server программного средства "
                        "управления и запуска OCI-контейнеров Podman связана с неконтролируемым "
                        "расходом ресурсов."),
        "software": "управления и запуска OCI-контейнеров Podman",
        "severity": "critical", "cvss_score": 9.8, "cmdb_match": False,
    }]
    text, _ = render_reply(plan={"template_key": "vulnerability", "blocks": [], "llm": False},
                           templates=load_reply_resources(db)[2],
                           letter_number="9/999", letter_date="2026-07-24",
                           org_name="Правительства Липецкой области", active_vulns=vulns)
    assert "Дополнительно сообщаем, что данное программное обеспечение не используется." in text
    assert "ведутся работы по обновлению" not in text


def test_vuln_in_cmdb_uses_update(doc_db):
    db, doc, _ = doc_db
    vulns = [{
        "bdu_id": "BDU:2026-10166",
        "description": ("Уязвимость компонента WebView HTTP Server программного средства "
                        "управления и запуска OCI-контейнеров Podman связана с неконтролируемым "
                        "расходом ресурсов."),
        "software": "управления и запуска OCI-контейнеров Podman",
        "severity": "critical", "cvss_score": 9.8, "cmdb_match": True,
    }]
    text, _ = render_reply(plan={"template_key": "vulnerability", "blocks": [], "llm": False},
                           templates=load_reply_resources(db)[2],
                           letter_number="9/999", letter_date="2026-07-24",
                           org_name="Правительства Липецкой области", active_vulns=vulns)
    assert "ведутся работы по обновлению" in text
    assert "не используется" not in text


def test_vulnerability_card_status_not_used_has_no_compensation():
    vuln = {
        "bdu_id": "BDU:2026-05590", "software": "FortiOs",
        "cmdb_match": False, "is_applicable": False,
        "action_type": "skip", "current_version": "",
        "target_version": "7.6.5",
    }
    status, needs_compensation = _vulnerability_card_status(vuln)
    assert status == "Дополнительно сообщаем, что FortiOs не используется."
    assert needs_compensation is False


def test_bdu_header_contains_all_vulnerabilities():
    desc = (
        "13. Хакерскими группировками, для получения доступа к сетевому "
        "оборудованию осуществляется эксплуатация уязвимости службы fgfmd "
        "программного средства для централизованного управления устройствами "
        "Fortinet FortiManager (BDU:2024-08556, уровень опасности по CVSS 3.1 — "
        "критический). Затем злоумышленниками осуществляется эксплуатация "
        "уязвимости операционных систем FortiOs, системы управления учетными "
        "данными FortiPAM и прокси-сервера для защиты от интернет-атак FortiProxy "
        "(BDU:2026-05590, уровень опасности по CVSS 3.1 — средний) для получения "
        "административных привилегий и дальнейшего внедрения на целевую систему "
        "вредоносного программного обеспечения (PEERSTITCH)."
    )
    intro = _template_intro({"description": desc})
    assert "BDU:2024-08556" in intro
    assert "BDU:2026-05590" in intro
    assert "операционных систем FortiOs" in intro
    assert "PEERSTITCH" not in intro
    assert intro.startswith("деятельностью хакерских группировок, эксплуатирующих")


def test_vulnerability_card_status_uses_description_subject():
    vuln = {
        "bdu_id": "BDU:2025-04927", "software": "SAP NetWeaver",
        "description": (
            "Уязвимость функции MetadataUploader инструмента Visual Composer "
            "программной интеграционной платформы SAP NetWeaver связана с "
            "возможностью неограниченной загрузкой исполняемых файлов."
        ),
        "cmdb_match": False, "is_applicable": False,
        "action_type": "skip",
    }
    status, needs_compensation = _vulnerability_card_status(vuln)
    assert status == (
        "Дополнительно сообщаем, что инструмент Visual Composer программной "
        "интеграционной платформы SAP NetWeaver не используется."
    )
    assert needs_compensation is False


def test_vulnerability_card_status_update_has_no_compensation():
    vuln = {
        "bdu_id": "BDU:2026-99997", "software": "Samba",
        "cmdb_match": True, "is_applicable": True,
        "action_type": "update", "current_version": "4.20.0",
        "target_version": "4.21.0",
    }
    status, needs_compensation = _vulnerability_card_status(vuln)
    assert "ведутся работы по обновлению Samba" in status
    assert needs_compensation is False


def test_vulnerability_card_status_installed_skip_keeps_specific_compensation():
    vuln = {
        "bdu_id": "BDU:2026-00828", "software": "Microsoft Office",
        "cmdb_match": False, "is_applicable": True,
        "action_type": "skip", "current_version": "18.2110.13110.0",
        "action_details": "использование SIEM-систем; изменение ключей реестра",
    }
    status, needs_compensation = _vulnerability_card_status(vuln)
    assert status.endswith("приняты следующие компенсирующие меры:")
    assert needs_compensation is True


def test_vulnerability_card_status_compensate_requires_measures():
    vuln = {
        "bdu_id": "BDU:2026-99995", "software": "Samba",
        "cmdb_match": True, "is_applicable": True,
        "action_type": "compensate",
        "action_details": "ограничен доступ к командной строке для недоверенных пользователей",
    }
    status, needs_compensation = _vulnerability_card_status(vuln)
    assert status.endswith("приняты следующие компенсирующие меры:")
    assert needs_compensation is True


def test_vuln_render_paragraph(doc_db):
    """Vulnerability-письмо: абзац по эталону «Уязвимость <продукт> (BDU:…), связанная с …»."""
    db, doc, _ = doc_db
    doc.letter_type = "vulnerability"
    db.commit()
    vulns = [{
        "bdu_id": "BDU:2026-07317",
        "cve_id": "CVE-2026-1111",
        "description": ("Уязвимость подсистемы печати (printing subsystem) программ сетевого "
                        "взаимодействия Samba связана с непринятием мер по обеспечению "
                        "целостности программного обеспечения. Уровень опасности по CVSS 3.1 — "
                        "критический."),
        "software": "Samba",
        "severity": "critical",
        "cvss_score": 9.8,
        "fixed_version": "",
        "patch_url": "",
        "recommendation": "обновить Samba",
    }]
    plan = {"template_key": "vulnerability", "blocks": [], "llm": False}
    text, _ = render_reply(plan=plan, templates=load_reply_resources(db)[2],
                           letter_number="9/114", letter_date="2026-06-10",
                           org_name="Правительства Липецкой области", active_vulns=vulns)
    assert "Уязвимость подсистемы печати (printing subsystem) программ сетевого" in text
    assert "BDU:2026-07317" in text
    assert "CVE-2026-1111" not in text
    assert "уровень опасности по CVSS 3.1 — критический" in text
    assert ", связанная с непринятием мер" in text
    assert "С уважением" not in text


def test_vuln_letter_llm_plan_blocks(doc_db):
    """Vulnerability-письмо: уязвимость → LLM-блок (меры из плана), абзац без
    хвоста «Эксплуатация уязвимости…», формат «уровень опасности по CVSS {v} — {sev}»."""
    db, doc, _ = doc_db
    doc.letter_type = "vulnerability"
    db.commit()
    from shared.generator.templated_reply import _apply_llm_plan
    vulns = [{
        "bdu_id": "BDU:2026-07317", "cve_id": "CVE-2026-4480",
        "description": ("Уязвимость подсистемы печати (printing subsystem) программ сетевого "
                        "взаимодействия Samba связана с непринятием мер по нейтрализации "
                        "специальных элементов при обработке параметра %J. Уровень опасности по "
                        "CVSS 3.1 — критический. Эксплуатация уязвимости "
                        "может позволить нарушителю, действующему удаленно, выполнить произвольный код"),
        "software": "Samba", "severity": "critical", "cvss_score": 10.0,
        "cvss_version": "", "recommendation": "Обновить Samba",
    }]
    blocks = _vulns_to_blocks(vulns)
    assert blocks[0]["threat_type"] == "vulnerability"
    assert blocks[0]["n"] == 1 and blocks[0]["bdu_id"] == "BDU:2026-07317"
    library, fragments, tpl = load_reply_resources(db)
    lib_by_id = {m["id"]: m for m in library}
    frag_by_key = {f["key"]: f for f in fragments}
    # id мер не хардкодим: библиотека пересобирается из эталонов, порядок/id меняются.
    base_id = next(m["id"] for m in library if "base" in (m["tags"] or ""))
    phish_id = next(m["id"] for m in library if m["threat_type"] == "phishing")
    llm_plan = {"template_key": "vulnerability", "blocks": [
        {"n": 1, "fragment_id": "", "measure_ids": [phish_id, base_id], "new_measures": [
            {"text": "Контроль применения обновлений Samba;", "note": ""}]}]}
    plan = _apply_llm_plan(llm_plan, lib_by_id, frag_by_key, blocks, addr_count=1)
    assert plan and plan["llm"] is True
    blk = plan["blocks"][0]
    assert blk["software"] == "Samba"  # cvss_version из описания подставляется на рендере
    assert len(blk["measures"]) == 2  # base-мера + new_measure; phishing-мера отсечена
    assert blk["measures"][0]["measure_id"] == base_id
    text, _ = render_reply(plan=plan, templates=tpl, letter_number="9/114",
                           letter_date="2026-06-10",
                           org_name="Правительства Липецкой области",
                           active_vulns=vulns, addr_count=1)
    assert "Эксплуатация уязвимости может позволить" not in text
    assert "CVE-2026-4480" not in text
    assert "уровень опасности по CVSS 3.1 — критический" in text
    assert "Уязвимость подсистемы печати (printing subsystem)" in text
    assert "связанная с непринятием мер" in text
    assert "Дополнительно приняты следующие меры:" not in text
    assert "Контроль применения обновлений Samba;" not in text
    assert "ведутся работы по обновлению" in text


def test_vuln_letter_fallback_still_bdu(doc_db):
    """LLM недоступен → vuln-план пустой, рендер остаётся на BDU-описаниях."""
    db, doc, _ = doc_db
    doc.letter_type = "vulnerability"
    db.commit()
    vulns = [{
        "bdu_id": "BDU:2026-07317", "cve_id": "CVE-2026-4480",
        "description": ("Уязвимость подсистемы печати (printing subsystem) программ сетевого "
                        "взаимодействия Samba связана с непринятием мер по нейтрализации "
                        "специальных элементов при обработке параметра %J."),
        "software": "Samba", "severity": "critical", "cvss_score": 10.0,
        "cvss_version": "3.1", "recommendation": "",
    }]
    blocks = _vulns_to_blocks(vulns)
    plan = plan_reply(db=db, letter_type="vulnerability", blocks=blocks,
                      addr_count=1, use_llm=False)
    assert plan["blocks"] == [] and plan["llm"] is False
    text, _ = render_reply(plan=plan, templates=load_reply_resources(db)[2],
                           letter_number="9/114", letter_date="2026-06-10",
                           org_name="Правительства Липецкой области", active_vulns=vulns)
    assert "Уязвимость подсистемы печати" in text
    assert "BDU:2026-07317" in text


def test_backfill_empty_llm_measures(doc_db):
    """Пустой measure_ids от LLM (как у 9B) → блок заполняется fallback-мерами."""
    db, doc, threats = doc_db
    library, _, _ = load_reply_resources(db)
    plan = {"template_key": "hacker", "llm": True, "blocks": [
        {"number": 1, "threat_id": threats[0].id, "fragment_key": "phishing_general",
         "intro": "деятельностью хакерской группировки Vortex Werewolf",
         "threat_type": "phishing", "description": threats[0].description,
         "measures": [], "new_measures": []},
        {"number": 2, "threat_id": threats[1].id, "fragment_key": "",
         "intro": "реализуемыми угрозами безопасности информации",
         "threat_type": "malware_attack", "description": "атака с DCRat",
         "measures": [], "new_measures": []},
    ]}
    _backfill_empty_blocks(plan, "hacker", addr_count=1, library=library)
    blk0 = plan["blocks"][0]
    blk1 = plan["blocks"][1]
    assert blk0["measures"], "фишинг-блок обязан получить антифишинговый набор"
    assert any("песочниц" in m["text"] for m in blk0["measures"])
    assert blk1["measures"], "не-фишинг блок обязан получить базовые меры"
    assert all(m["source"] == "library" for m in blk0["measures"] + blk1["measures"])

def test_software_placeholder_substituted():
    """Шаблон «{{software}} не применяется» -> продукт из блока уязвимости."""
    blk = {"threat_type": "vulnerability", "software": "Samba",
           "description": "Уязвимость подсистемы печати Samba (BDU:2026-07317)"}
    assert _extract_ctx(blk)["software"] == "Samba"
    out = _inflect_measure("{{software}} не применяется", 1, "Samba")
    assert out == "Samba не применяется"
    assert "{{" not in out


def test_software_placeholder_fallback_without_product():
    """Без продукта подставляем нейтральную формулировку, а не оставляем {{...}}:
    неразрешённые плейсхолдеры вырезаются из письма фильтром ниже по коду."""
    out = _inflect_measure("{{software}} не применяется", 1, "")
    assert "{{" not in out
    assert "не применяется" in out


def test_reference_plan_does_not_inject_url_or_sender_without_source(doc_db):
    db, doc, _ = doc_db
    blocks = [{
        "id": 1, "number": 1, "threat_type": "phishing",
        "description": "Фишинговая рассылка.",
        "explicit_measures": [],
    }]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    texts = [m["text"] for m in plan["blocks"][0]["measures"]]
    assert not any("URL-адрес" in text or "анализ ссылок" in text for text in texts)
    assert not any("известных отправителей" in text for text in texts)


def test_source_url_and_sender_measures_are_preserved(doc_db):
    db, doc, _ = doc_db
    blocks = [{
        "id": 1, "number": 1, "threat_type": "phishing",
        "description": "Фишинговая рассылка.",
        "explicit_measures": [
            "Осуществлять автоматическую проверку указанных в письмах URL-адресов",
            "Организовать получение почтовых вложений только от известных отправителей",
        ],
    }]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    texts = [m["text"] for m in plan["blocks"][0]["measures"]]
    assert any("URL-адрес" in text for text in texts)
    assert any("известных отправителей" in text for text in texts)


def test_source_measures_take_precedence_over_reference(doc_db):
    db, doc, _ = doc_db
    blocks = [{
        "id": 1, "number": 1, "threat_type": "phishing",
        "description": "1. Фишинговая рассылка с архивом sample.7z",
        "explicit_measures": [
            "Производить автоматическую проверку вложений с использованием «песочницы»",
            "Осуществлять автоматическую проверку указанных в письмах URL-адресов",
            "Организовать получение почтовых вложений только от известных отправителей",
            "Обеспечить ограничение обращений к указанным адресам",
        ],
    }]
    rep = generate_reply(db=db, doc_id=doc.id, letter_type="hacker",
                         blocks=blocks, addr_count=2, use_llm=False)
    assert "URL-адресов" in rep["text"]
    assert "известных отправителей" in rep["text"]
    assert "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам" in rep["text"]
    assert "в письме и приложении" not in rep["text"]
    assert "песочницы" in rep["text"]


def test_referenced_source_measures_do_not_add_network_measure(doc_db):
    db, doc, _ = doc_db
    blocks = [
        {
            "id": 1, "number": 1, "threat_type": "phishing",
            "description": (
                "1. Фишинговая рассылка. 1.1. Проверка песочницы. "
                "1.2. Проверка антивирусом. 1.3. Проверка URL-адресов. "
                "1.4. Проверка домена. 1.5. Получение вложений от известных "
                "отправителей. 1.6. Не открывать вложения. 1.7. Минимальные привилегии."
            ),
            "explicit_measures": [
                "Проверка песочницы", "Проверка антивирусом", "Проверка URL-адресов",
                "Проверка домена", "Получение вложений от известных отправителей",
                "Не открывать вложения", "Минимальные привилегии",
            ],
        },
        {
            "id": 2, "number": 2, "threat_type": "phishing",
            "description": (
                "2. Фишинговая рассылка. Необходимо реализовать меры, указанные "
                "в пунктах 1.1-1.7. Также необходимо настроить правила системы "
                "мониторинга событий информационной безопасности."
            ),
            "explicit_measures": [
                "Необходимо реализовать меры, указанные в пунктах 1.1-1.7",
                "Необходимо осуществить настройку правил системы мониторинга событий",
            ],
        },
    ]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    second = plan["blocks"][1]["measures"]
    assert any("мониторинга" in m["text"] for m in second)
    assert not any("ограничение обращений" in m["text"].lower() for m in second)


def test_repeated_phishing_header_keeps_only_theme():
    intro = _template_intro({
        "number": 5,
        "threat_type": "phishing",
        "group_name": "",
        "theme": "Документы к авто на 19-20 октября",
        "archive_name": "2026_10_19 UTS.r11",
        "exe_name": "2026_10_19 UTS.exe",
        "malware_type": "загрузчик (GuLoader), троян удаленного доступа (Remcos RAT)",
        "description": "",
    })
    assert "с тематикой «Документы к авто на 19-20 октября»" in intro
    assert "вложением" not in intro
    assert "тип ВПО" not in intro


def test_first_phishing_block_is_detailed_even_with_nonone_number():
    intro = _template_intro({
        "number": 3,
        "phishing_rank": 1,
        "threat_type": "phishing",
        "theme": "Документы",
        "archive_name": "Документы.7z",
        "exe_name": "Документы.pdf.exe",
        "malware_type": "троян удаленного доступа (GrimGazer)",
        "description": "",
    })
    assert "вложением" in intro
    assert "тип ВПО" in intro


def test_attachment_and_malware_intro_is_consistent():
    from shared.generator.templated_reply import _template_intro
    intro = _template_intro({
        "threat_type": "phishing",
        "group_name": "Watch Wolf",
        "theme": "Документы, акты",
        "archive_name": "Документы.7z",
        "exe_name": "Документы.pdf.exe",
        "malware_type": "троян удаленного доступа (GrimGazer)",
        "description": "",
    })
    assert "архив «Документы.7z»" in intro
    assert "содержащий файл «Документы.pdf.exe»" in intro
    assert "тип ВПО — троян удаленного доступа (GrimGazer)" in intro


def test_17_malware_types_are_complete():
    from shared.generator.templated_reply import _template_intro
    intro = _template_intro({
        "threat_type": "malware_attack",
        "description": (
            "Распространяется вредоносное программное обеспечение типов "
            "«загрузчик» (Trojan.Loader.3261), «бэкдор» (AsyncRAT), "
            "«стилер» (JS.Stealer.191) и «троян удаленного доступа» "
            "(Trojan.InjectNET.14)."
        ),
    })
    for value in ("Trojan.Loader.3261", "AsyncRAT", "JS.Stealer.191",
                  "Trojan.InjectNET.14"):
        assert value in intro
    assert "тип ВПО —" not in intro


def test_software_placeholder_in_llm_plan(doc_db):
    """Мера из библиотеки с плейсхолдером доходит до плана уже с продуктом."""
    db, doc, _ = doc_db
    library, _, _ = load_reply_resources(db)
    tpl = next((m for m in library
                if "{{software}}" in (m["text"] or "")
                and (m.get("threat_type") == "vulnerability")), None)
    if tpl is None:
        pytest.skip("в библиотеке нет шаблонных vulnerability-мер")
    blocks = [{"id": 0, "n": 1, "threat_type": "vulnerability",
               "software": "OpenSSL",
               "description": "Уязвимость библиотеки OpenSSL (BDU:2021-00364)"}]
    lib_by_id = {m["id"]: m for m in library}
    llm_plan = {"template_key": "vulnerability", "blocks": [
        {"n": 1, "fragment_id": "", "measure_ids": [tpl["id"]], "new_measures": []}]}
    from shared.generator.templated_reply import _apply_llm_plan
    out = _apply_llm_plan(llm_plan, lib_by_id, {}, blocks, 1)
    texts = [m["text"] for m in out["blocks"][0]["measures"]]
    assert texts, "LLM-выбранная шаблонная мера должна попасть в план"
    assert all("{{" not in t for t in texts)
    assert any("OpenSSL" in t for t in texts)


def test_vuln_update_without_target_renders_bdu_compensation():
    vuln = {
        "bdu_id": "BDU:2026-09906", "software": "Windows",
        "description": "Уязвимость Windows связана с повышением привилегий.",
        "cmdb_match": True, "is_applicable": True,
        "action_type": "update", "target_version": "", "fixed_version": "",
        "action_details": "ограничить сетевой доступ; минимизировать привилегии",
    }
    parts = _vuln_paragraph(vuln, "9-145")
    assert "обновление" in parts[0].lower()
    assert "невозможно" in parts[0].lower()
    assert any("ограничить сетевой доступ" in part for part in parts[1:])


def test_network_measure_is_controlled_by_source_measures():
    from shared.generator.templated_reply import _NETWORK_MEASURE, _enforce_network_measure_policy

    plan = {"blocks": [
        {"number": 1, "measures": [{"text": _NETWORK_MEASURE}, {"text": "core"}]},
        {"number": 2, "measures": [{"text": _NETWORK_MEASURE}, {"text": "core"}]},
    ]}
    blocks = [
        {"number": 1, "explicit_measures": [_NETWORK_MEASURE]},
        {"number": 2, "explicit_measures": ["core measure"]},
    ]
    _enforce_network_measure_policy(plan, blocks)
    assert any(_NETWORK_MEASURE in m["text"] for m in plan["blocks"][0]["measures"])
    assert all(_NETWORK_MEASURE not in m["text"] for m in plan["blocks"][1]["measures"])


def test_vulnerability_card_contains_full_identity_and_compensation():
    from shared.generator.templated_reply import (
        _vulnerability_card_header, _vulnerability_card_measures,
    )

    vuln = {
        "software": "Example Product",
        "cve_id": "CVE-2099-0001",
        "bdu_id": "BDU:2099-0001",
        "severity": "high",
        "cvss_score": 8.1,
        "cvss_version": "3.1",
        "current_version": "1.2.3",
        "recommendation": "use SIEM to monitor exploitation attempts; restrict access to the vulnerable component",
    }
    header = _vulnerability_card_header(vuln)
    measures = _vulnerability_card_measures(vuln)
    for value in ("Example Product", "CVE-2099-0001", "BDU:2099-0001", "CVSS 3.1", "8.1"):
        assert value in header
    assert measures
    assert any("SIEM" in item for item in measures)
