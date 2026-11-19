from shared.extractor.letter_analyzer import analyze_letter, letter_number_from_filename
from conftest import SAMPLE_TEXT


def test_letter_number_from_filename():
    assert letter_number_from_filename("Проект мер № 9-213.doc") == "9/213"
    assert letter_number_from_filename("9-208.pdf") == "9/208"
    assert letter_number_from_filename("2026-11-09.pdf") == ""


def test_letter_number_and_date():
    info = analyze_letter(SAMPLE_TEXT)
    assert info.letter_number == "456/1"
    assert info.letter_date == "2024-03-15"
    assert info.letter_type == "hacker"


def test_threats_parsed():
    info = analyze_letter(SAMPLE_TEXT)
    assert len(info.threats) == 2
    assert info.threats[0].archive_name == "doc.zip"
    assert info.threats[1].threat_type == "vulnerability"


def test_threat_group_and_type():
    info = analyze_letter(SAMPLE_TEXT)
    assert info.threats[0].group_name == "Rare Werewolf"
    assert info.threats[0].threat_type == "phishing"
    assert info.threats[1].group_name == "Cloud Werewolf"


def test_referenced_measures_are_expanded_from_shared_catalog():
    text = """
    1. Хакерской группировкой Watch Wolf осуществляются фишинговые рассылки
    электронных писем с тематикой «Документы, акты». Во вложениях прикреплен архив
    с наименованием «Документы.7z», содержащий исполняемый файл
    с наименованием «Документы.pdf.exe».
    1.1. Производить автоматическую проверку вложений с использованием «песочницы».
    1.2. Производить проверку почтовых вложений средствами антивирусной защиты.
    1.3. Осуществлять автоматическую проверку указанных в письмах URL-адресов.
    1.4. Проверять имя домена отправителя электронного письма.
    1.5. Организовать получение почтовых вложений только от известных отправителей.
    1.6. Не открывать и не загружать почтовые вложения.
    1.7. Работать с электронной почтой под учетными записями с минимальными привилегиями.
    2. Хакерской группировкой Clubfoot Wolf осуществляются фишинговые рассылки.
    Необходимо реализовать меры защиты, указанные в пунктах 1.1-1.7.
    Кроме того, необходимо обеспечить ограничение обращений к адресу bad[.]example.
    Также необходимо осуществить настройку правил системы мониторинга событий.
    3. Хакерскими группировками осуществляются фишинговые рассылки.
    Необходимо реализовать меры защиты, указанные в пунктах 1.1-1.7.
    Также необходимо осуществить настройку правил системы мониторинга событий.
    """
    info = analyze_letter(text)
    assert len(info.threats) == 3

    first = info.threats[0]
    assert len(first.measures) == 7
    assert any("URL" in measure for measure in first.measures)
    assert any("известных отправителей" in measure for measure in first.measures)

    second = info.threats[1]
    assert len(second.measures) == 9
    assert any("песочницы" in measure for measure in second.measures)
    assert any("bad[.]example" in measure for measure in second.measures)

    third = info.threats[2]
    assert len(third.measures) == 8
    assert not any("ограничение обращений" in measure.lower()
                   for measure in third.measures)


def test_numbered_measures_are_kept_whole():
    from shared.extractor.letter_analyzer import _extract_measures
    section = (
        "необходимо принять следующие меры защиты. "
        "1.1. Производить автоматическую проверку вложений. "
        "1.2. Производить проверку антивирусом: для Kaspersky включить функцию; "
        "для Dr.Web использовать SpIDer Mail. "
        "1.3. Обеспечить ограничение обращений к адресам: 45[.]156[.]87[.]120."
    )
    measures = _extract_measures(section)
    assert len(measures) == 3
    assert measures[0].startswith("Производить автоматическую")
    assert "Kaspersky" in measures[1] and "SpIDer Mail" in measures[1]
    assert "45[.]156[.]87[.]120" in measures[2]
