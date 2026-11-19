from tools.measure_audit import (
    _candidate,
    _candidates,
    _match,
    _source_measures,
)


def test_source_measures_skip_letter_header_and_keep_actions():
    text = (
        "ФСТЭК РОССИИ Председателям Комиссий по информационной безопасности "
        "1.1. Производить проверку вложений с использованием песочницы. "
        "1.2. Обеспечить ограничение обращений к адресам."
    )
    measures = _source_measures(text)
    assert any("Производить проверку вложений" in value for value in measures)
    assert any("Обеспечить ограничение" in value for value in measures)
    assert all("Председателям Комиссий" not in value for value in measures)


def test_response_candidates_are_indented_measure_lines():
    text = (
        "Ответ на письмо 9/104\n"
        "1. В целях предотвращения угрозы приняты меры:\n"
        "  производится проверка вложений\n"
        "  осуществляется мониторинг событий.\n"
    )
    candidates = _candidates(text, etalon=False)
    assert [item.text for item in candidates] == [
        "производится проверка вложений",
        "осуществляется мониторинг событий",
    ]


def test_etalon_candidates_include_action_paragraphs():
    text = (
        "Ответ на письмо 9/114\n"
        "Уязвимость Samba (BDU:2026-07317). Samba не используется.\n"
        "Ограничено использование символа подстановки в конфигурации.\n"
        "Дополнительно приняты следующие меры:\n"
    )
    candidates = _candidates(text, etalon=True)
    assert any("Ограничено использование" in item.text for item in candidates)


def test_measure_match_exact_and_fuzzy():
    exact = _candidate("производится проверка вложений")
    candidates = [_candidate("производится проверка вложений")]
    assert _match(exact, candidates)[0] == 1.0

    fuzzy = _candidate("Обеспечить ограничение обращений к адресам")
    paraphrased = _candidate("на уровне сетевых средств обеспечено ограничение обращений к адресам")
    score, _ = _match(fuzzy, [paraphrased])
    assert score >= 0.65
