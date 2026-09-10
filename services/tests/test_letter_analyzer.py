from shared.extractor.letter_analyzer import analyze_letter
from conftest import SAMPLE_TEXT


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