import sys
import os
import pytest

pkg = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if pkg not in sys.path:
    sys.path.insert(0, pkg)

from app.extractor.ioc_extractor import extract_iocs, _clean_domain
from app.generator.response_generator import _inflect_addresses, _canonical_product


def test_defanged_domain_url_extracted():
    text = "ограничение обращений к URL-адресу hxxps[:]//github[.]com/clawsights/"
    iocs = extract_iocs(text)
    assert "github.com" in iocs.domains


def test_defanged_domain_bypasses_common_filter():
    # github.com normally filtered out, but in hxxps[:]// defanged URL must be kept
    text = "компрометация, hxxps[:]//github[.]com/repo"
    iocs = extract_iocs(text)
    assert "github.com" in iocs.domains


def test_plain_common_domain_still_filtered():
    from app.extractor.ioc_extractor import COMMON_DOMAINS
    text = "скачивание по ссылке https://raw.githubusercontent.com/x"
    iocs = extract_iocs(text)
    assert "raw.githubusercontent.com" not in iocs.domains


def test_defanged_ip_from_hxxps_url():
    text = "адрес hxxps://1[.]2[.]3[.]4/path"
    iocs = extract_iocs(text)
    assert "1.2.3.4" in iocs.ips


def test_clean_domain_variants():
    cases = {
        "hxxps[:]//github.com": "github.com",
        "hxxps://x.com": "x.com",
        "hxxp://a.b": "a.b",
        "https://foo.com/path": "foo.com",
    }
    for raw, expected in cases.items():
        assert _clean_domain(raw) == expected


def test_inflect_singular():
    m = ["на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;"]
    out = _inflect_addresses(m, 1)
    assert "к указанному адресу" in out[0]
    assert "адресам" not in out[0]


def test_inflect_plural():
    m = ["...обращений к указанным адресам;"]
    assert "адресам" in _inflect_addresses(m, 2)[0]


def test_inflect_unknown_count_keeps_plural():
    m = ["...обращений к указанным адресам;"]
    assert "адресам" in _inflect_addresses(m, 0)[0]


def test_canonical_product_trueconf():
    assert _canonical_product("программного обеспечения «trueconf server»") == "программного обеспечения «TrueConf Server»"


def test_canonical_product_returns_original_if_unknown():
    assert _canonical_product("программного обеспечения «FooBar»") == "программного обеспечения «FooBar»"
