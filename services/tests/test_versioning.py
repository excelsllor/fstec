"""Версионный matching (ТЗ 2.4): semver-нормализация, диапазоны, CPE/product-матчи."""
import asyncio

from security_service.enriched import CpeMatch, RangeSpec
from security_service.versioning import (build_range, compare_versions, in_range,
                                         match_cpe, match_product, normalize_version,
                                         product_search_terms, vuln_range_hit)


def test_normalize_version():
    assert normalize_version("1.1.1k") == (1, 1, 1)
    assert normalize_version("2.15.0") == (2, 15, 0)
    assert normalize_version("108.0.1462.42") == (108, 0, 1462, 42)
    assert normalize_version("") is None
    assert normalize_version("openssl") is None


def test_compare_versions():
    assert compare_versions("2.15.0", "2.16.0") == -1
    assert compare_versions("2.17.0", "2.16.0") == 1
    assert compare_versions("1.1.1k", "1.1.1") == 1
    assert compare_versions("1.1.1k", "1.1.1w") == -1
    assert compare_versions("1.1.1k", "1.1.1k") == 0
    assert compare_versions("2.15", "2.15.0") == -1


def test_in_range():
    spec = RangeSpec(min_version="2.0", min_inclusive=False, max_version="2.16.0", max_inclusive=True)
    assert in_range("2.15.0", spec)
    assert in_range("2.16.0", spec)      # max включительно
    assert not in_range("2.0", spec)     # min исключительно
    assert not in_range("2.17.0", spec)
    assert not in_range("abc", spec)
    assert in_range("2.15.0", RangeSpec())  # пустой диапазон не ограничивает


def test_build_range_from_nvd():
    m = build_range("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                    {"versionStartExcluding": "2.0", "versionEndIncluding": "2.16.0"})
    assert m.ranges[0].is_specified
    assert m.ranges[0].min_inclusive is False
    assert m.ranges[0].max_inclusive is True
    assert vuln_range_hit("2.15.0", [m])
    assert not vuln_range_hit("2.17.0", [m])


def test_match_cpe():
    assert match_cpe(["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
                     "cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*")
    assert not match_cpe(["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
                         "cpe:2.3:a:microsoft:edge:108.0:*:*:*:*:*:*:*")


def test_match_product():
    assert match_product("Log4j", "Apache Log4j")
    assert match_product("OpenSSL Project", "openssl")
    assert match_product("Microsoft Edge", "OpenSSL") is False


def test_match_product_aliases():
    assert match_product("python3", "CPython")
    assert match_product("python3-pillow", "Pillow")
    assert match_product("python3-msgpack", "MessagePack")
    assert match_product("librsvg2", "librsvg")
    assert match_product("cifs-utils", "CIFS cifs-utils")
    assert match_product("golang", "Go crypto")
    assert match_product("Office", "Microsoft Office")
    assert match_product("python3", "Python Requests") is False
    assert match_product("trueconf", "TrueConf Server") is False
    assert match_product("Git", "установка Git-сервера Gitea") is False
    assert match_product("Gitea", "установка Git-сервера Gitea") is True


def test_match_product_rejects_component_variants():
    assert match_product("Linux", "Linux")
    assert match_product("wazuh-agent", "Wazuh")
    assert match_product("GitLab EE", "GitLab")
    assert match_product("python3-django", "Django")
    assert match_product("python3-PyYAML", "PyYAML")
    assert match_product("python3-urllib3", "urllib3")
    assert match_product("perl-XML-Parser", "XML::Parser")
    assert not match_product("GitLab Runner", "GitLab")
    assert not match_product("util-linux", "Linux")
    assert not match_product("libselinux", "Linux")
    assert not match_product("netcat-openbsd", "OpenBSD")
    assert not match_product("libraw1394", "RAW-")
    assert not match_product("xml-common", "XML-")
    assert not match_product("python2-netaddr", "NET Framework")
    assert not match_product("net-tools", "NET Framework")
    assert not match_product("Microsoft Edge Update", "Microsoft Edge")
    assert not match_product("linux-firmware-whence", "Linux")
    assert not match_product("Windows Subsystem for Linux", "Linux")
    assert not match_product("Kaspersky Endpoint Security 11.3.0 для Linux", "Linux")
    assert not match_product("MindFusion XML Viewer", "XML-")
    assert not match_product("XML редактор 2", "XML-")
    assert not match_product("XML Конвертер 2", "XML-")


def test_match_product_mariadb_case_insensitive():
    assert match_product("mariadb", "MariaDB")
    assert match_product("mariadb", "mariadb")
    assert match_product("mariadb-server", "MariaDB Server")
    assert match_product("MariaDB", "управления базами данных MariaDB")


def test_product_search_terms_include_glpi_package_alias():
    assert "python3-pillow" in product_search_terms("Pillow")
    assert "python3-requests" in product_search_terms("Requests")
    assert "librsvg2" in product_search_terms("librsvg")
    assert "Office" in product_search_terms("Microsoft Office")


def test_match_product_extracts_latin_name_from_russian_description():
    assert match_product("python3-pillow", "для работы с изображениями Pillow")
    assert match_product("python3-requests",
                         "HTTP запросов языка программирования Python Requests")
    assert match_product("librsvg2", "отрисовки векторной графики librsvg")
    assert match_product("golang", "для языка программирования Go crypto")
    assert "python3-pillow" in product_search_terms("для работы с изображениями Pillow")


async def _async_hit():
    return True


def test_vuln_range_hit_multi():
    m1 = CpeMatch(criteria="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                  ranges=[RangeSpec(max_version="1.1.1k", max_inclusive=True)])
    assert vuln_range_hit("1.1.1k", [m1])
    assert not vuln_range_hit("3.0.0", [m1])