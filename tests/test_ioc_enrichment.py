from pathlib import Path

import pytest

from src.ioc_enrichment import enrich_alert, enrich_ip, load_ioc_database

IOC_FILE = Path(__file__).resolve().parent.parent / "data" / "ioc_database.csv"

EXPECTED_KEYS = {"ip", "status", "threat_category", "confidence", "source", "description"}


@pytest.fixture
def ioc_db():
    """The real IOC database, loaded fresh for each test that asks for it."""
    return load_ioc_database(IOC_FILE)


def test_ioc_database_is_loaded(ioc_db):
    assert len(ioc_db) == 5
    assert "203.0.113.45" in ioc_db


@pytest.mark.parametrize(
    "ip, expected_status",
    [
        ("203.0.113.45", "known"),
        ("203.0.113.77", "unknown"),
        ("198.51.100.200", "unknown"),
        ("192.0.2.99", "unknown"),
        ("10.0.5.10", "private"),
        ("192.168.1.45", "private"),
        ("172.16.0.1", "private"),
        ("172.31.255.255", "private"),
        ("127.0.0.1", "private"),
        ("172.15.255.255", "unknown"),  # just below 172.16.0.0/12
        ("172.32.0.1", "unknown"),      # just above 172.16.0.0/12
        ("999.1.1.1", "invalid"),
        ("not-an-ip", "invalid"),
        ("", "invalid"),
        ("1.2.3", "invalid"),
        ("10.0.0.256", "invalid"),
        (None, "invalid"),
    ],
)
def test_ip_status(ip, expected_status, ioc_db):
    assert enrich_ip(ip, ioc_db)["status"] == expected_status


def test_known_ip_returns_ioc_details(ioc_db):
    result = enrich_ip("203.0.113.45", ioc_db)
    assert result["threat_category"] == "ssh_bruteforce"
    assert result["confidence"] == "high"
    assert result["source"] == "synthetic-lab-feed"


def test_unknown_ip_is_not_called_malicious(ioc_db):
    result = enrich_ip("203.0.113.77", ioc_db)
    assert result["threat_category"] is None
    assert result["confidence"] is None
    assert "not evidence" in result["description"]


def test_whitespace_around_ip_is_ignored(ioc_db):
    assert enrich_ip("  203.0.113.45 ", ioc_db)["status"] == "known"


def test_enrich_alert_enriches_source_and_destination(ioc_db):
    alert = {"source_ip": "203.0.113.45", "destination_ip": "10.0.5.10"}
    result = enrich_alert(alert, ioc_db)
    assert result["source"]["status"] == "known"
    assert result["destination"]["status"] == "private"


@pytest.mark.parametrize("ip", ["203.0.113.45", "203.0.113.77", "10.0.5.10", "bad"])
def test_result_always_has_the_same_keys(ip, ioc_db):
    assert set(enrich_ip(ip, ioc_db)) == EXPECTED_KEYS