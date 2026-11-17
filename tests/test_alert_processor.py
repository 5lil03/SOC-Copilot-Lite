from datetime import datetime
from pathlib import Path

import pytest

from src.alert_processor import (
    classify_severity,
    load_alerts,
    normalize_alert,
    process_alerts,
    validate_alert,
    validate_alerts,
)

# Absolute path to data/alerts.json, whatever folder pytest is launched from.
ALERTS_FILE = Path(__file__).resolve().parent.parent / "data" / "alerts.json"


def make_alert():
    """Return a fresh, valid alert. Tests modify it to create errors."""
    return {
        "id": "TEST-001",
        "timestamp": "2026-11-13T08:15:02+00:00",
        "rule": {"id": "100001", "level": 10, "description": "Test rule"},
        "data": {"srcip": "203.0.113.45", "dstip": "10.0.5.10"},
    }


@pytest.mark.parametrize(
    "level, expected",
    [
        (0, "low"), (3, "low"),
        (4, "medium"), (7, "medium"),
        (8, "high"), (11, "high"),
        (12, "critical"), (15, "critical"),
    ],
)
def test_classify_severity_boundaries(level, expected):
    assert classify_severity(level) == expected


def test_load_alerts_returns_the_eight_synthetic_alerts():
    alerts = load_alerts(ALERTS_FILE)
    assert len(alerts) == 8


def test_valid_alert_has_no_problems():
    assert validate_alert(make_alert()) == []


def test_missing_source_ip_is_reported():
    alert = make_alert()
    del alert["data"]["srcip"]
    assert "missing field: data.srcip" in validate_alert(alert)


def test_level_out_of_range_is_reported():
    alert = make_alert()
    alert["rule"]["level"] = 99
    assert "rule.level must be an integer between 0 and 15" in validate_alert(alert)


def test_invalid_timestamp_is_reported():
    alert = make_alert()
    alert["timestamp"] = "yesterday"
    assert "timestamp is not a valid ISO 8601 date" in validate_alert(alert)


def test_non_dictionary_alert_is_rejected():
    assert validate_alert("not an alert") == ["alert is not a JSON object"]


def test_validate_alerts_separates_valid_and_rejected():
    broken = make_alert()
    del broken["rule"]
    valid, rejected = validate_alerts([make_alert(), broken])
    assert len(valid) == 1
    assert len(rejected) == 1
    assert rejected[0]["position"] == 1


def test_normalize_alert_builds_flat_dictionary():
    normalized = normalize_alert(make_alert())
    assert normalized["alert_id"] == "TEST-001"
    assert normalized["source_ip"] == "203.0.113.45"
    assert normalized["severity"] == "high"
    assert isinstance(normalized["timestamp"], datetime)


def test_normalize_alert_uses_none_for_optional_fields():
    normalized = normalize_alert(make_alert())
    assert normalized["username"] is None
    assert normalized["destination_port"] is None


def test_process_alerts_on_the_synthetic_file():
    alerts, rejected = process_alerts(ALERTS_FILE)
    assert len(alerts) == 8
    assert rejected == []
    severities = [alert["severity"] for alert in alerts]
    assert severities.count("critical") == 1