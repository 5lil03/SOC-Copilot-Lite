from pathlib import Path

import pytest

from src.alert_processor import process_alerts
from src.attack_classifier import ATTACK_RULES, classify_alert

ALERTS_FILE = Path(__file__).resolve().parent.parent / "data" / "alerts.json"


@pytest.mark.parametrize(
    "rule_id, category",
    [
        ("100001", "ssh_bruteforce"),
        ("100002", "port_scanning"),
        ("100003", "suspicious_login"),
        ("100004", "multiple_auth_failures"),
        ("100005", "unknown_activity"),
        ("100006", "account_compromise"),
        ("100007", "failed_login"),
    ],
)
def test_known_rules_get_their_category(rule_id, category):
    assert classify_alert({"rule_id": rule_id})["category"] == category


def test_unknown_rule_falls_back_to_manual_analysis():
    result = classify_alert({"rule_id": "999999"})
    assert result["category"] == "unknown_activity"
    assert result["techniques"] == []


def test_ssh_bruteforce_maps_to_password_guessing():
    technique = classify_alert({"rule_id": "100001"})["techniques"][0]
    assert technique["id"] == "T1110.001"
    assert technique["tactic"] == "Credential Access"


def test_account_compromise_has_two_techniques():
    techniques = classify_alert({"rule_id": "100006"})["techniques"]
    assert [t["id"] for t in techniques] == ["T1110.001", "T1078"]


def test_single_failed_login_has_no_technique():
    assert classify_alert({"rule_id": "100007"})["techniques"] == []


def test_result_states_it_is_a_rule_based_mapping():
    assert "Rule-based" in classify_alert({"rule_id": "100001"})["method"]


def test_every_technique_has_id_name_and_tactic():
    for rule in ATTACK_RULES.values():
        for technique in rule["techniques"]:
            assert set(technique) == {"id", "name", "tactic"}


def test_changing_a_result_does_not_change_the_table():
    result = classify_alert({"rule_id": "100001"})
    result["techniques"].clear()
    assert len(ATTACK_RULES["100001"]["techniques"]) == 1


def test_every_rule_in_alerts_file_has_a_mapping():
    alerts, _ = process_alerts(ALERTS_FILE)
    missing = {a["rule_id"] for a in alerts if a["rule_id"] not in ATTACK_RULES}
    assert missing == set()