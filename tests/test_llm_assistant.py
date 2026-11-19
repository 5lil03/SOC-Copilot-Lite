import pytest

from src.llm_assistant import (
    SECTION_TITLES,
    extract_section_items,
    generate_template_report,
    order_playbooks,
    report_to_text,
)
from src.pipeline import analyze_alerts

SAMPLE_PLAYBOOK = """# Title

## Investigation steps
1. First step.
2. Second step.

## Recommended actions (require analyst approval)
- Action one.
- Action two.

## Escalation
Escalate if needed.
"""


@pytest.fixture(scope="module")
def incidents():
    items, _ = analyze_alerts()
    return {item["alert"]["alert_id"]: item for item in items}


def test_extract_numbered_items():
    assert extract_section_items(SAMPLE_PLAYBOOK, "investigation steps") == [
        "First step.",
        "Second step.",
    ]


def test_extract_bulleted_items():
    assert extract_section_items(SAMPLE_PLAYBOOK, "recommended actions") == [
        "Action one.",
        "Action two.",
    ]


def test_extract_from_missing_section_returns_empty_list():
    assert extract_section_items(SAMPLE_PLAYBOOK, "does not exist") == []


def test_every_report_has_all_eight_sections_filled(incidents):
    for incident in incidents.values():
        report = generate_template_report(incident)
        for key, _ in SECTION_TITLES:
            assert report[key], f"empty section {key} for {incident['alert']['alert_id']}"
        assert len(SECTION_TITLES) == 8


def test_steps_and_actions_come_from_the_retrieved_playbook(incidents):
    report = generate_template_report(incidents["ALERT-001"])
    assert report["sources"] == ["ssh_bruteforce.md"]
    assert report["investigation_steps"][0].startswith("Identify the source IP address")
    assert any("blocking the source IP" in action for action in report["remediation_actions"])


def test_account_compromise_alert_uses_the_account_playbook_first(incidents):
    report = generate_template_report(incidents["ALERT-006"])
    assert report["sources"][0] == "account_compromise.md"
    assert report["investigation_steps"][0].startswith("Establish the timeline")


def test_order_playbooks_puts_the_category_playbook_first(incidents):
    ordered = order_playbooks(incidents["ALERT-006"])
    assert [match["source"] for match in ordered][0] == "account_compromise.md"


def test_alert_without_playbook_says_so(incidents):
    report = generate_template_report(incidents["ALERT-005"])
    assert report["sources"] == []
    assert any("No playbook reached" in item for item in report["limitations"])
    assert any("manual analysis" in item.lower() for item in report["investigation_steps"])


def test_unknown_ip_is_flagged_as_uncertain(incidents):
    report = generate_template_report(incidents["ALERT-003"])
    assert any("source IP is unknown" in item for item in report["limitations"])


def test_known_ip_is_described_as_synthetic_database_entry(incidents):
    report = generate_template_report(incidents["ALERT-001"])
    assert any("(synthetic) IOC database" in line for line in report["evidence"])


def test_severity_section_reflects_the_alert(incidents):
    assert generate_template_report(incidents["ALERT-006"])["severity"].startswith("CRITICAL")
    assert generate_template_report(incidents["ALERT-008"])["severity"].startswith("LOW")


def test_report_never_claims_an_action_was_executed(incidents):
    for incident in incidents.values():
        text = report_to_text(generate_template_report(incident)).lower()
        assert "nothing has been executed" in text


def test_report_is_deterministic(incidents):
    first = generate_template_report(incidents["ALERT-002"])
    second = generate_template_report(incidents["ALERT-002"])
    assert first == second


def test_report_text_contains_every_section_title(incidents):
    text = report_to_text(generate_template_report(incidents["ALERT-004"]))
    for _, title in SECTION_TITLES:
        assert title in text