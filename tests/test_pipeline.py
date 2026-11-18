from src.pipeline import analyze_alerts


def find(incidents, alert_id):
    return next(item for item in incidents if item["alert"]["alert_id"] == alert_id)


def test_pipeline_analyzes_all_eight_alerts():
    incidents, rejected = analyze_alerts()
    assert len(incidents) == 8
    assert rejected == []


def test_each_incident_has_the_four_sections():
    incidents, _ = analyze_alerts()
    for item in incidents:
        assert set(item) == {"alert", "enrichment", "classification", "playbooks"}


def test_critical_alert_is_enriched_classified_and_matched():
    incidents, _ = analyze_alerts()
    item = find(incidents, "ALERT-006")
    sources = [match["source"] for match in item["playbooks"]["matches"]]
    assert item["alert"]["severity"] == "critical"
    assert item["enrichment"]["source"]["status"] == "known"
    assert item["classification"]["category"] == "account_compromise"
    assert "account_compromise.md" in sources


def test_unrelated_alert_has_no_playbook():
    incidents, _ = analyze_alerts()
    item = find(incidents, "ALERT-005")
    assert item["playbooks"]["found"] is False
    assert item["enrichment"]["destination"]["status"] == "unknown"