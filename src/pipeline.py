"""Glue code: run modules 1 to 4 on every alert and return one record per incident."""

from pathlib import Path

from src.alert_processor import process_alerts
from src.attack_classifier import classify_alert
from src.ioc_enrichment import enrich_alert, load_ioc_database
from src.rag_engine import build_index, build_query, load_playbooks, retrieve

ROOT = Path(__file__).resolve().parent.parent


def analyze_alerts(root=ROOT):
    """Run the full analysis pipeline.

    Return (incidents, rejected). Each incident is a dictionary with four keys:
    alert, enrichment, classification, playbooks."""
    root = Path(root)
    alerts, rejected = process_alerts(root / "data" / "alerts.json")
    ioc_db = load_ioc_database(root / "data" / "ioc_database.csv")
    index = build_index(load_playbooks(root / "playbooks"))

    incidents = []
    for alert in alerts:
        classification = classify_alert(alert)
        incidents.append(
            {
                "alert": alert,
                "enrichment": enrich_alert(alert, ioc_db),
                "classification": classification,
                "playbooks": retrieve(build_query(alert, classification), index),
            }
        )
    return incidents, rejected