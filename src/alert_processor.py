"""Module 1 - Alert processing: load and validate security alerts."""

import json
from datetime import datetime

# Each entry is the "path" to a field inside the alert.
# ("rule", "level") means alert["rule"]["level"].
REQUIRED_FIELDS = [
    ("id",),
    ("timestamp",),
    ("rule", "id"),
    ("rule", "level"),
    ("rule", "description"),
    ("data", "srcip"),
    ("data", "dstip"),
]


def load_alerts(path):
    """Read a JSON file and return the list of raw alerts."""
    with open(path, encoding="utf-8") as f:
        alerts = json.load(f)
    if not isinstance(alerts, list):
        raise ValueError("The alerts file must contain a JSON list.")
    return alerts


def get_field(alert, path):
    """Follow a path such as ("rule", "level") inside nested dictionaries.
    Return None if any step is missing."""
    value = alert
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def validate_alert(alert):
    """Return the list of problems found in one alert (empty list = valid)."""
    if not isinstance(alert, dict):
        return ["alert is not a JSON object"]

    problems = []

    for path in REQUIRED_FIELDS:
        value = get_field(alert, path)
        if value is None or value == "":
            problems.append("missing field: " + ".".join(path))

    level = get_field(alert, ("rule", "level"))
    if level is not None and (not isinstance(level, int) or not 0 <= level <= 15):
        problems.append("rule.level must be an integer between 0 and 15")

    timestamp = get_field(alert, ("timestamp",))
    if timestamp is not None:
        try:
            datetime.fromisoformat(timestamp)
        except (TypeError, ValueError):
            problems.append("timestamp is not a valid ISO 8601 date")

    return problems


def validate_alerts(alerts):
    """Split alerts into (valid_alerts, rejected).
    Each rejected item is {"position": index in the file, "problems": [...]}."""
    valid = []
    rejected = []
    for position, alert in enumerate(alerts):
        problems = validate_alert(alert)
        if problems:
            rejected.append({"position": position, "problems": problems})
        else:
            valid.append(alert)
    return valid, rejected


if __name__ == "__main__":
    alerts = load_alerts("data/alerts.json")
    valid, rejected = validate_alerts(alerts)
    print(f"Loaded: {len(alerts)} | Valid: {len(valid)} | Rejected: {len(rejected)}")
    for item in rejected:
        print(item)