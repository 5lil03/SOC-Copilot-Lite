"""Module 3 - Attack classification with a rule-based MITRE ATT&CK mapping."""

METHOD_NOTE = (
    "Rule-based mapping of our own detection rules, "
    "not an automatic MITRE ATT&CK detection engine."
)

# Key = rule id found in the alerts. Value = category + MITRE references + reason.
ATTACK_RULES = {
    "100001": {
        "category": "ssh_bruteforce",
        "techniques": [
            {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
        ],
        "reason": "Many failed SSH logins from one source match repeated password guessing.",
    },
    "100002": {
        "category": "port_scanning",
        "techniques": [
            {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
        ],
        "reason": "Many distinct ports probed in a short time match active scanning.",
    },
    "100003": {
        "category": "suspicious_login",
        "techniques": [
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        ],
        "reason": "A valid account was used at an unusual time from a new IP address.",
    },
    "100004": {
        "category": "multiple_auth_failures",
        "techniques": [
            {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        ],
        "reason": "Repeated failed logons for one account may be password guessing, "
                  "but a user who forgot a password is also possible.",
    },
    "100005": {
        "category": "unknown_activity",
        "techniques": [],
        "reason": "Unusual outbound connection with no known technique. Manual analysis is needed.",
    },
    "100006": {
        "category": "account_compromise",
        "techniques": [
            {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        ],
        "reason": "A successful login after many failures suggests the guessed credentials worked.",
    },
    "100007": {
        "category": "failed_login",
        "techniques": [],
        "reason": "A single failed login is not enough evidence to map to an attack technique.",
    },
}

UNKNOWN_ATTACK = {
    "category": "unknown_activity",
    "techniques": [],
    "reason": "No predefined mapping for this rule. Manual analysis is needed.",
}


def classify_alert(alert):
    """Return the attack category and MITRE ATT&CK references of a normalized alert."""
    rule = ATTACK_RULES.get(alert["rule_id"], UNKNOWN_ATTACK)
    return {
        "category": rule["category"],
        "techniques": list(rule["techniques"]),
        "reason": rule["reason"],
        "method": METHOD_NOTE,
    }


if __name__ == "__main__":
    from src.alert_processor import process_alerts

    alerts, _ = process_alerts("data/alerts.json")
    for alert in alerts:
        result = classify_alert(alert)
        ids = ", ".join(t["id"] for t in result["techniques"]) or "-"
        print(f"{alert['alert_id']} | {result['category']:<22} | {ids}")