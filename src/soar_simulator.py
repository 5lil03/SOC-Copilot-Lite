"""Module 6 - SOAR simulator: recommended actions, analyst approval, simulated execution.

IMPORTANT: this module never touches a network, a firewall, an account or a file.
Approving an action only writes one line in the history (a list in memory)."""

import csv
import io
from datetime import datetime, timezone

ACTION_LABELS = {
    "block_ip": "Recommend blocking the source IP at the firewall",
    "review_account": "Recommend account review (password reset, active sessions)",
    "escalate": "Escalate the incident to the incident response lead",
    "mark_investigated": "Mark the incident as investigated",
    "close": "Close the incident after analyst review",
}

LOG_FIELDS = ["timestamp", "alert_id", "action_id", "action", "approval", "execution", "note"]

# Status of an incident, from the least to the most advanced.
STATUS_ORDER = ["open", "investigated", "escalated", "closed"]
STATUS_BY_ACTION = {"mark_investigated": "investigated", "escalate": "escalated", "close": "closed"}

BLOCKABLE_CATEGORIES = ("ssh_bruteforce", "port_scanning", "account_compromise")
ACCOUNT_CATEGORIES = ("suspicious_login", "multiple_auth_failures", "account_compromise")


def recommend_actions(incident):
    """Return the list of actions proposed to the analyst for one incident.

    Each action is {"action_id", "label", "reason"}. The rules are simple and visible:
    category, severity and IOC status decide which actions are proposed."""
    alert = incident["alert"]
    category = incident["classification"]["category"]
    source = incident["enrichment"]["source"]
    actions = []

    def add(action_id, reason):
        actions.append({"action_id": action_id, "label": ACTION_LABELS[action_id], "reason": reason})

    if category in BLOCKABLE_CATEGORIES and source["status"] in ("known", "unknown"):
        if source["status"] == "known":
            add("block_ip", f"Source IP {source['ip']} is listed in the local IOC database. "
                            "Block only after analyst validation.")
        else:
            add("block_ip", f"Source IP {source['ip']} is unknown to the local IOC database. "
                            "Verify it before any blocking.")

    if category in ACCOUNT_CATEGORIES:
        account = alert["username"] if alert["username"] is not None else "the involved account"
        add("review_account", f"{account} may be targeted or compromised. Check recent activity.")

    if alert["severity"] == "critical" or category in ("account_compromise", "unknown_activity"):
        add("escalate", "Critical impact or unexplained activity: a senior analyst should decide.")

    add("mark_investigated", "Record that an analyst reviewed this alert and its evidence.")

    if alert["severity"] == "low":
        add("close", "Low severity: close after the analyst has reviewed it.")

    return actions


def find_decision(log, alert_id, action_id):
    """Return the recorded decision for this alert and action, or None."""
    for entry in log:
        if entry["alert_id"] == alert_id and entry["action_id"] == action_id:
            return entry
    return None


def approval_blocker(log, alert_id, action_id):
    """Return a message if the action cannot be approved yet, otherwise None."""
    if action_id == "close":
        investigated = find_decision(log, alert_id, "mark_investigated")
        if investigated is None or investigated["approval"] != "approved":
            return "Mark the incident as investigated first."
    return None


def record_decision(log, alert_id, action, decision, now=None):
    """Record the analyst decision (approved or rejected) and return the new history entry.

    An approved action is only SIMULATED: nothing is changed in any system."""
    if decision not in ("approved", "rejected"):
        raise ValueError("decision must be 'approved' or 'rejected'")
    if find_decision(log, alert_id, action["action_id"]) is not None:
        raise ValueError("This action already has a decision.")
    if decision == "approved":
        blocker = approval_blocker(log, alert_id, action["action_id"])
        if blocker:
            raise ValueError(blocker)

    moment = now or datetime.now(timezone.utc)
    entry = {
        "timestamp": moment.strftime("%Y-%m-%d %H:%M:%S"),
        "alert_id": alert_id,
        "action_id": action["action_id"],
        "action": action["label"],
        "approval": decision,
        "execution": "simulated" if decision == "approved" else "not executed",
        "note": (
            "Simulation only: no change was made to any system."
            if decision == "approved"
            else "Rejected by the analyst."
        ),
    }
    log.append(entry)
    return entry


def incident_status(log, alert_id):
    """open, investigated, escalated or closed, from the approved actions."""
    status = "open"
    for entry in log:
        if entry["alert_id"] == alert_id and entry["approval"] == "approved":
            new_status = STATUS_BY_ACTION.get(entry["action_id"])
            if new_status and STATUS_ORDER.index(new_status) > STATUS_ORDER.index(status):
                status = new_status
    return status


def count_handled(log, alert_ids):
    """Number of incidents that are no longer open (investigated, escalated or closed)."""
    return sum(1 for alert_id in alert_ids if incident_status(log, alert_id) != "open")


def log_to_csv(log):
    """The action history as CSV text (for download)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=LOG_FIELDS)
    writer.writeheader()
    writer.writerows(log)
    return buffer.getvalue()