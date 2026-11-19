"""Module 5 - Incident report generation (template version, works without any LLM)."""

import re

SEVERITY_NOTE = (
    "Thresholds used by this project: 0-3 low, 4-7 medium, 8-11 high, 12-15 critical "
    "(project convention, not an official Wazuh scale)."
)

WHY_IT_MATTERS = {
    "ssh_bruteforce": (
        "Repeated password guessing against SSH can give an attacker remote access to the "
        "server if one guess succeeds. The risk is higher when SSH is exposed to the internet."
    ),
    "port_scanning": (
        "Port scanning is usually reconnaissance: the source is mapping which services are "
        "reachable, often before an attack."
    ),
    "suspicious_login": (
        "A valid account used at an unusual time from a new source can mean stolen credentials. "
        "A successful login is more serious than a failed one because access was granted."
    ),
    "multiple_auth_failures": (
        "Repeated failed logons can indicate password guessing, but they are also caused by "
        "users who forgot a password, so the real cause must be checked."
    ),
    "account_compromise": (
        "A successful login after many failed attempts suggests that guessed credentials may "
        "have worked. The attacker may now act as a legitimate user."
    ),
    "failed_login": (
        "A single failed login is common and usually harmless. It matters only if it is part "
        "of a larger pattern."
    ),
    "unknown_activity": (
        "This activity does not match any predefined category. It is unusual, but there is not "
        "enough information to say that it is malicious."
    ),
}

NO_PLAYBOOK_STEPS = [
    "No playbook is available for this alert. Review the raw log line and the alert context.",
    "Check the IP addresses in the threat intelligence sources available to you.",
    "Escalate to a senior analyst for manual analysis if the activity remains unexplained.",
]

NO_PLAYBOOK_ACTIONS = [
    "No action is proposed automatically. The analyst decides after manual analysis.",
]

SECTION_TITLES = [
    ("summary", "1. Incident summary"),
    ("attack_type", "2. Detected attack type"),
    ("severity", "3. Severity assessment"),
    ("evidence", "4. Evidence"),
    ("why_it_matters", "5. Why this incident matters"),
    ("investigation_steps", "6. Investigation recommendations"),
    ("remediation_actions", "7. Proposed remediation actions (not executed, analyst approval required)"),
    ("limitations", "8. Limitations and uncertainty"),
]


def extract_section_items(playbook_text, heading_start):
    """Return the numbered or bulleted items of the '## ...' section of a playbook
    whose heading starts with heading_start."""
    items = []
    inside = False
    for line in playbook_text.splitlines():
        if line.startswith("## "):
            inside = line[3:].strip().lower().startswith(heading_start.lower())
            continue
        if inside:
            match = re.match(r"^(?:[-*]|\d+\.)\s+(.*)$", line.strip())
            if match:
                items.append(match.group(1))
    return items


def order_playbooks(incident):
    """Retrieved playbooks, with the one named after the attack category first."""
    category_file = incident["classification"]["category"] + ".md"
    matches = incident["playbooks"]["matches"]
    return sorted(matches, key=lambda match: match["source"] != category_file)


def describe_ip(role, result):
    """One evidence line about an IP address and its enrichment status."""
    label = f"{role.capitalize()} IP {result['ip']}"
    if result["status"] == "known":
        return (
            f"{label}: listed in the local (synthetic) IOC database as "
            f"{result['threat_category']} (confidence {result['confidence']})."
        )
    if result["status"] == "unknown":
        return (
            f"{label}: not in the local IOC database (unknown, "
            "which is not evidence that it is safe or malicious)."
        )
    if result["status"] == "private":
        return f"{label}: internal address."
    return f"{label}: not a valid IP address."


def describe_techniques(classification):
    if not classification["techniques"]:
        return "No MITRE ATT&CK technique is mapped to this category"
    return "; ".join(
        f"{t['id']} {t['name']} ({t['tactic']})" for t in classification["techniques"]
    )


def build_evidence(incident):
    """List the facts that come directly from the alert and from the enrichment."""
    alert = incident["alert"]
    evidence = [
        f"Time (UTC): {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}",
        f"Rule {alert['rule_id']} (level {alert['level']}): {alert['description']}",
        describe_ip("source", incident["enrichment"]["source"]),
        describe_ip("destination", incident["enrichment"]["destination"]),
    ]
    if alert["agent_name"] is not None:
        evidence.append(f"Reporting host: {alert['agent_name']}")
    if alert["username"] is not None:
        evidence.append(f"Account involved: {alert['username']}")
    if alert["destination_port"] is not None:
        evidence.append(f"Destination port: {alert['destination_port']}")
    if alert["full_log"] is not None:
        evidence.append(f"Log line: {alert['full_log']}")
    return evidence


def build_limitations(incident, matches):
    """List what we do not know, so the analyst is not misled."""
    classification = incident["classification"]
    retrieval = incident["playbooks"]
    limitations = [
        "This report is built from one alert and fixed templates. It is not a full investigation.",
        f"Classification method: {classification['method']}",
        "All data is synthetic. Every action is only a recommendation: nothing has been executed.",
    ]
    for role in ("source", "destination"):
        if incident["enrichment"][role]["status"] == "unknown":
            limitations.append(
                f"The {role} IP is unknown to the local IOC database: no threat intelligence is available."
            )
    if not classification["techniques"]:
        limitations.append("No MITRE ATT&CK technique is mapped, so the attack type is uncertain.")
    if not matches:
        limitations.append(
            f"No playbook reached the similarity threshold (closest: {retrieval['best_candidate']}, "
            f"score {retrieval['score']:.2f})."
        )
    if len(matches) > 1:
        others = ", ".join(match["source"] for match in matches[1:])
        limitations.append(f"Other playbooks also matched and may be worth reading: {others}.")
    return limitations


def generate_template_report(incident):
    """Build the 8-section incident report from structured data only (no LLM)."""
    alert = incident["alert"]
    classification = incident["classification"]
    matches = order_playbooks(incident)

    steps = []
    actions = []
    if matches:
        steps = extract_section_items(matches[0]["text"], "investigation steps")
        actions = extract_section_items(matches[0]["text"], "recommended actions")

    return {
        "generated_by": "template",
        "summary": (
            f"{alert['severity'].capitalize()} alert {alert['alert_id']}: {alert['description']}. "
            f"Category: {classification['category']}. "
            f"Source {alert['source_ip']}, destination {alert['destination_ip']}."
        ),
        "attack_type": (
            f"{classification['category']}. {describe_techniques(classification)}. "
            f"Reason: {classification['reason']}"
        ),
        "severity": (
            f"{alert['severity'].upper()} - rule level {alert['level']} on a 0-15 scale. "
            f"{SEVERITY_NOTE}"
        ),
        "evidence": build_evidence(incident),
        "why_it_matters": WHY_IT_MATTERS.get(
            classification["category"], "No explanation is available for this category."
        ),
        "investigation_steps": steps or NO_PLAYBOOK_STEPS,
        "remediation_actions": actions or NO_PLAYBOOK_ACTIONS,
        "limitations": build_limitations(incident, matches),
        "sources": [match["source"] for match in matches],
    }


def report_to_text(report):
    """Plain-text version of a report (used for display and download)."""
    lines = [f"Report generated by: {report['generated_by']}"]
    if report["sources"]:
        lines.append("Playbooks consulted: " + ", ".join(report["sources"]))
    lines.append("")
    for key, title in SECTION_TITLES:
        lines.append(title)
        value = report[key]
        if isinstance(value, list):
            lines += [f"  - {item}" for item in value]
        else:
            lines.append(f"  {value}")
        lines.append("")
    return "\n".join(lines)