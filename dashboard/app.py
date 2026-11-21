"""SOC Copilot Lite - Streamlit dashboard."""

import sys
from pathlib import Path

# Streamlit puts the script folder (dashboard/) on the import path, not the project root.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from src.llm_assistant import (  # noqa: E402
    OLLAMA_MODEL,
    SECTION_TITLES,
    check_ollama,
    generate_report,
    report_to_text,
)
from src.pipeline import analyze_alerts  # noqa: E402
from src.soar_simulator import (  # noqa: E402
    approval_blocker,
    count_handled,
    find_decision,
    incident_status,
    log_to_csv,
    recommend_actions,
    record_decision,
)
from src.rag_engine import DEFAULT_THRESHOLD  # noqa: E402

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

st.set_page_config(page_title="SOC Copilot Lite", layout="wide")


@st.cache_data
def load_data():
    """Run modules 1 to 4 once and keep the result in cache."""
    return analyze_alerts()


def show(value):
    """Convert any value to text for display ('-' when missing)."""
    return "-" if value is None else str(value)


def build_alerts_table(incidents):
    rows = []
    for item in incidents:
        alert = item["alert"]
        rows.append(
            {
                "Alert ID": alert["alert_id"],
                "Time (UTC)": alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "Severity": alert["severity"],
                "Level": alert["level"],
                "Source IP": alert["source_ip"],
                "Destination IP": alert["destination_ip"],
                "Category": item["classification"]["category"],
                "Description": alert["description"],
            }
        )
    return pd.DataFrame(rows)


def build_ioc_table(incidents):
    rows = []
    for item in incidents:
        for role in ("source", "destination"):
            result = item["enrichment"][role]
            rows.append(
                {
                    "Alert ID": item["alert"]["alert_id"],
                    "Role": role,
                    "IP": result["ip"],
                    "Status": result["status"],
                    "Threat category": show(result["threat_category"]),
                    "Confidence": show(result["confidence"]),
                    "Details": result["description"],
                }
            )
    return pd.DataFrame(rows)


def build_mitre_table(incidents):
    rows = []
    for item in incidents:
        classification = item["classification"]
        techniques = classification["techniques"] or [
            {"id": "-", "name": "No technique mapped", "tactic": "-"}
        ]
        for technique in techniques:
            rows.append(
                {
                    "Alert ID": item["alert"]["alert_id"],
                    "Category": classification["category"],
                    "Technique ID": technique["id"],
                    "Technique": technique["name"],
                    "Tactic": technique["tactic"],
                    "Reason": classification["reason"],
                }
            )
    return pd.DataFrame(rows)


def find_incident(incidents, alert_id):
    return next(item for item in incidents if item["alert"]["alert_id"] == alert_id)


def decide(alert_id, action, decision):
    """Callback of the Approve / Reject buttons: it runs BEFORE the page is redrawn,
    so every number on the page already includes the new decision."""
    record_decision(st.session_state["soar_log"], alert_id, action, decision)


def reset_simulation():
    st.session_state["soar_log"] = []


# ---------------------------------------------------------------- data
incidents, rejected = load_data()

st.title("SOC Copilot Lite")
st.caption(
    "AI-assisted security alert analysis - educational prototype using "
    "synthetic alerts and simulated response actions."
)

if not incidents:
    st.error("No valid alert found. Check data/alerts.json.")
    st.stop()

alerts_df = build_alerts_table(incidents)

# History of the simulated SOAR actions (kept in memory for the browser session).
st.session_state.setdefault("soar_log", [])

with st.sidebar:
    st.header("Filters")
    selected_severities = st.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
    if st.button("Reload data"):
        st.cache_data.clear()
        st.rerun()

    st.header("Report mode")
    use_ollama = st.toggle("Use local LLM (Ollama)", value=False)
    if use_ollama:
        ollama_ready, ollama_message = check_ollama()
        if ollama_ready:
            st.success(ollama_message)
        else:
            st.warning(ollama_message)

tab_overview, tab_alerts, tab_intel, tab_investigation, tab_soar = st.tabs(
    ["Overview", "Alert Management", "Threat Intelligence", "AI Investigation", "SOAR Simulation"]
)

# ------------------------------------------------------------ overview
with tab_overview:
    counts = alerts_df["Severity"].value_counts()
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total alerts", len(alerts_df))
    col2.metric("Critical", int(counts.get("critical", 0)))
    col3.metric("High", int(counts.get("high", 0)))
    col4.metric(
        "Investigated incidents",
        count_handled(st.session_state["soar_log"], list(alerts_df["Alert ID"])),
    )
    col5.metric("Rejected (invalid)", len(rejected))

    st.subheader("Alerts by severity")
    st.bar_chart(counts.reindex(SEVERITY_ORDER, fill_value=0), sort=False)

    if rejected:
        st.warning(f"{len(rejected)} alert(s) were rejected by the validation step.")
        st.dataframe(pd.DataFrame(rejected).astype(str), hide_index=True, width="stretch")

# ----------------------------------------------------- alert management
with tab_alerts:
    filtered = alerts_df[alerts_df["Severity"].isin(selected_severities)]
    st.dataframe(filtered, hide_index=True, width="stretch")

    if filtered.empty:
        st.info("No alert matches the selected severities.")
    else:
        alert_id = st.selectbox("Alert details", filtered["Alert ID"], key="details_alert")
        alert = find_incident(incidents, alert_id)["alert"]

        details = pd.DataFrame(
            {
                "Field": [
                    "Alert ID", "Time (UTC)", "Rule ID", "Level", "Severity",
                    "Agent", "User", "Destination port", "Source IP", "Destination IP",
                ],
                "Value": [
                    show(alert["alert_id"]),
                    alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    show(alert["rule_id"]),
                    show(alert["level"]),
                    show(alert["severity"]),
                    show(alert["agent_name"]),
                    show(alert["username"]),
                    show(alert["destination_port"]),
                    show(alert["source_ip"]),
                    show(alert["destination_ip"]),
                ],
            }
        )
        st.dataframe(details, hide_index=True, width="stretch")
        st.caption("Raw log line (untrusted text, displayed as plain code):")
        st.code(show(alert["full_log"]), language=None)

# ------------------------------------------------- threat intelligence
with tab_intel:
    st.subheader("IOC enrichment")
    st.dataframe(build_ioc_table(incidents), hide_index=True, width="stretch")
    st.caption(
        "unknown = not in the local IOC database. It is not evidence that the address "
        "is safe or malicious. All IOC entries are synthetic."
    )

    st.subheader("MITRE ATT&CK classification")
    st.dataframe(build_mitre_table(incidents), hide_index=True, width="stretch")
    st.caption(incidents[0]["classification"]["method"])

# --------------------------------------------------- AI investigation
with tab_investigation:
    alert_id = st.selectbox("Select an alert", alerts_df["Alert ID"], key="investigation_alert")
    incident = find_incident(incidents, alert_id)
    alert = incident["alert"]
    classification = incident["classification"]
    retrieval = incident["playbooks"]

    st.markdown(
        f"**{alert['alert_id']}** - severity **{alert['severity']}** - "
        f"category **{classification['category']}**"
    )
    st.text(alert["description"])
    st.write(classification["reason"])

    st.subheader("Retrieved playbook")
    if retrieval["found"]:
        for position, match in enumerate(retrieval["matches"]):
            with st.expander(
                f"{match['source']} (similarity {match['score']:.2f})", expanded=(position == 0)
            ):
                st.markdown(match["text"])
    else:
        st.warning(
            f"No relevant playbook found. Closest: {retrieval['best_candidate']} "
            f"(similarity {retrieval['score']:.2f}, threshold {DEFAULT_THRESHOLD:.2f}). "
            "Manual analysis is needed."
        )

    st.subheader("AI incident analysis")
    saved_reports = st.session_state.setdefault("llm_reports", {})
    report = generate_report(incident, use_llm=False)

    if use_ollama:
        if st.button(f"Generate report with {OLLAMA_MODEL}", key="generate_llm"):
            with st.spinner(f"Asking {OLLAMA_MODEL}... this can take a minute on a CPU."):
                saved_reports[alert["alert_id"]] = generate_report(incident, use_llm=True)
        if alert["alert_id"] in saved_reports:
            report = saved_reports[alert["alert_id"]]
        else:
            st.info("Click the button to generate the LLM report. The template report is shown meanwhile.")

    if report.get("fallback_reason"):
        st.warning(f"Template report shown instead. {report['fallback_reason']}")
    if report["generated_by"] == "template":
        st.caption(
            "Report generated by: template (deterministic, built from the alert, "
            "the IOC results and the retrieved playbook)."
        )
    else:
        st.caption(
            f"Report generated by: {report['generated_by']}. AI-generated text, validated by "
            "the application and shown as plain text. Verify it against the evidence."
        )

    for key, title in SECTION_TITLES:
        st.markdown(f"**{title}**")
        value = report[key]
        st.text("\n".join(f"- {item}" for item in value) if isinstance(value, list) else value)

    safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in alert["alert_id"])
    st.download_button(
        "Download report (.txt)",
        data=report_to_text(report),
        file_name=f"{safe_id}_report.txt",
        mime="text/plain",
    )

# ------------------------------------------------------ SOAR simulation
with tab_soar:
    st.info(
        "Simulation only. Approving an action records it in the history below. "
        "No change is made to any network, firewall or account."
    )
    soar_alert_id = st.selectbox("Select an alert", alerts_df["Alert ID"], key="soar_alert")
    soar_incident = find_incident(incidents, soar_alert_id)
    soar_log = st.session_state["soar_log"]

    st.markdown(f"**Incident status:** {incident_status(soar_log, soar_alert_id)}")
    st.subheader("Recommended actions")

    for proposed in recommend_actions(soar_incident):
        decision = find_decision(soar_log, soar_alert_id, proposed["action_id"])
        with st.container(border=True):
            st.markdown(f"**{proposed['label']}**")
            st.text(proposed["reason"])
            if decision is not None:
                st.caption(
                    f"{decision['approval'].capitalize()} at {decision['timestamp']} UTC "
                    f"- execution: {decision['execution']}"
                )
            else:
                blocker = approval_blocker(soar_log, soar_alert_id, proposed["action_id"])
                col_approve, col_reject, _ = st.columns([1, 1, 4])
                col_approve.button(
                    "Approve",
                    key=f"approve_{soar_alert_id}_{proposed['action_id']}",
                    on_click=decide,
                    args=(soar_alert_id, proposed, "approved"),
                    disabled=blocker is not None,
                    help=blocker,
                )
                col_reject.button(
                    "Reject",
                    key=f"reject_{soar_alert_id}_{proposed['action_id']}",
                    on_click=decide,
                    args=(soar_alert_id, proposed, "rejected"),
                )

    st.subheader("Action history")
    if soar_log:
        history = pd.DataFrame(list(reversed(soar_log))).rename(
            columns={
                "timestamp": "Time (UTC)",
                "alert_id": "Alert ID",
                "action": "Action",
                "approval": "Approval",
                "execution": "Execution",
                "note": "Note",
            }
        )
        st.dataframe(
            history[["Time (UTC)", "Alert ID", "Action", "Approval", "Execution", "Note"]],
            hide_index=True,
            width="stretch",
        )
        st.download_button(
            "Download history (.csv)",
            data=log_to_csv(soar_log),
            file_name="soar_history.csv",
            mime="text/csv",
        )
        st.button("Reset simulation", on_click=reset_simulation)
    else:
        st.caption("No action recorded yet.")