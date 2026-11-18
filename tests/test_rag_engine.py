from pathlib import Path

import pytest

from src.rag_engine import (
    DEFAULT_THRESHOLD,
    build_index,
    build_query,
    clean_text,
    load_playbooks,
    retrieve,
)

PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent / "playbooks"


@pytest.fixture(scope="module")
def index():
    """The real playbooks, indexed once for all tests in this file."""
    return build_index(load_playbooks(PLAYBOOKS_DIR))


def query_for(description, category, techniques=()):
    """Build a search text the same way the application does."""
    alert = {"description": description}
    classification = {"category": category, "techniques": [{"name": t} for t in techniques]}
    return build_query(alert, classification)


def test_load_playbooks_reads_the_four_files():
    playbooks = load_playbooks(PLAYBOOKS_DIR)
    assert len(playbooks) == 4
    assert "ssh_bruteforce.md" in playbooks


def test_clean_text_removes_markdown_symbols():
    assert clean_text("## Hello-World! `ssh_key`") == "hello world ssh key"


def test_build_index_rejects_an_empty_folder():
    with pytest.raises(ValueError):
        build_index({})


@pytest.mark.parametrize(
    "description, category, techniques, expected_source",
    [
        ("SSH brute force: many failed logins from the same source",
         "ssh_bruteforce", ["Password Guessing"], "ssh_bruteforce.md"),
        ("Possible port scan: many distinct ports probed in a short time",
         "port_scanning", ["Active Scanning"], "port_scanning.md"),
        ("Successful login outside usual hours from a previously unseen source IP",
         "suspicious_login", ["Valid Accounts"], "suspicious_login.md"),
        ("Multiple failed logons for the same account",
         "multiple_auth_failures", ["Brute Force"], "ssh_bruteforce.md"),
    ],
)
def test_alert_retrieves_the_expected_playbook(description, category, techniques, expected_source, index):
    result = retrieve(query_for(description, category, techniques), index)
    assert result["found"] is True
    assert result["matches"][0]["source"] == expected_source


def test_account_compromise_alert_also_returns_the_account_playbook(index):
    query = query_for(
        "Successful SSH login after many failed attempts from the same source",
        "account_compromise",
        ["Password Guessing", "Valid Accounts"],
    )
    sources = [match["source"] for match in retrieve(query, index)["matches"]]
    assert "account_compromise.md" in sources


def test_unrelated_alert_returns_no_playbook(index):
    query = query_for("Unusual outbound connection to an uncommon port", "unknown_activity")
    result = retrieve(query, index)
    assert result["found"] is False
    assert result["matches"] == []
    assert result["score"] < DEFAULT_THRESHOLD


def test_empty_query_finds_nothing(index):
    result = retrieve("", index)
    assert result["found"] is False
    assert result["score"] == 0.0


def test_top_k_limits_the_number_of_results(index):
    query = query_for(
        "Successful SSH login after many failed attempts from the same source",
        "account_compromise",
        ["Password Guessing", "Valid Accounts"],
    )
    assert len(retrieve(query, index, top_k=1)["matches"]) == 1


def test_threshold_above_one_rejects_everything(index):
    query = query_for("SSH brute force: many failed logins from the same source", "ssh_bruteforce")
    assert retrieve(query, index, threshold=1.01)["found"] is False


def test_scores_are_between_zero_and_one(index):
    query = query_for("Possible port scan: many distinct ports probed in a short time", "port_scanning")
    scores = retrieve(query, index)["all_scores"].values()
    assert all(0.0 <= score <= 1.0 for score in scores)


def test_returned_text_comes_from_the_playbook_file(index):
    query = query_for("Possible port scan: many distinct ports probed in a short time", "port_scanning")
    match = retrieve(query, index)["matches"][0]
    assert match["text"].startswith("# Port Scanning Investigation")