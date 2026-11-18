"""Module 4 - Lightweight RAG retriever: TF-IDF + cosine similarity over local playbooks."""

import re
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Minimum cosine similarity to accept a playbook.
# Calibrated on the 8 synthetic alerts: irrelevant alert = 0.15, weakest good match = 0.37.
DEFAULT_THRESHOLD = 0.25

# Maximum number of playbooks returned for one alert.
DEFAULT_TOP_K = 2


def load_playbooks(folder):
    """Read every Markdown playbook. Return {file_name: raw_text}."""
    paths = sorted(Path(folder).glob("*.md"))
    return {path.name: path.read_text(encoding="utf-8") for path in paths}


def clean_text(text):
    """Lowercase and keep only letters and digits (removes Markdown symbols)."""
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def build_index(playbooks):
    """Learn the TF-IDF vocabulary and turn every playbook into a vector."""
    if not playbooks:
        raise ValueError("No playbook found: the playbooks folder is empty.")
    names = list(playbooks)
    vectorizer = TfidfVectorizer(stop_words="english")
    matrix = vectorizer.fit_transform([clean_text(playbooks[name]) for name in names])
    return {"names": names, "texts": playbooks, "vectorizer": vectorizer, "matrix": matrix}


def build_query(alert, classification):
    """Build the search text from structured alert fields (not from the raw log)."""
    parts = [alert["description"], classification["category"].replace("_", " ")]
    parts += [technique["name"] for technique in classification["techniques"]]
    return " ".join(parts)


def retrieve(query, index, threshold=DEFAULT_THRESHOLD, top_k=DEFAULT_TOP_K):
    """Return the best playbooks for the query.

    Only playbooks whose similarity is >= threshold are returned (at most top_k).
    If none qualifies, found is False and matches is empty."""
    query_vector = index["vectorizer"].transform([clean_text(query)])
    scores = cosine_similarity(query_vector, index["matrix"])[0]
    ranking = scores.argsort()[::-1]  # positions from best to worst score

    matches = []
    for position in ranking[:top_k]:
        score = float(scores[position])
        if score >= threshold:
            name = index["names"][int(position)]
            matches.append({"source": name, "text": index["texts"][name], "score": score})

    best = int(ranking[0])
    return {
        "found": len(matches) > 0,
        "matches": matches,
        "best_candidate": index["names"][best],
        "score": float(scores[best]),
        "all_scores": {name: float(s) for name, s in zip(index["names"], scores)},
    }


if __name__ == "__main__":
    from src.alert_processor import process_alerts
    from src.attack_classifier import classify_alert

    alerts, _ = process_alerts("data/alerts.json")
    index = build_index(load_playbooks("playbooks"))

    for alert in alerts:
        classification = classify_alert(alert)
        result = retrieve(build_query(alert, classification), index)
        if result["found"]:
            summary = ", ".join(f"{m['source']} ({m['score']:.2f})" for m in result["matches"])
        else:
            summary = f"no relevant playbook (closest: {result['best_candidate']} {result['score']:.2f})"
        print(f"{alert['alert_id']} | {summary}")