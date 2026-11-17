"""Module 2 - IOC extraction and enrichment with a local IOC database."""

import csv
import ipaddress

# Addresses we consider internal: RFC 1918 private ranges + loopback.
# We list them ourselves because ipaddress.is_private is also True for the
# documentation ranges (203.0.113.0/24, ...) used by our synthetic attackers.
INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def load_ioc_database(path):
    """Read the IOC CSV and return a dictionary: {ip_address: row}."""
    with open(path, newline="", encoding="utf-8") as f:
        return {row["ip"]: row for row in csv.DictReader(f)}


def make_result(ip, status, description, entry=None):
    """Build an enrichment result with the same keys in every case."""
    entry = entry or {}
    return {
        "ip": ip,
        "status": status,
        "threat_category": entry.get("threat_category"),
        "confidence": entry.get("confidence"),
        "source": entry.get("source"),
        "description": description,
    }


def enrich_ip(ip, ioc_db):
    """Return the enrichment result for one IP: invalid, private, unknown or known."""
    ip = str(ip).strip()

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return make_result(ip, "invalid", "Not a valid IP address.")

    if any(address in network for network in INTERNAL_NETWORKS):
        return make_result(ip, "private", "Internal address, not looked up in the IOC database.")

    entry = ioc_db.get(str(address))
    if entry is None:
        return make_result(
            ip,
            "unknown",
            "Not found in the local IOC database. "
            "This is not evidence that the address is safe or malicious.",
        )

    return make_result(ip, "known", entry["description"], entry)


def enrich_alert(alert, ioc_db):
    """Enrich the source and destination IPs of one normalized alert."""
    return {
        "source": enrich_ip(alert["source_ip"], ioc_db),
        "destination": enrich_ip(alert["destination_ip"], ioc_db),
    }


if __name__ == "__main__":
    from src.alert_processor import process_alerts

    alerts, _ = process_alerts("data/alerts.json")
    ioc_db = load_ioc_database("data/ioc_database.csv")

    for alert in alerts:
        result = enrich_alert(alert, ioc_db)
        src = result["source"]
        dst = result["destination"]
        category = src["threat_category"] or "-"
        print(
            f"{alert['alert_id']} | src {src['ip']:<15} {src['status']:<8} | "
            f"dst {dst['ip']:<10} {dst['status']:<8} | {category}"
        )