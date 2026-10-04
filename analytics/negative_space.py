import csv
import os


def load_csv(file_path):
    """Load a CSV file into a list of dictionaries."""

    with open(file_path, "r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def detect_negative_space(asset_file, alert_file):

    assets = load_csv(asset_file)
    alerts = load_csv(alert_file)

    # Build a set of assets that have generated alerts
    observed_assets = set()

    for alert in alerts:
        observed_assets.add(
            (alert["cse_id"], alert["asset_id"])
        )

    findings = []

    for asset in assets:

        cse_id = asset["cse_id"]
        asset_id = asset["asset_id"]

        # Only consider assets where monitoring is expected
        if asset["expected_monitoring"].lower() != "yes":
            continue

        # Check whether the asset produced any observed alert
        if (cse_id, asset_id) not in observed_assets:

            priority = "MEDIUM"

            # Critical assets receive higher review priority
            if asset["criticality"].lower() == "critical":
                priority = "HIGH"

            findings.append({
                "cse_id": cse_id,
                "asset_id": asset_id,
                "asset_type": asset["asset_type"],
                "criticality": asset["criticality"],
                "finding_type": "Potential Negative Space",
                "priority": priority,
                "reason": (
                    "Expected monitoring exists, but no "
                    "corresponding security alert activity "
                    "was observed in the submitted dataset."
                ),
                "manual_review": "RECOMMENDED"
            })

    return findings


if __name__ == "__main__":

    asset_file = "data/asset_inventory.csv"
    alert_file = "data/sample_alerts.csv"

    findings = detect_negative_space(
        asset_file,
        alert_file
    )

    print("\n=== SAT-SA NEGATIVE SPACE ANALYSIS ===\n")

    if not findings:

        print("No potential negative-space indicators detected.")

    else:

        for finding in findings:

            print(f"CSE: {finding['cse_id']}")
            print(f"Asset: {finding['asset_id']}")
            print(f"Asset Type: {finding['asset_type']}")
            print(f"Criticality: {finding['criticality']}")
            print(f"Finding: {finding['finding_type']}")
            print(f"Priority: {finding['priority']}")

            print("Evidence:")
            print(f"  - {finding['reason']}")

            print(
                f"Manual Review: "
                f"{finding['manual_review']}"
            )

            print("-" * 55)