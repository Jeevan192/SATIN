import csv
from datetime import datetime


def parse_time(value):
    return datetime.strptime(value, "%Y-%m-%d %H:%M")


def detect_execution_gaps(file_path):
    findings = []

    with open(file_path, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for alert in reader:

            # We are currently focusing on critical alerts
            if alert["severity"].lower() != "critical":
                continue

            alert_time = parse_time(alert["alert_time"])
            investigation_start = parse_time(
                alert["investigation_start"]
            )
            closure_time = parse_time(
                alert["closure_time"]
            )

            total_handling_minutes = (
                closure_time - alert_time
            ).total_seconds() / 60

            investigation_duration_minutes = (
                closure_time - investigation_start
            ).total_seconds() / 60

            reasons = []

            # Signal 1: unusually rapid closure
            if total_handling_minutes <= 10:
                reasons.append(
                    f"Critical alert closed in "
                    f"{total_handling_minutes:.0f} minutes"
                )

            # Signal 2: no escalation
            if alert["escalated"].lower() == "no":
                reasons.append("No escalation recorded")

            # Signal 3: no root-cause evidence
            if alert["root_cause_found"].lower() == "no":
                reasons.append(
                    "No root-cause evidence recorded"
                )

            # Signal 4: very short investigation
            if investigation_duration_minutes <= 5:
                reasons.append(
                    f"Investigation lasted only "
                    f"{investigation_duration_minutes:.0f} minutes"
                )

            # We require multiple indicators before flagging
            if len(reasons) >= 2:

                findings.append({
                    "alert_id": alert["alert_id"],
                    "cse_id": alert["cse_id"],
                    "asset_id": alert["asset_id"],
                    "severity": alert["severity"],
                    "finding_type": "Potential Execution Gap",
                    "priority": "HIGH",
                    "reasons": reasons,
                    "manual_review": "RECOMMENDED"
                })

    return findings


if __name__ == "__main__":

    file_path = "data/sample_alerts.csv"

    findings = detect_execution_gaps(file_path)

    print("\n=== SAT-SA EXECUTION GAP ANALYSIS ===\n")

    if not findings:
        print("No potential execution gaps detected.")

    else:

        for finding in findings:

            print(f"CSE: {finding['cse_id']}")
            print(f"Alert: {finding['alert_id']}")
            print(f"Asset: {finding['asset_id']}")
            print(f"Finding: {finding['finding_type']}")
            print(f"Priority: {finding['priority']}")

            print("Evidence:")

            for reason in finding["reasons"]:
                print(f"  - {reason}")

            print(
                f"Manual Review: "
                f"{finding['manual_review']}"
            )

            print("-" * 50)