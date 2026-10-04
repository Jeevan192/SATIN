import sys
import os

# Allow Python to find execution_gaps.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from execution_gaps import detect_execution_gaps


def generate_entity_summary(file_path):

    findings = detect_execution_gaps(file_path)

    entity_summary = {}

    for finding in findings:

        cse_id = finding["cse_id"]

        if cse_id not in entity_summary:
            entity_summary[cse_id] = {
                "cse_id": cse_id,
                "total_findings": 0,
                "critical_findings": 0,
                "no_escalation": 0,
                "no_root_cause": 0,
                "rapid_closures": 0
            }

        summary = entity_summary[cse_id]

        summary["total_findings"] += 1

        if finding["severity"].lower() == "critical":
            summary["critical_findings"] += 1

        for reason in finding["reasons"]:

            if "No escalation" in reason:
                summary["no_escalation"] += 1

            if "No root-cause" in reason:
                summary["no_root_cause"] += 1

            if "closed in" in reason:
                summary["rapid_closures"] += 1

    # Convert dictionary into list
    summaries = list(entity_summary.values())

    # Sort entities by number of findings
    summaries.sort(
        key=lambda x: x["total_findings"],
        reverse=True
    )

    return summaries


if __name__ == "__main__":

    file_path = "data/sample_alerts.csv"

    summaries = generate_entity_summary(file_path)

    print("\n=== SAT-SA ENTITY SUPERVISORY SUMMARY ===\n")

    for summary in summaries:

        print(f"CSE: {summary['cse_id']}")
        print(
            f"Potential supervisory signals: "
            f"{summary['total_findings']}"
        )
        print(
            f"Critical alert findings: "
            f"{summary['critical_findings']}"
        )
        print(
            f"Rapid closure indicators: "
            f"{summary['rapid_closures']}"
        )
        print(
            f"No escalation indicators: "
            f"{summary['no_escalation']}"
        )
        print(
            f"No root-cause indicators: "
            f"{summary['no_root_cause']}"
        )

        if summary["total_findings"] >= 3:
            print("Review priority: HIGH")
        else:
            print("Review priority: MEDIUM")

        print("Manual review: RECOMMENDED")
        print("-" * 55)