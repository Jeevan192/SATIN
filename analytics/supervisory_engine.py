import json
import sys
import os
from datetime import datetime

# Allow imports from the analytics directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from execution_gaps import detect_execution_gaps
from negative_space import detect_negative_space


def run_supervisory_analysis(alert_file, asset_file):
    """
    Run all SAT-SA supervisory analytics
    and combine their findings into a unified
    supervisory finding structure.
    """

    all_findings = []

    # --------------------------------------------------
    # 1. Execution Gap Detection
    # --------------------------------------------------

    execution_gap_findings = detect_execution_gaps(
        alert_file
    )

    for finding in execution_gap_findings:

        all_findings.append({
            "cse_id": finding["cse_id"],
            "asset_id": finding["asset_id"],
            "finding_type": finding["finding_type"],
            "priority": finding["priority"],
            "evidence": finding["reasons"],
            "manual_review": finding["manual_review"],
            "source": "Execution Gap Detector"
        })

    # --------------------------------------------------
    # 2. Negative Space Detection
    # --------------------------------------------------

    negative_space_findings = detect_negative_space(
        asset_file,
        alert_file
    )

    for finding in negative_space_findings:

        all_findings.append({
            "cse_id": finding["cse_id"],
            "asset_id": finding["asset_id"],
            "finding_type": finding["finding_type"],
            "priority": finding["priority"],
            "evidence": [
                finding["reason"]
            ],
            "manual_review": finding["manual_review"],
            "source": "Negative Space Detector"
        })

    return all_findings


def generate_entity_summary(findings):
    """
    Aggregate individual supervisory findings
    at the CSE/entity level.
    """

    entities = {}

    for finding in findings:

        cse_id = finding["cse_id"]

        if cse_id not in entities:

            entities[cse_id] = {
                "cse_id": cse_id,
                "total_findings": 0,
                "high_priority": 0,
                "execution_gaps": 0,
                "negative_space": 0,
                "assets": set()
            }

        entity = entities[cse_id]

        entity["total_findings"] += 1

        if finding["priority"] == "HIGH":
            entity["high_priority"] += 1

        if finding["finding_type"] == "Potential Execution Gap":
            entity["execution_gaps"] += 1

        if finding["finding_type"] == "Potential Negative Space":
            entity["negative_space"] += 1

        if finding["asset_id"]:
            entity["assets"].add(
                finding["asset_id"]
            )

    # --------------------------------------------------
    # Convert sets to lists and determine review priority
    # --------------------------------------------------

    for entity in entities.values():

        entity["assets"] = sorted(
            list(entity["assets"])
        )

        # Initial prototype prioritisation.
        # This will later be replaced with a
        # more robust multi-signal prioritisation model.

        if entity["high_priority"] >= 3:

            entity["review_priority"] = "HIGH"

        elif entity["high_priority"] >= 1:

            entity["review_priority"] = "MEDIUM"

        else:

            entity["review_priority"] = "LOW"

    return list(entities.values())


def save_findings(
    findings,
    summaries,
    output_file,
    alert_file,
    asset_file
):
    """
    Save the complete supervisory analysis
    as a machine-readable JSON evidence record.
    """

    output = {

        "analysis_metadata": {

            "engine": "SAT-SA",

            "version": "0.1",

            "analysis_type": "Supervisory Analytics",

            "generated_at": datetime.now().isoformat(),

            "input_sources": {
                "alert_data": alert_file,
                "asset_inventory": asset_file
            },

            "analytics_modules": [
                "Execution Gap Detector",
                "Negative Space Detector"
            ]
        },

        "analysis_summary": {

            "total_findings": len(findings),

            "entities_flagged": len(summaries),

            "high_priority_findings": sum(
                1
                for finding in findings
                if finding["priority"] == "HIGH"
            )
        },

        "entity_summaries": summaries,

        "findings": findings
    }

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=4
        )


if __name__ == "__main__":

    # --------------------------------------------------
    # Input files
    # --------------------------------------------------

    alert_file = "data/sample_alerts.csv"

    asset_file = "data/asset_inventory.csv"

    output_file = "data/supervisory_findings.json"

    # --------------------------------------------------
    # Run SAT-SA analytics
    # --------------------------------------------------

    findings = run_supervisory_analysis(
        alert_file,
        asset_file
    )

    # --------------------------------------------------
    # Generate entity-level summaries
    # --------------------------------------------------

    summaries = generate_entity_summary(
        findings
    )

    # --------------------------------------------------
    # Save machine-readable evidence
    # --------------------------------------------------

    save_findings(
        findings,
        summaries,
        output_file,
        alert_file,
        asset_file
    )

    # --------------------------------------------------
    # Console output
    # --------------------------------------------------

    print("\n======================================")
    print("       SAT-SA SUPERVISORY ENGINE")
    print("======================================\n")

    print(
        f"Total supervisory findings: "
        f"{len(findings)}"
    )

    print()

    print("ENTITY SUPERVISORY SUMMARY")
    print("--------------------------------------")

    for entity in sorted(
        summaries,
        key=lambda x: x["total_findings"],
        reverse=True
    ):

        print(
            f"\nCSE: {entity['cse_id']}"
        )

        print(
            f"Total findings: "
            f"{entity['total_findings']}"
        )

        print(
            f"High-priority findings: "
            f"{entity['high_priority']}"
        )

        print(
            f"Execution gaps: "
            f"{entity['execution_gaps']}"
        )

        print(
            f"Negative-space indicators: "
            f"{entity['negative_space']}"
        )

        print(
            f"Review priority: "
            f"{entity['review_priority']}"
        )

        print(
            f"Assets requiring attention: "
            f"{', '.join(entity['assets'])}"
        )

    print("\n")
    print("DETAILED FINDINGS")
    print("--------------------------------------")

    for finding in findings:

        print(
            f"\n[{finding['priority']}] "
            f"{finding['cse_id']} | "
            f"{finding['finding_type']}"
        )

        print(
            f"Asset: {finding['asset_id']}"
        )

        print(
            f"Source: {finding['source']}"
        )

        print("Evidence:")

        for evidence in finding["evidence"]:

            print(
                f"  - {evidence}"
            )

        print(
            f"Manual review: "
            f"{finding['manual_review']}"
        )

    print("\n--------------------------------------")
    print(
        f"Evidence record saved to: "
        f"{output_file}"
    )
    print("--------------------------------------")