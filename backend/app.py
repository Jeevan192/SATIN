from fastapi import FastAPI, HTTPException
import json
import os


app = FastAPI(
    title="SAT-SA API",
    description="Supervisory Analytics Tool for SOC Assessment",
    version="0.1"
)


DATA_FILE = os.path.join(
    "data",
    "supervisory_findings.json"
)


def load_analysis():

    if not os.path.exists(DATA_FILE):
        raise FileNotFoundError(
            "Supervisory findings file not found."
        )

    with open(
        DATA_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


# --------------------------------------------------
# Root
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "application": "SAT-SA",
        "description": "Supervisory Analytics Tool for SOC Assessment",
        "status": "operational"
    }


# --------------------------------------------------
# Summary
# --------------------------------------------------

@app.get("/summary")
def get_summary():

    data = load_analysis()

    return data["analysis_summary"]


# --------------------------------------------------
# Entity summaries
# --------------------------------------------------

@app.get("/entities")
def get_entities():

    data = load_analysis()

    return {
        "entities": data["entity_summaries"]
    }


# --------------------------------------------------
# All findings
# --------------------------------------------------

@app.get("/findings")
def get_findings():

    data = load_analysis()

    return {
        "findings": data["findings"]
    }


# --------------------------------------------------
# Findings for a specific CSE
# --------------------------------------------------

@app.get("/findings/{cse_id}")
def get_entity_findings(cse_id: str):

    data = load_analysis()

    findings = [
        finding
        for finding in data["findings"]
        if finding["cse_id"].upper() == cse_id.upper()
    ]

    if not findings:

        raise HTTPException(
            status_code=404,
            detail=f"No findings found for {cse_id}"
        )

    return {
        "cse_id": cse_id,
        "findings": findings
    }


# --------------------------------------------------
# Complete analysis
# --------------------------------------------------

@app.get("/analysis")
def get_full_analysis():

    return load_analysis()