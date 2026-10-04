import streamlit as st
import requests


# --------------------------------------------------
# Configuration
# --------------------------------------------------

API_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="SAT-SA",
    page_icon="",
    layout="wide"
)


# --------------------------------------------------
# API Helper
# --------------------------------------------------

def get_api_data(endpoint):

    try:

        response = requests.get(
            f"{API_URL}{endpoint}",
            timeout=5
        )

        response.raise_for_status()

        return response.json()

    except requests.exceptions.RequestException:

        return None


# --------------------------------------------------
# Header
# --------------------------------------------------

st.title("SAT-SA")

st.caption(
    "Supervisory Analytics Tool for SOC Assessment"
)

st.divider()


# --------------------------------------------------
# Load backend data
# --------------------------------------------------

summary = get_api_data("/summary")

entities_data = get_api_data("/entities")

findings_data = get_api_data("/findings")


# --------------------------------------------------
# Backend connection check
# --------------------------------------------------

if summary is None:

    st.error(
        "Unable to connect to the SAT-SA backend. "
        "Make sure FastAPI is running on port 8000."
    )

    st.stop()


if entities_data is None or findings_data is None:

    st.error(
        "The SAT-SA backend responded, "
        "but the analysis data could not be loaded."
    )

    st.stop()


entities = entities_data["entities"]

findings = findings_data["findings"]


# --------------------------------------------------
# Supervisory Overview
# --------------------------------------------------

st.subheader("Supervisory Overview")


col1, col2, col3 = st.columns(3)


with col1:

    st.metric(
        "Total Findings",
        summary["total_findings"]
    )


with col2:

    st.metric(
        "Entities Flagged",
        summary["entities_flagged"]
    )


with col3:

    st.metric(
        "High-Priority Findings",
        summary["high_priority_findings"]
    )


st.divider()


# --------------------------------------------------
# Entity-Level Summary
# --------------------------------------------------

st.subheader("Entity-Level Supervisory Summary")


for entity in entities:

    with st.container():

        col1, col2, col3, col4, col5 = st.columns(5)


        with col1:

            st.write("**CSE**")
            st.write(entity["cse_id"])


        with col2:

            st.write("**Findings**")
            st.write(entity["total_findings"])


        with col3:

            st.write("**Execution Gaps**")
            st.write(entity["execution_gaps"])


        with col4:

            st.write("**Negative Space**")
            st.write(entity["negative_space"])


        with col5:

            st.write("**Review Priority**")
            st.write(entity["review_priority"])


        st.write(
            "**Assets requiring attention:** "
            + ", ".join(entity["assets"])
        )


        st.divider()


# --------------------------------------------------
# Supervisory Findings
# --------------------------------------------------

st.subheader("Supervisory Findings")


for finding in findings:

    title = (
        f"{finding['priority']} | "
        f"{finding['cse_id']} | "
        f"{finding['finding_type']} | "
        f"{finding['asset_id']}"
    )


    with st.expander(title):

        col1, col2 = st.columns(2)


        with col1:

            st.write("**Entity**")
            st.write(finding["cse_id"])

            st.write("**Asset**")
            st.write(finding["asset_id"])

            st.write("**Finding Type**")
            st.write(finding["finding_type"])


        with col2:

            st.write("**Priority**")
            st.write(finding["priority"])

            st.write("**Source**")
            st.write(finding["source"])

            st.write("**Manual Review**")
            st.write(finding["manual_review"])


        st.write("**Evidence**")


        for evidence in finding["evidence"]:

            st.write(
                f"- {evidence}"
            )