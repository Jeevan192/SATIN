# SAT-SA: 2-Minute Demo Video Script

**Title:** SAT-SA - Supervisory Analytics Tool for SOC Assessment  
**Audience:** NCIIPC Evaluation Committee & Jury  
**Format:** Live Walkthrough & Screen Capture (Max Duration: 120 Seconds)  

---

### [0:00 - 0:10] The Supervisory Problem: Claims vs. Evidence
- **Visual:** Split screen showing an Entity SOC SLA Report claiming "99.4% MTTR compliance" beside SAT-SA's terminal executing completely offline.
- **Narrator (Audio):** *"Policies and executive dashboards tell you what a SOC claims. Incident and case management data tell you what it actually does. SAT-SA is an offline supervisory analytics tool built for NCIIPC to measure that gap across Critical Sector Entities."*

### [0:10 - 0:30] Batch Ingestion & Canonical Schema Validation
- **Visual:** Ingestion command runs: `python -m satsa.pipeline --data data/synthetic`. Data files (alerts, cases, workflow events, escalations, assets, entity profiles) ingest across 12 CSEs. Quarantine router intercepts schema anomalies.
- **Narrator (Audio):** *"SAT-SA ingests periodic multi-CSE data batches. Our strict Pydantic schemas validate referential integrity and quarantine malformed records without halting execution. Over 39,000 alerts are ingested, normalized, and benchmarked against peer cohorts in under 5 seconds on standard CPU hardware."*

### [0:30 - 0:55] Portfolio Risk Ranking & 8-Capability Radar
- **Visual:** Streamlit Examiner Dashboard loads (`http://localhost:8501`). Shows Portfolio Risk Ranking table, sorting 12 CSEs by Entity Risk Index (0–100), risk tiers, and QoQ trends. Focus clicks on high-risk entity `CSE-FIN-01`.
- **Narrator (Audio):** *"Supervisors immediately see the portfolio risk hierarchy. Drilling into CSE-FIN-01, our 8-capability area radar reveals severe gaps in Investigation, Escalation, and Asset Coverage compared to the peer cohort median."*

### [0:55 - 1:20] Finding Card: Execution Gap Drill-Down (EG-01 / EG-04)
- **Visual:** Open Finding Card `EG-01` (Critical alert closure speed anomaly). Shows observed MTTC of 2.1 minutes vs. peer median of 42.8 minutes ($z_{\text{MAD}} = -3.4$). Drill down to underlying alert evidence table.
- **Narrator (Audio):** *"SAT-SA identifies execution gaps—where records exist but contradict effectiveness. Here, 34 critical alerts were closed in under 3 minutes without escalation. Evidence links directly show rubber-stamped investigation notes detected via character n-gram TF-IDF similarity."*

### [1:20 - 1:35] Negative Space Discovery: Silent Assets & Suppressed Categories (NS-01)
- **Visual:** Switch to Negative Space panel. Highlight finding `NS-01`: 8 Tier-1 Core Banking databases generated zero alerts over the entire quarter. Asset coverage heatmap displays dark blind spots.
- **Narrator (Audio):** *"Our primary innovation is detecting 'Negative Space'—what should be there but is missing. SAT-SA anti-joins asset registers against event streams, flagging monitored critical databases that remained completely silent while peer assets averaged 140 alerts."*

### [1:35 - 1:50] Prioritized Review Queue & Ground-Truth Validation Lift
- **Visual:** Review Queue tab. Show 50-item budgeted queue for the examiner: 42 high-risk diversified alerts (85%) + 8 uniform random control samples (15%). Display Validation Benchmark report table showing **2.28x Lift** over random sampling.
- **Narrator (Audio):** *"Supervisors cannot review thousands of alerts. SAT-SA builds a mathematically budgeted review queue combining 85% risk-diversified cases with a 15% random control slice for anti-gaming. On ground truth benchmarks, this delivers 2.28x lift over random inspection at a 10% review budget."*

### [1:50 - 2:00] Cryptographic Audit Chain & Offline Guarantee
- **Visual:** Audit Verification tab shows green `VALID` banner verifying SHA-256 hash-chain integrity. Run `python -m satsa.offline_check` demonstrating outbound network blocking.
- **Narrator (Audio):** *"Every finding, parameter, and input checksum is sealed in an immutable SHA-256 hash chain with cryptographic tamper detection. 100% offline, zero cloud dependencies, verifiable air-gap deployment. SAT-SA: Accountability through empirical evidence."*
