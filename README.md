# SATIN
## Supervisory Analytics & Traceability Intelligence Network

### SIH26157 — Supervisory Analytics Tool for SOC Assessment
**National Critical Information Infrastructure Protection Centre (NCIIPC)**

> **A SOC can report excellent performance on paper. SATIN helps a supervisor determine whether the operational evidence actually supports those claims.**

SATIN is an **offline, evidence-first supervisory analytics platform** designed for the NCIIPC supervisory assessment of Critical Sector Entities (CSEs).

It analyzes periodic SOC submissions containing alerts, cases, workflow events, escalations, and asset inventories to identify:

- Execution gaps between reported performance and observed operational evidence
- Negative space where expected security activity or monitoring evidence is absent
- Anomalous and suspicious operational patterns
- Deviations from relevant peer entities
- Entities requiring greater supervisory attention
- Specific samples and findings that should be reviewed first

SATIN does not replace the examiner.

It answers a more useful question:

> **"Given thousands or millions of submitted records, where should the examiner look first, and what evidence supports that concern?"**

---

# 1. The Problem

Supervisory assessment of SOC operations becomes difficult when examiners have to evaluate large periodic submissions from multiple Critical Sector Entities.

A SOC may report:

- High alert coverage
- Fast incident closure
- Strong escalation performance
- Low false-positive rates
- High operational efficiency

However, reported metrics alone do not necessarily demonstrate that the underlying security processes were effective.

The supervisory challenge is therefore not simply:

> **"How many alerts did the SOC process?"**

It is:

> **"Does the evidence contained in the operational records support what the SOC claims?"**

SATIN addresses this problem by combining statistical analysis, rule-based supervisory analytics, peer benchmarking, anomaly detection, evidence traceability, and human review.

---

# 2. SATIN's Core Insight

SATIN is built around two complementary supervisory concepts.

## 2.1 Execution Gap

### Evidence exists — but the evidence contradicts the expected operational behaviour.

An Execution Gap occurs when submitted records exist, but their characteristics indicate that the claimed or expected operational process may not have occurred as represented.

Examples include:

- Critical alerts being closed substantially faster than comparable peer activity
- Critical alerts being closed without appropriate escalation
- Alerts being acknowledged without meaningful workflow activity
- Investigation notes exhibiting highly repetitive template behaviour
- Repeated alerts occurring without evidence of remediation
- Alert closures clustering around SLA boundaries
- Excessive concentration of high-severity closures among a small number of analysts
- Significant drift in disposition behaviour

**Question SATIN asks:**

> **"What happened — and does the evidence suggest that it was actually handled as claimed?"**

---

## 2.2 Negative Space

### The expected evidence is missing.

Negative Space identifies situations where the absence of expected activity becomes a supervisory signal.

Examples include:

- Critical assets generating no security alerts during the reporting period
- Expected threat categories being absent relative to comparable entities
- High-severity alerts lacking corresponding cases or escalation records
- Alert volumes significantly below peer expectations
- Extended periods of operational silence
- Critical assets with inadequate monitoring coverage

**Question SATIN asks:**

> **"What should have happened, but didn't?"**

This distinction is central to SATIN.

It allows the platform to investigate both **suspicious activity** and **suspicious absence of activity**.

---

# 3. What SATIN Delivers

SATIN transforms periodic CSE submissions into an examiner-oriented supervisory workflow:

```text
        CSE PERIODIC SUBMISSIONS
                  |
                  v
       +-----------------------+
       | Secure Data Ingestion |
       | Schema Validation     |
       | Referential Checks    |
       +-----------+-----------+
                   |
                   v
       +-----------------------+
       | Evidence Store        |
       | Feature Compilation   |
       +-----------+-----------+
                   |
          +--------+--------+
          |                 |
          v                 v
  Execution Gap       Negative Space
     Engine               Engine
          |                 |
          +--------+--------+
                   |
                   v
       +-----------------------+
       | Peer Benchmarking    |
       | Statistical Analysis |
       | Novelty Detection    |
       +-----------+-----------+
                   |
                   v
       +-----------------------+
       | Entity Risk Scoring  |
       | Supervisory Indicators|
       +-----------+-----------+
                   |
                   v
       +-----------------------+
       | Prioritised Review   |
       | Queue                |
       +-----------+-----------+
                   |
                   v
       +-----------------------+
       | Finding Cards        |
       | Evidence Drill-down  |
       | Claim-vs-Reality     |
       +-----------+-----------+
                   |
                   v
       +-----------------------+
       | Human Examiner       |
       | Confirm / Dismiss    |
       +-----------+-----------+
                   |
                   v
       +-----------------------+
       | Audited Report       |
       | Hash Verification    |
       +-----------------------+
```

---

# 4. Why SATIN Is Different

SATIN is not another SOC monitoring dashboard.

It is deliberately designed as a **supervisory analytical workbench**.

| Conventional SOC Platform | SATIN |
|---|---|
| Monitors live security events | Analyses periodic supervisory submissions |
| Generates operational alerts | Identifies supervisory concerns |
| Optimised for SOC analysts | Optimised for examiners and supervisors |
| Detects threats in real time | Evaluates operational effectiveness |
| Primarily activity-focused | Activity + absence-focused |
| Individual SOC perspective | Cross-entity peer benchmarking |
| Risk score may be opaque | Evidence-backed Finding Cards |
| Operational automation | Human-in-the-loop supervisory decision |
| Cloud/SaaS commonly used | Designed for air-gapped deployment |

SATIN therefore sits **above the operational SOC layer**.

It does not replace a SIEM, EDR, SOAR, or SOC.

It evaluates evidence produced by those systems.

---

# 5. Key Capabilities

## 5.1 Execution Gap Detection

Eight modular detectors identify suspicious operational behaviour.

| Detector | Capability |
|---|---|
| EG-01 | Critical/High closure speed anomaly |
| EG-02 | Critical/High closure without escalation |
| EG-03 | Acknowledged alerts lacking workflow actions |
| EG-04 | Template-driven investigation notes |
| EG-05 | Repeat alerts without remediation |
| EG-06 | SLA boundary closure bunching |
| EG-07 | Analyst closure concentration |
| EG-08 | Disposition drift |

---

## 5.2 Negative Space Detection

Six detectors identify missing or unexpectedly low operational evidence.

| Detector | Capability |
|---|---|
| NS-01 | Critical assets with zero alerts |
| NS-02 | Suppressed expected threat categories |
| NS-03 | Alerts missing cases or escalation |
| NS-04 | Alert volume below peer baseline |
| NS-05 | Operational silence windows |
| NS-06 | Criticality-weighted monitoring deficit |

---

## 5.3 Novelty Detection

SATIN also contains a dedicated novelty detection lane:

- NOV-01 — Multivariate behavioural drift
- Isolation Forest
- Local Outlier Factor
- Cohort-normalised entity-month feature vectors

This allows SATIN to surface patterns that are not necessarily captured by fixed supervisory rules.

---

# 6. Evidence-First Explainability

A core design principle of SATIN is:

> **A risk score without evidence is not a useful supervisory finding.**

Every Finding Card is designed to answer:

1. Why was this entity flagged?
2. What was observed?
3. What is the relevant peer baseline?
4. What threshold was crossed?
5. Which detector generated the finding?
6. How confident is the result?
7. Which underlying records support it?
8. What should the examiner investigate?

A typical Finding Card contains information such as:

```text
Finding
----------------------------------------
Detector: EG-01
Severity: HIGH

Observed:
Median critical-alert closure = 1.8 min

Peer baseline:
Median = 45.2 min

Threshold:
Below cohort 5th percentile

Deviation:
-94.1%

Confidence:
High

Evidence:
Alert IDs:
A-10421
A-10432
A-10457
...

Recommended review:
Inspect investigation workflow and closure evidence.
```

The objective is not to tell the examiner what decision to make.

The objective is to give the examiner a defensible reason to investigate.

---

# 7. Peer Benchmarking

Raw metrics can be misleading.

A large banking CSE and a smaller telecom CSE should not necessarily be evaluated against identical thresholds.

SATIN therefore constructs hierarchical peer cohorts using:

```text
Sector
   |
   +-- Size Band
          |
          +-- Entity
```

Where sufficient peer data exists, SATIN uses robust statistical baselines including:

- Median
- Median Absolute Deviation (MAD)
- Empirical percentiles
- Robust Z-scores
- Poisson-based comparisons
- Size-adjusted expectations

If a sufficiently specific cohort is unavailable, SATIN falls back to broader cohorts.

This produces **context-aware supervisory signals rather than arbitrary global thresholds**.

---

# 8. Entity Supervisory Risk Index

SATIN converts detector-level findings into an entity-level supervisory view.

The Entity Supervisory Risk Index combines eight capability areas and supports period-over-period trend analysis.

The examiner can therefore move from:

```text
All CSEs
    |
    v
Which entities need attention?
    |
    v
Which capability area is driving the concern?
    |
    v
Which finding caused the score?
    |
    v
What evidence supports the finding?
```

This creates a direct path from **supervisory prioritisation to underlying evidence**.

---

# 9. Intelligent Review Prioritisation

A supervisory team cannot manually inspect every record.

SATIN therefore constructs a budgeted review queue.

The current implementation uses:

- **85% risk-diversified selection**
- **15% random-control selection**

The random-control slice is deliberate.

It provides an anti-gaming mechanism and allows supervisors to compare targeted selection against baseline sampling.

Each selected item carries its selection rationale.

---

# 10. Claim-vs-Reality Analysis

SATIN can evaluate self-reported operational KPIs against evidence-derived measurements.

For example:

```text
                 CLAIMED        OBSERVED
------------------------------------------------
MTTC             8.0 min        42.7 min
Coverage         96%            71%
Escalation       91%            63%
False Positive   12%            28%
```

The system then produces a credibility assessment:

```text
SUBSTANTIATED
PARTIALLY SUBSTANTIATED
MATERIALLY EXAGGERATED
```

The purpose is not to automatically accuse an entity of misconduct.

It provides a structured supervisory signal indicating where the reported narrative and operational evidence diverge.

---

# 11. Human-in-the-Loop Supervision

SATIN does not make final supervisory decisions.

Examiners remain responsible for interpreting findings.

Supervisors can:

- Confirm findings
- Dismiss findings
- Review supporting evidence
- Inspect peer comparisons
- Drill down to source records
- Export supervisory reports

Confirmed and dismissed findings are retained in a local feedback ledger and can influence subsequent prioritisation.

This creates a controlled feedback loop:

```text
Analytics
    |
    v
Human Examiner
    |
    v
Supervisory Decision
    |
    v
Feedback
    |
    v
Future Prioritisation
```

---

# 12. Air-Gapped by Design

SATIN is specifically designed for environments where sensitive supervisory data cannot leave the assessment environment.

### SATIN does NOT require:

- Cloud services
- SaaS platforms
- External AI APIs
- Internet connectivity
- Hosted machine-learning models
- GPU infrastructure

All analytics execute locally.

The system includes an offline verification mechanism that intercepts and blocks non-loopback network activity.

Run:

```bash
python satsa/offline_check.py
```

Expected result:

```text
[PASS] Air-gap sandbox verified:
Outbound network calls are strictly intercepted and blocked.
```

Offline operation is not merely a deployment preference.

**It is part of the system architecture.**

---

# 13. Data Model

SATIN works with six canonical supervisory data tables.

| Dataset | Purpose |
|---|---|
| `alerts` | Alert lifecycle and disposition |
| `cases` | Case management and investigation records |
| `workflow_events` | Investigation workflow activity |
| `escalations` | Escalation history |
| `assets` | Critical asset and monitoring inventory |
| `entities` | CSE metadata and peer-group information |

Supported formats:

```text
CSV
JSON
Parquet
```

Malformed records are quarantined with reasons rather than silently discarded.

SATIN operates on the **supervisory evidence layer** and does not require raw packet captures, customer data, or live security telemetry.

---

# 14. Cryptographic Auditability

Supervisory analytics must be reproducible and traceable.

SATIN therefore generates a cryptographically sealed execution record.

## Run Manifest

The manifest records hashes of:

- Input data
- Detector code
- Configuration
- Parameters
- Generated outputs

## Hash-Chained Audit Ledger

Each audit event is linked to the previous event using SHA-256:

```text
Hash(i) =
SHA-256(
    Entry ID
    + Timestamp
    + Event Type
    + Payload Hash
    + Hash(i-1)
)
```

Any retroactive modification to the chain becomes detectable.

Verify the audit trail:

```bash
python satsa/audit.py --verify
```

Example:

```text
[OK] Audit log integrity verified.
Run Manifest Hash: <SHA-256>
```

The audit layer provides **tamper evidence and reproducibility** for supervisory analysis.

---

# 15. Validation

SATIN is not presented as a conceptual prototype only.

The repository contains a deterministic synthetic benchmark with seeded ground-truth fault injections.

### Benchmark

```text
Entities:              12
Alerts:                39,211
Ground-truth faults:   4,747
Random seed:            42
```

The benchmark covers fault patterns corresponding to the supervisory scenarios targeted by SATIN.

---

## Review Budget Performance

| Review Budget | Items Examined | True Positives | Precision@k | Recall@k | Lift vs Random |
|---:|---:|---:|---:|---:|---:|
| 5% | 1,246 | 346 | 27.8% | 7.3% | 2.12x |
| 10% | 2,495 | 666 | **26.7%** | **14.0%** | **2.28x** |
| 20% | 4,990 | 1,315 | 26.4% | 27.7% | 1.90x |

### Key Result

At a **10% review budget**, SATIN achieves:

> **2.28x lift over random sampling**

This demonstrates the intended supervisory value of prioritisation: directing limited examiner attention toward a substantially more informative subset of the available evidence.

Entity ranking correlation with injected fault density:

```text
Spearman rho = 0.3601
```

---

# 16. Detection Layer Ablation

SATIN's ensemble was also evaluated against individual analytical layers.

| Configuration | Findings Surfaced | Precision@10% | Recall@10% |
|---|---:|---:|---:|
| Rules only | 685 | 10.3% | 5.4% |
| Peer statistics only | 1,718 | 26.5% | 13.9% |
| ML novelty only | 13 | 6.7% | 3.5% |
| **Full SATIN ensemble** | **2,416** | **26.7%** | **14.0%** |

This supports the architectural decision to combine:

```text
Deterministic supervisory rules
            +
Peer-relative statistics
            +
Novelty detection
            =
SATIN supervisory ensemble
```

The ML layer is therefore not treated as a black-box replacement for deterministic supervisory logic.

---

# 17. Scale & Performance

SATIN uses a vectorized processing architecture with a Parquet/DuckDB-backed evidence store.

Measured benchmarks:

| Alert Rows | Pipeline Runtime | Throughput | Peak Memory |
|---:|---:|---:|---:|
| 1,000,000 | 151.9 sec | 6,585 alerts/sec | 1.53 GB |
| 5,000,000 | 592.2 sec | 8,443 alerts/sec | 5.14 GB |
| 10,000,000 | ~20 min* | ~8,000 alerts/sec* | ~10.3 GB* |

`*` 10M figures are projections based on measured runs and are not represented as a completed benchmark.

Reproduce the benchmark with:

```bash
python scripts/scale_test.py --rows 1000000
```

or:

```bash
python scripts/scale_test.py --rows 5000000
```

---

# 18. SIH26157 Requirements Traceability

SATIN was implemented against the functional and deployment requirements of SIH26157.

| Requirement | SATIN Implementation |
|---|---|
| Multi-CSE data ingestion | Canonical six-table ingestion |
| Multiple data formats | CSV, JSON, Parquet |
| Large-scale analysis | Vectorized processing + Parquet/DuckDB |
| Detection weaknesses | Execution Gap + Negative Space detectors |
| Execution Gap detection | EG-01 to EG-08 |
| Negative Space detection | NS-01 to NS-06 |
| Unknown anomalies | Isolation Forest + LOF |
| Peer benchmarking | Sector/size cohort analysis |
| Entity risk indicators | Eight capability areas + Entity Risk Index |
| Review prioritisation | Budgeted supervisory review queue |
| Explainability | Evidence-backed Finding Cards |
| Evidence traceability | Source row IDs and drill-down |
| Auditability | SHA-256 manifest + hash chain |
| Supervisory dashboards | Offline Streamlit interface |
| Reporting | HTML/PDF report generation |
| Trend analysis | Entity and period-level trends |
| Air-gapped deployment | Offline runtime enforcement |
| Human oversight | Examiner Confirm/Dismiss workflow |

The complete traceability matrix is maintained in the project documentation.

---

# 19. Quick Start

## Requirements

```text
Python 3.11+
CPU-only
No GPU required
No internet required at runtime
```

## Installation

```bash
git clone <repository-url>
cd SATIN

pip install -r requirements.txt
```

## Generate Benchmark Data

```bash
python synth/generate.py \
    --seed 42 \
    --entities 12 \
    --alerts 39000
```

## Run the Analytics Pipeline

```bash
python satsa/pipeline.py \
    --data data/synthetic \
    --output data/output \
    --budget 50
```

## Start the Backend

```bash
python -m uvicorn backend.app:app \
    --host 127.0.0.1 \
    --port 8000
```

Local API documentation:

```text
http://127.0.0.1:8000/docs
```

## Start the Examiner Dashboard

```bash
python -m streamlit run dashboard/app.py
```

## Verify the Audit Chain

```bash
python satsa/audit.py --verify
```

## Verify Offline Enforcement

```bash
python satsa/offline_check.py
```

## Run Validation

```bash
python validation/run_validation.py --seed 42
```

## Run Tests

```bash
python -m pytest tests/ -v
```

---

# 20. Quality Assurance

SATIN includes automated tests covering:

- Data ingestion
- Schema validation
- Referential integrity
- Synthetic data generation
- Peer statistics
- Execution Gap detectors
- Negative Space detectors
- Novelty detection
- Entity scoring
- Review queues
- Audit-chain integrity
- Air-gap enforcement
- RBAC
- Secure storage
- Claim-vs-Reality analysis
- Examiner feedback
- Report generation
- REST APIs
- Dashboard behaviour

Current benchmark:

```text
88 tests passed
```

---

# 21. Architecture

```text
                         SATIN
                          |
          +---------------+---------------+
          |               |               |
          v               v               v
     Data Layer      Analytics Layer   Governance
          |               |               |
     Ingestion       Execution Gap       RBAC
     Validation      Negative Space      Audit
     Quarantine      Peer Statistics     Feedback
     Evidence Store  Novelty Detection   Reports
          |               |               |
          +---------------+---------------+
                          |
                          v
                Entity Supervisory Risk
                          |
                          v
                 Review Prioritisation
                          |
                          v
                  Examiner Dashboard
                          |
                          v
                Evidence-backed Finding
                          |
                          v
                  Human Decision
```

---

# 22. Repository Structure

```text
SATIN/
│
├── backend/
│   └── app.py
│
├── dashboard/
│   └── app.py
│
├── data/
│   ├── synthetic/
│   └── output/
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DEMO_SCRIPT.md
│   ├── ENCRYPTION.md
│   └── PRESENTATION_OUTLINE.md
│
├── satsa/
│   ├── audit.py
│   ├── auth.py
│   ├── claim_reality.py
│   ├── config.py
│   ├── feedback.py
│   ├── features.py
│   ├── ingest.py
│   ├── manual_review.py
│   ├── minipdf.py
│   ├── offline_check.py
│   ├── peers.py
│   ├── pipeline.py
│   ├── queue.py
│   ├── report.py
│   ├── schemas.py
│   ├── scoring.py
│   ├── secure_store.py
│   ├── store.py
│   └── detectors/
│       ├── execution_gaps.py
│       ├── negative_space.py
│       └── base.py
│
├── scripts/
│   └── scale_test.py
│
├── synth/
│   └── generate.py
│
├── tests/
│
├── validation/
│   ├── run_validation.py
│   └── run_robustness.py
│
├── requirements.txt
└── pyproject.toml
```

---

# 23. Technology Stack

| Layer | Technology |
|---|---|
| Language | Python |
| Analytics | NumPy, Polars, Pandas |
| Statistical Analysis | SciPy |
| Machine Learning | Scikit-learn |
| Evidence Store | Parquet + DuckDB |
| Backend | FastAPI |
| Dashboard | Streamlit |
| Validation | Pytest |
| Reporting | Jinja2 + WeasyPrint / offline PDF fallback |
| Authentication | Local RBAC |
| Audit | SHA-256 hash chaining |
| Deployment | Local / Air-Gapped |

---

# 24. Security & Deployment Philosophy

SATIN follows a security-first deployment model.

### Data Sovereignty

All assessment data remains within the local supervisory environment.

### Air-Gap Assurance

No runtime dependence on external services.

### Human Accountability

Analytics provide recommendations and evidence; examiners make supervisory decisions.

### Reproducibility

Inputs, parameters, code state, and generated outputs are represented in the audit trail.

### Explainability

Findings expose the evidence and statistical reasoning behind the prioritisation.

### Controlled Access

Role-based permissions separate administrative, supervisory, and audit responsibilities.

---

# 25. What SATIN Does Not Do

SATIN is intentionally not:

- A SIEM
- A SOC monitoring platform
- A live threat detection system
- A packet-analysis platform
- A replacement for SOC analysts
- A disciplinary decision engine
- A cloud-based security analytics service
- A system that makes final supervisory decisions

Instead:

> **SATIN is an offline supervisory intelligence layer that helps examiners analyse evidence produced by existing SOC operations.**

This boundary is fundamental to the solution.

---

# 26. The Supervisory Value Proposition

SATIN addresses the central challenge of supervisory assessment:

```text
Large Volume of SOC Evidence
             |
             v
       Analytical Noise
             |
             v
     SATIN Prioritisation
             |
             v
     Evidence-backed Findings
             |
             v
       Human Examination
             |
             v
     Supervisory Decision
```

The value is not simply faster analytics.

The value is **better allocation of scarce supervisory attention**.

Instead of asking an examiner to search millions of records manually, SATIN provides:

> **Who should be examined?**

> **Why should they be examined?**

> **What evidence supports the concern?**

> **How does their behaviour compare with peers?**

> **What should the examiner investigate next?**

---

# 27. Final Outcome

SATIN transforms periodic SOC submissions into a structured supervisory intelligence workflow:

```text
SUBMIT
   ↓
VALIDATE
   ↓
ANALYSE
   ↓
BENCHMARK
   ↓
PRIORITISE
   ↓
EXPLAIN
   ↓
REVIEW
   ↓
AUDIT
```

The system is designed to make supervisory assessment:

- More targeted
- More evidence-driven
- More explainable
- More reproducible
- More scalable
- More resistant to superficial metric reporting
- Suitable for air-gapped environments

---

# 28. The SATIN Principle

> ## Do not replace the examiner.
> ## Make the examiner's attention count.

SATIN does not tell a supervisor what decision to make.

It makes sure the supervisor knows:

**where to look, why to look there, and what evidence supports the concern.**

---

## Project Information

**SATIN — Supervisory Analytics & Traceability Intelligence Network**

**SIH Problem Statement:** SIH26157  
**Problem Statement:** Supervisory Analytics Tool for SOC Assessment  
**Organisation:** National Critical Information Infrastructure Protection Centre (NCIIPC)  
**Domain:** Cybersecurity / Critical Infrastructure / Supervisory Analytics  
**Deployment Model:** Offline / Air-Gapped  
**Decision Model:** Human-in-the-Loop  
**Primary User:** Supervisory Examiner

---

**License:** Proprietary Supervisory Software designed for the National Critical Information Infrastructure Protection Centre (NCIIPC). All rights reserved.


So the Quick Start section should use that exact command.
