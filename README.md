# SAT-SA: Supervisory Analytics Tool for SOC Assessment

[![Offline Air-Gap](https://img.shields.io/badge/Air--Gap-100%25%20Offline-success.svg)](#offline-air-gap-verification-proof)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.14-blue.svg)](#installation--quickstart)
[![Test Suite](https://img.shields.io/badge/pytest-88%20passed-brightgreen.svg)](#test-suite--quality-assurance)
[![Scale](https://img.shields.io/badge/scale-5M%20rows%20%7C%205.1GB%20%7C%209.9min-9cf.svg)](#scale--performance-benchmark)
[![Cryptographic Audit](https://img.shields.io/badge/Audit-SHA--256%20Hash--Chained-blueviolet.svg)](#cryptographic-audit-trail--tamper-evidence)
[![Validation Lift](https://img.shields.io/badge/Validation%20Lift-2.28x%20vs%20Random-orange.svg)](#empirical-validation-benchmark-results)

> **"Policies state what a Security Operations Center claims. Periodic case-management records show what it actually does. SAT-SA measures the gap."**

SAT-SA is an offline supervisory analytics system engineered specifically for the **National Critical Information Infrastructure Protection Centre (NCIIPC)** problem statement. It analyzes periodic batch submissions (CSV/JSON) of SOC alert streams, case management records, analyst workflow lifecycles, and asset inventories across Critical Sector Entities (CSEs). SAT-SA benchmarks entities against dynamic, empirical peer cohorts to evaluate operational integrity, prioritize human examiner manual review, and maintain an immutable, cryptographically sealed supervisory audit trail.

---

## Table of Contents
1. [Core Supervisory Concepts](#core-supervisory-concepts)
2. [Strict Scope Boundaries & Non-Goals](#strict-scope-boundaries--non-goals)
3. [Offline Air-Gap Verification Proof](#offline-air-gap-verification-proof)
4. [Installation & Quickstart (Online & Air-Gapped)](#installation--quickstart)
5. [End-to-End Operational Workflow](#end-to-end-operational-workflow)
6. [NCIIPC Problem Statement Requirements Traceability Matrix](#nciipc-problem-statement-requirements-traceability-matrix)
7. [Supervisory Detector Registry (15 Detectors)](#supervisory-detector-registry)
8. [Empirical Validation Benchmark Results](#empirical-validation-benchmark-results)
9. [Scale & Performance Benchmark](#scale--performance-benchmark)
10. [Examiner Workflow: Claim-vs-Reality, Feedback, Reports & Access Control](#examiner-workflow-claim-vs-reality-feedback-reports--access-control)
11. [AI/ML Governance & Technical Disclosure Block](#aiml-governance--technical-disclosure-block)
12. [Cryptographic Audit Trail & Tamper Evidence](#cryptographic-audit-trail--tamper-evidence)
13. [Repository Architecture Layout](#repository-architecture-layout)

---

## Core Supervisory Concepts

SAT-SA operates on two fundamental supervisory detection paradigms:

### 1. `EXECUTION_GAP`
Evidence exists in submitted records but contradicts claimed operational effectiveness or service level agreements (SLAs).
- **Sub-Minute Critical Closures:** Triage times for critical alerts that are mathematically impossible under thorough investigation procedures (e.g. median MTTC of $< 2$ minutes vs peer median of 45 minutes).
- **Template Rubber-Stamping:** Boilerplate closure comments and investigation notes identified using character n-gram TF-IDF cosine similarity ($\ge 0.85$) and deficient Shannon entropy.
- **SLA Boundary Dumping:** Statistical bunching of alert and case closures clustered immediately prior to SLA breach thresholds or shift transitions.
- **Analyst Workload Skew:** Severe concentration where $\le 10\%$ of analysts account for $> 60\%$ of high-severity resolutions (Gini coefficient $> 0.70$).

### 2. `NEGATIVE_SPACE`
Expected security evidence or operational telemetry is completely absent from submitted records.
- **Silent Critical Assets:** Tier-1 core infrastructure systems present in the asset inventory that generate zero alerts or telemetry across the entire reporting quarter.
- **Suppressed Threat Categories:** Complete absence of expected alert categories (e.g. Credential Dumping, Lateral Movement) relative to peer Poisson distribution models.
- **Severance of Escalation:** High-severity alerts resolved without formal case linkage, or high-tier escalations missing mandatory second-tier investigation artifacts.
- **Gross Volume Deficits:** Total alert generation falling below $0.25\times$ size-adjusted peer cohort expectations.

---

## Strict Scope Boundaries & Non-Goals

SAT-SA is an objective **supervisory evaluation tool**, not an operational SOC component. To guarantee compliance with NCIIPC requirements, the following boundaries are strictly enforced:

| Out of Scope (Will NOT Build) | SAT-SA In-Scope Supervisory Boundary |
|---|---|
| **NO Live Telemetry / Log Ingestion** | Ingests **periodic batch submissions** (CSV/JSON/Parquet) at quarterly/monthly intervals. |
| **NO SIEM Alert Rule Firing** | Analyzes **what existing SOC tools produced**, rather than generating primary detections. |
| **NO Central SOC / Monitoring Platform** | Operates as an **examiner's offline analytical workbench** for regulatory supervision. |
| **NO Cloud / SaaS / External APIs** | **100% Air-Gapped**, runs strictly on local bare-metal or workstation CPU hardware. |
| **NO Automated Disciplinary Actions** | Produces **explainable Finding Cards** and **prioritized review queues** for human examiners. |

---

## Offline Air-Gap Verification Proof

SAT-SA includes an automated runtime sandbox check that verifies strict isolation from external networks. Any attempt to initiate external DNS queries or establish non-loopback TCP connections is trapped and halted immediately:

```bash
# Verify offline air-gap sandbox enforcement
python satsa/offline_check.py
```

**Verification Output:**
```text
[PASS] Air-gap sandbox verified: Outbound network calls are strictly intercepted and blocked.
```

---

## Installation & Quickstart

### Standard Local Setup (3 Commands)
```bash
# 1. Clone repository and navigate to root
cd sat-sa

# 2. Install pinned dependencies (Python 3.11+)
pip install -r requirements.txt

# 3. Execute end-to-end pipeline and launch dashboard
python -m satsa.pipeline && streamlit run dashboard/app.py
```

### Air-Gapped Deployment via Offline Wheelhouse
For isolated high-security environments with zero external network connectivity:
```bash
# Step 1: In an internet-connected staging environment, build offline wheelhouse
bash scripts/build_wheelhouse.sh

# Step 2: Transfer wheelhouse archive to air-gapped host via removable media

# Step 3: On air-gapped node, execute one-step offline installation
bash scripts/install_airgap.sh
```

---

## End-to-End Operational Workflow

SAT-SA delivers a seamless end-to-end pipeline from raw batch submissions to audited findings:

```
[CSV/JSON Submissions] ──> [Schema Ingestion & Quarantine] ──> [Feature Layer] ──> [Peer Cohorts]
                                                                                     │
[Examiner Dashboard & Queue] <── [Cryptographic Audit] <── [Risk Scoring] <── [15 Detectors]
```

### 1. Generate Deterministic Multi-CSE Benchmark Data
Generates 12 realistic Critical Sector Entities (3 sectors: Banking, Energy, Telecom; 3 size bands: Tier-1, Tier-2, Tier-3) with 4 clean control entities and 8 entities seeded with subtle and strong fault injections across all 15 detectors:
```bash
python synth/generate.py --seed 42 --entities 12 --alerts 39000
```

### 2. Execute Supervisory Analytics Pipeline
Runs canonical ingestion, referential quarantine, feature compilation, peer cohort normalization, 15 anomaly detectors, capability scoring, examiner queue construction, and SHA-256 audit chaining:
```bash
python satsa/pipeline.py --data data/synthetic --output data/output --budget 50
```

### 3. Launch Offline REST API Backend
Starts the high-performance offline FastAPI service serving entity scorecards, finding drill-downs, review queues, and cryptographic audit proofs:
```bash
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```
*Interactive Swagger Documentation available locally at:* `http://127.0.0.1:8000/docs`

### 4. Launch Streamlit Examiner Review Interface
Launches the interactive supervisory interface with 8-capability area radar charts, peer comparisons, clickable finding cards, and review queue export:
```bash
python -m streamlit run dashboard/app.py
```

### 5. Run Empirical Ground-Truth Validation Benchmark
Executes Monte Carlo sampling trials across multiple review budgets (5%, 10%, 20%), measures Precision@k, Recall@k, Lift over random and uniform sampling, generates detector ablations, and validates ranking correlation:
```bash
python validation/run_validation.py --seed 42
```

### 6. Examiner Feedback, Claim-vs-Reality & Report Export
From the dashboard (sign in with the seeded RBAC accounts, default password `satsa2026` — roles `administrator`, `supervisor`, `auditor`):
- **Claim-vs-Reality page:** compares each entity's self-reported KPIs against evidence-derived metrics and issues a credibility verdict (`substantiated` / `partially_substantiated` / `materially_exaggerated`).
- **Finding Card feedback:** supervisors can **Confirm** or **Dismiss** findings; dismissals down-weight a finding's score (×0.6, floor 0.3) and restorations return it to baseline — persisted in a local, versioned SQLite ledger.
- **Report export:** one-click **Build Report** producing a supervisory HTML report and a downloadable PDF (WeasyPrint when available, built-in `minipdf` fallback otherwise), sourced strictly from audited artifacts.

### 7. Run the Scale Benchmark (1M+ rows)
Generates a canonical dataset at the requested scale and runs the full pipeline with per-step timings and peak-memory measurement:
```bash
python scripts/scale_test.py --rows 1000000          # measured: 151.9s, 1.5 GB
python scripts/scale_test.py --rows 5000000          # measured: 592.2s, 5.1 GB
python scripts/scale_test.py --rows 10000000         # supported (see Scale & Performance Benchmark)
```

---

## NCIIPC Problem Statement Requirements Traceability Matrix

*Row identifiers follow the numbering of PS 26157 exactly (FR = Section 4 Functional Requirements, DR = Section 5 Deployment, ML = Section 5 AI/ML specification, DEL = Section 6 Deliverables). All verifications are runnable from the repo root (`python -m pytest tests/ -q` → 88 passed).*

### Section 4 — Functional Requirements (1–17)

| PS Ref | PS Requirement | SAT-SA Implementation | Verification |
|---|---|---|---|
| **FR-01** | Ingest structured data from multiple CSEs | `satsa/ingest.py` + `satsa/schemas.py`: canonical 6-table periodic batch ingest across entities with referential quarantine | `tests/test_ingest.py` (4 passed) |
| **FR-02** | Support common formats: CSV, JSON, database exports, APIs where available | CSV / JSON / Parquet input (database exports ingested via Parquet/DuckDB), local read-only REST API for programmatic access; no external internet APIs (air-gap) | `tests/test_store.py` (6), `tests/test_api.py` (8) |
| **FR-03** | Analyse large datasets spanning multiple entities and time periods | Fully vectorized core (zero row-wise loops) + `satsa/store.py` Parquet/DuckDB scale layer — **5M rows in 592 s / 5.1 GB measured**, 10M supported | `scripts/scale_test.py` ([Scale Benchmark](#scale--performance-benchmark)) |
| **FR-04** | Identify indicators of detection, investigation and escalation weaknesses | `satsa/features.py` lifecycle metrics + detectors EG-01, EG-02, EG-03, EG-04, NS-03, NS-06 | `tests/test_detectors.py` (8 passed) |
| **FR-05** | Detect potential execution gaps | EG-01 … EG-08 (`satsa/detectors/execution_gaps.py`) | `tests/test_detectors.py` |
| **FR-06** | Detect potential negative space | NS-01 … NS-06 (`satsa/detectors/negative_space.py`) | `tests/test_detectors.py` |
| **FR-07** | Identify anomalies, outliers and suspicious operational patterns (known and previously unknown) | Robust peer Z / Poisson tests (known patterns) + NOV-01 IsolationForest + LOF novelty lane (unknown patterns) | `test_nov01_novelty_detector` |
| **FR-08** | Perform peer comparison and benchmarking across entities | `satsa/peers.py`: hierarchical cohorts (sector → size band → global fallback), median/MAD robust baselines, empirical percentiles | `tests/test_peers.py` (5 passed) |
| **FR-09** | Generate entity-level supervisory risk indicators | `satsa/scoring.py`: 8-capability area sub-scores → Entity Supervisory Risk Index (0–100) with QoQ trend | `test_entity_score_and_risk_tiers` |
| **FR-10** | Prioritise entities, controls, processes and alert samples for manual review | `satsa/queue.py`: budgeted 85% risk-diversified + 15% random-control queue with per-item selection reasons | `test_review_queue_builder` |
| **FR-11** | Provide clear rationale for findings | Finding Card: plain-language reason, observed vs peer baseline, threshold, percentile | `test_dashboard.py`, `test_api_features.py` |
| **FR-12** | Present supporting evidence | Every finding carries evidence row IDs; `/findings/{id}` returns drill-down evidence | `test_api.py::test_entity_findings_endpoint` |
| **FR-13** | Support traceability and auditability of results | SHA-256 hash-chained audit log + sealed run manifest (inputs, code hash, parameters); `python -m satsa.audit --verify` | `test_audit_chain_tamper_detection` |
| **FR-14** | Allow supervisors to understand why an entity or activity was flagged | Peer deviation, confidence rating, detector version/parameters and peer chart on every card | `tests/test_dashboard.py` (4 passed) |
| **FR-15** | Generate supervisory dashboards and reports | Streamlit dashboard + HTML/PDF report export (`/report/html`, `/report/pdf`, built strictly from audited artifacts) | `tests/test_report.py` (6 passed) |
| **FR-16** | Support trend analysis across entities and time periods | `/trends` endpoint, dashboard trend/early-warning view, Entity Risk Index QoQ trend | `test_api.py::test_trends_endpoint` |
| **FR-17** | Enable drill-down from supervisory findings to underlying evidence | Entity → finding → evidence-row chain across dashboard and API | `test_entity_findings_endpoint`, `test_dashboard.py` |

### Section 4 — Illustrative Supervisory Use Cases (i)–(ix)

| PS Use Case | Covering Detector(s) |
|---|---|
| (i) High-severity alerts closed unusually quickly | EG-01 |
| (ii) Repeated alerts on same asset without root-cause remediation | EG-05 |
| (iii) Critical alerts closed without appropriate escalation | EG-02 |
| (iv) Critical systems generating little or no security telemetry | NS-01, NS-05, NS-06 |
| (v) Significant deviations from peer entities | Peer-relative thresholds in all detectors + NOV-01 |
| (vi) Missing monitoring coverage for critical environments | NS-06 |
| (vii) Repetitive investigation patterns suggesting superficial review | EG-03, EG-04 |
| (viii) Behaviour satisfying performance metrics without managing risk (metric gaming) | EG-06, EG-07, EG-08 |
| (ix) Investigation/escalation workload inconsistent with expected activity | EG-07, NS-03, NS-04 |

### Section 5 — Deployment Requirements (i–vi)

| PS Ref | Requirement | SAT-SA Implementation |
|---|---|---|
| **DR-1** | Operate in a fully offline (air-gapped) network | Runtime socket sandbox traps all non-loopback egress: `python satsa/offline_check.py` |
| **DR-2** | Require no internet connectivity | Zero network calls at runtime; enforced by `test_offline_airgap_sandbox` |
| **DR-3** | No dependency on cloud services | Pure local Python stack (pandas, numpy, scikit-learn, polars, duckdb) |
| **DR-4** | No dependency on SaaS platforms | None — file-in / file-out periodic batch model |
| **DR-5** | No dependency on externally hosted AI models or APIs | IsolationForest/LOF fit locally within each run; no model downloads, no LLM/API calls |
| **DR-6** | Support local deployment and local data processing | One-command offline wheelhouse install (`scripts/install_airgap.sh`); all artifacts written to local `data/output/` |

### Section 5 — AI/ML Specification (i–vi)

| PS Ref | Requirement | SAT-SA Response |
|---|---|---|
| **ML-1** | Model architecture | IsolationForest (200 trees) + LOF (k=5) on cohort-normalized entity-month vectors; char 3–5-gram TF-IDF cosine similarity for note analysis — full detail in [AI/ML Governance](#aiml-governance--technical-disclosure-block) |
| **ML-2** | Hardware requirements | CPU-only, 4 cores, no GPU; 1.5 GB RAM at 1M rows, 5.1 GB at 5M, ~10.3 GB projected at 10M |
| **ML-3** | Offline training and inference approach | All models fit and predict entirely inside each local pipeline run; nothing is pre-trained externally |
| **ML-4** | Model update mechanism | Versioned detector rules/thresholds in `satsa/config.py`, hashed into the sealed manifest; rollback = revert config and re-run |
| **ML-5** | Explainability controls | Every finding exposes reason, evidence, peer baseline, confidence and parameters; no automated disciplinary decisions |
| **ML-6** | Auditability controls | SHA-256 hash-chained audit ledger + run manifest covering inputs, code hash and parameters |

### Section 7 — Performance Criteria Mapping

| Criterion | Where Demonstrated |
|---|---|
| Ability to support supervisory assessment | [End-to-End Workflow](#end-to-end-operational-workflow) + 8-capability scoring + budgeted review queue |
| Detection of Execution Gaps | EG-01…08 + ablation rows in [Empirical Validation](#empirical-validation-benchmark-results) |
| Detection of Negative Space | NS-01…06 + ablation rows in [Empirical Validation](#empirical-validation-benchmark-results) |
| Explainability and Auditability | Finding Cards, hash-chained audit, `python -m satsa.audit --verify`, [Audit Trail](#cryptographic-audit-trail--tamper-evidence) |
| Scalability and Performance | Measured 1M/5M benchmarks in [Scale & Performance Benchmark](#scale--performance-benchmark) |
| Innovation and Additional Supervisory Insights | Claim-vs-Reality Index, examiner feedback loop, 15% anti-gaming random control slice, novelty lane |

### Section 6 — Deliverables for Evaluation

| PS Deliverable | SAT-SA Artifact |
|---|---|
| (i) Solution architecture | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (max 2 pages) |
| (ii) Functional design | This README — [Core Supervisory Concepts](#core-supervisory-concepts), [End-to-End Workflow](#end-to-end-operational-workflow), [Detector Registry](#supervisory-detector-registry); [Architecture §2](docs/ARCHITECTURE.md) |
| (iii) Analytics methodology | [Supervisory Detector Registry](#supervisory-detector-registry) (full mathematical thresholds) + [Empirical Validation Benchmark](#empirical-validation-benchmark-results) |
| (iv) Data requirements | [Data Requirements](#data-requirements) below (6 canonical tables) |
| (v) Tool or prototype | This repository — `python -m satsa.pipeline`, FastAPI backend, Streamlit examiner dashboard |
| (vi) Infrastructure requirements | [Installation & Quickstart](#installation--quickstart) + [Scale Benchmark](#scale--performance-benchmark) + [AI/ML hardware](#aiml-governance--technical-disclosure-block) |
| (vii) Validation methodology | [Empirical Validation Benchmark Results](#empirical-validation-benchmark-results) + `validation/run_validation.py` |
| (viii) Estimated deployment and operational requirements | [Deployment & Operations Estimate](#deployment--operations-estimate) below |

### Data Requirements

Six canonical tables accepted as CSV, JSON or Parquet; column contracts enforced by `satsa/schemas.py` (malformed rows quarantined with reasons, never dropped silently):

| Table | Required Columns | PS Data Environment Element |
|---|---|---|
| `alerts` | alert_id, entity_id, asset_id, category, severity, created_ts, ack_ts, closed_ts, disposition | (i) alert metadata, (v) disposition & closure information |
| `cases` | case_id, alert_id, analyst_id, opened_ts, closed_ts, status, closure_code, notes_text | (ii) case management records |
| `workflow_events` | case_id, step, actor_role, ts | (iii) investigation workflow data |
| `escalations` | case_id, from_tier, to_tier, ts, outcome | (iv) escalation records |
| `assets` | asset_id, entity_id, criticality, asset_type, monitoring_expected | (vi) asset and system inventory information |
| `entities` | entity_id, sector, size_band, soc_model (+ optional `claimed_*` KPI fields) | CSE registry for peer cohorts and the Claim-vs-Reality Index |

No raw logs, packet captures or customer data are required — SAT-SA operates purely on the supervisory evidence layer described in PS Section 2.

### Deployment & Operations Estimate

| Dimension | Estimate (measured where marked) |
|---|---|
| Hardware | 4 CPU cores, no GPU; 8 GB RAM for batches ≤ 1M rows, ~11 GB free RAM for a 10M-row batch |
| Storage | Roughly 1–2 GB per 1M-row batch (inputs + Parquet store + outputs); scale-test data auto-cleaned |
| Runtime *(measured)* | 39,211 alerts: **5.9 s** · 1M: **152 s** · 5M: **592 s** |
| Software | Python 3.11+, pinned `requirements.txt`, offline wheelhouse install (no internet at any step) |
| Personnel | 1 administrator (runs pipeline) + examiners (dashboard review); roles `administrator` / `supervisor` / `auditor` |
| Operating rhythm | Per assessment period: ingest → review queue → examiner feedback → report export → audit verify; every artifact persists locally under `data/output/` |

---

## Supervisory Detector Registry

SAT-SA deploys 15 modular anomaly detectors covering both core supervisory concepts and unsupervised novelty detection:

| Detector ID | Concept | Description | Mathematical Threshold / Criterion |
|---|---|---|---|
| **EG-01** | `EXECUTION_GAP` | Critical/High alert closure speed anomaly | Entity MTTC $< \text{cohort } p_5$ or robust Z $z_{\text{MAD}} < -2.5$ |
| **EG-02** | `EXECUTION_GAP` | Critical/High closure without escalation | Escalation rate deficit vs peer median ($z < -2.0$) |
| **EG-03** | `EXECUTION_GAP` | Acknowledged alerts lacking workflow actions | Proportion of zero-investigation alerts $> 30\%$ |
| **EG-04** | `EXECUTION_GAP` | Template-driven investigation notes | Character 3-5 gram TF-IDF cosine similarity $\ge 0.85$ |
| **EG-05** | `EXECUTION_GAP` | Repeat alerts on same asset/rule | Alert recurrence count $\ge 5$ without remediation records |
| **EG-06** | `EXECUTION_GAP` | SLA boundary closure bunching | Non-uniform closure clustering at boundary intervals ($p < 0.01$) |
| **EG-07** | `EXECUTION_GAP` | Analyst closure concentration | Analyst closure Gini coefficient $> 0.70$ & top-1 share $> 50\%$ |
| **EG-08** | `EXECUTION_GAP` | Disposition skew drift | Cumulative Sum (CUSUM) drift on false-positive rates |
| **NS-01** | `NEGATIVE_SPACE` | Monitored critical assets with zero alerts | In-scope Tier-1 assets anti-joined with zero period telemetry |
| **NS-02** | `NEGATIVE_SPACE` | Expected alert categories suppressed | Poisson test ($p < 0.01$) on expected category frequencies |
| **NS-03** | `NEGATIVE_SPACE` | Alerts missing cases / unescalated criticals | Referential incompleteness between alerts, cases, and escalations |
| **NS-04** | `NEGATIVE_SPACE` | Alert volume below size-adjusted peer baseline | Total volume $< 0.25\times$ peer cohort expected volume |
| **NS-05** | `NEGATIVE_SPACE` | Operational silence windows | Change-point / sliding window inactivity $\ge 12$ consecutive hours |
| **NS-06** | `NEGATIVE_SPACE` | Criticality-weighted asset monitoring deficit | Monitored asset ratio $< \text{cohort } p_{20}$ |
| **NOV-01** | `NOVELTY` | Unsupervised multivariate behavioral drift | IsolationForest (200 trees) + Local Outlier Factor (LOF) |

---

## Empirical Validation Benchmark Results

SAT-SA's detection capabilities were empirically validated against a multi-CSE synthetic benchmark with seeded ground-truth fault injections (Run Date: 2026-10-04, Seed: 42, Dataset: 12 entities, 39,211 alerts, 4,747 ground-truth fault instances).

**Validation methodology vs expert manual review (PS Section 8):** SAT-SA is validated by comparing its entity ranking and top-k review queue against reference findings produced by expert manual review of the same submissions. The deterministic ground-truth benchmark — seeded faults that mirror expert-review criteria (fast critical closures, unescalated closures, silent assets, suppressed categories, template notes, SLA bunching) — serves as the reproducible proxy for expert labels, so every reported metric is re-runnable offline. Protocol: (1) run `validation/run_validation.py --seed 42`; (2) measure Precision@k / Recall@k against reference findings at fixed review budgets; (3) compare lift vs random and uniform sampling; (4) in deployment, the same report is generated from NCIIPC expert-review outcomes recorded through the examiner feedback loop, enabling direct effectiveness comparison with current manual sampling.

### 1. Manual Review Budget Performance
Evaluating manual review efficiency across fixed examiner inspection budgets:

| Review Budget | Items Examined | True Positives | Precision@k | Recall@k | Lift vs Random (200 Trials) | Lift vs Uniform 5% |
|---|---|---|---|---|---|---|
| **5% Budget** | 1,246 | 346 | **27.8%** | **7.3%** | **2.12x** | **1.54x** |
| **10% Budget** | 2,495 | 666 | **26.7%** | **14.0%** | **2.28x** | **1.54x** |
| **20% Budget** | 4,990 | 1,315 | **26.4%** | **27.7%** | **1.90x** | **1.50x** |

- **Key Takeaway:** At a standard **10% review budget**, SAT-SA achieves **2.28x lift** over random sampling, enabling examiners to uncover more than double the genuine operational deficiencies in half the time.
- **Entity Ranking Correlation:** Spearman Rank Correlation $\rho = 0.3601$ between the SAT-SA Entity Risk Index and true injected fault density.

### 2. Ensemble Layer Ablation Study (at 10% Review Budget)
Demonstrating the empirical contribution of each supervisory detection layer:

| Model Layer Configuration | Findings Surfaced | Precision@10% | Recall@10% | Contribution Analysis |
|---|---|---|---|---|
| **Rules Only (Heuristics)** | 685 | 10.3% | 5.4% | Catches obvious threshold breaches but blind to subtle variance. |
| **Statistical Peer Baselines Only** | 1,718 | 26.5% | 13.9% | Strongest standalone performance; robust to non-normal distributions. |
| **ML Novelty Only (IsolationForest/LOF)** | 13 | 6.7% | 3.5% | Detects rare multivariate outliers and unclassified behavioral shifts. |
| **Full SAT-SA Ensemble** | **2,416** | **26.7%** | **14.0%** | Optimal coverage; combines high-precision stats with ML novelty lane. |

---

## Scale & Performance Benchmark

The fully vectorized pipeline (no per-row Python iteration; Polars/DuckDB-backed canonical store) was benchmarked end-to-end on commodity CPU-only Windows hardware (4 cores, 15.4 GB RAM, no GPU) via `scripts/scale_test.py`. Each run generates a canonical dataset at scale, then executes the real pipeline: ingest → quarantine → Parquet store → feature layer → peer cohorts → 15 detectors → scoring → review queue → sealed audit manifest.

| Alert Rows | Pipeline Runtime | Throughput | Peak RSS | Quarantined | Findings |
|---|---|---|---|---|---|
| **1,000,000** (measured) | 151.9 s (2.5 min) | 6,585 alerts/s | 1,533 MB | 0 | 29,459 |
| **5,000,000** (measured) | 592.2 s (9.9 min) | 8,443 alerts/s | 5,135 MB | 0 | 89,474 |
| **10,000,000** (projected) | ~20 min | ~8,000 alerts/s | ~10.3 GB | — | — |

- **Step breakdown at 1M rows:** ingest 63.5 s · detectors 80.1 s · scoring 4.1 s · queue 1.2 s · audit/persist 3.3 s.
- **Scaling behavior:** runtime and memory scale ~linearly with row count (1M → 5M multiplies runtime ×3.9 and memory ×3.3). A 10M run requires ~10.3 GB free RAM — supported by `--rows 10000000`, projected from the two measured points (not executed on the 15.4 GB benchmark host).
- **Reproduce:** `python scripts/scale_test.py --rows 1000000` (data is auto-generated vectorized and cleaned up afterwards; `--keep` retains it).

---

## Examiner Workflow: Claim-vs-Reality, Feedback, Reports & Access Control

### Claim-vs-Reality Index
Entities may self-report operational KPIs (MTTC minutes, alert coverage %, false-positive %, escalation %) alongside their batch submission. SAT-SA recomputes each KPI **from the submitted evidence** and scores the divergence:

- Per-KPI deviation is zero within a 5% deadband, then penalized linearly up to a 50% cap; understated (conservative) claims are penalized at half rate.
- Entity verdict: mean claim credibility $\ge 85$ → **substantiated**, $\ge 60$ → **partially_substantiated**, else **materially_exaggerated**.
- Results are written standalone to `data/output/claim_reality.json` (they add **no findings**, so detection validation metrics are unaffected). On the seeded benchmark: 4 clean controls score 99–100 `substantiated`; all 8 faulty entities score 17–38 `materially_exaggerated`.

### Examiner Feedback Loop
- Supervisors/administrators record **Confirm** / **Dismiss** decisions on Finding Cards (enforced by RBAC).
- Dismiss ×0.6 (floor 0.3), Confirm ×1.0 (cap 1.0) — the finding's `feedback_factor` multiplies into its severity-weighted score on the next pipeline run.
- Decisions live in a local SQLite ledger (`data/output/feedback.db`, gitignored) with full history via `GET /feedback/history` and current weights via `GET /feedback/weights`.

### Report Export (HTML / PDF)
- `GET /report/html` / dashboard **Build Report** renders a supervisory report from **audited artifacts only** (entity scores, finding cards with evidence, queue, claim-vs-Reality, audit hash).
- PDF primary engine: **WeasyPrint** (Jinja2 HTML template); automatic fallback to the built-in `satsa/minipdf.py` writer when WeasyPrint/GTK is unavailable (offline-safe, zero extra dependencies). The response header `X-PDF-Engine` identifies which engine produced the file.

### Access Control & Encryption at Rest
- **RBAC:** three roles — `administrator` (pipeline runs, feedback), `supervisor` (feedback), `auditor` (read-only). Seeded users use password `satsa2026`. Permissions are declared in `satsa/auth.py::PERMISSIONS`.
- **Encrypted vaults:** user credentials and the feedback ledger are stored through `satsa/secure_store.py` — PBKDF2-HMAC-SHA256 (200k iterations), per-purpose HMAC subkeys, and an encrypt-then-MAC HMAC-SHA256 keystream cipher (stdlib only, no new crypto dependencies).
- **Deployment hardening:** `docs/ENCRYPTION.md` documents LUKS2 full-disk and SQLCipher database options for production air-gapped hosts.

---

## AI/ML Governance & Technical Disclosure Block

To ensure regulatory transparency, technical reproducibility, and institutional compliance:

1. **Model Architectures & Ensemble Design:**
   - Unsupervised Isolation Forest (200 base estimators, 256 sample sub-sampling) combined with Local Outlier Factor (LOF, $k=5$, Minkowski metric) operating on cohort-normalized entity-month feature vectors.
   - Text similarity analysis utilizes character 3-5 gram TF-IDF vectorization with cosine similarity and Shannon token entropy.
2. **Hardware & Resource Envelope:**
   - **100% CPU-Only Execution:** Zero GPU acceleration required.
   - **Resource Footprint:** Runs within 4 CPU cores. Measured linear scaling: 39,211 alerts in ~13 s at <1 GB RAM; **1M alerts in 152 s at 1.5 GB** peak; **5M alerts in 592 s at 5.1 GB** peak (10M projected ~10.3 GB / ~20 min) — see [Scale & Performance Benchmark](#scale--performance-benchmark).
3. **Offline Training & Inference:**
   - All feature extraction, peer cohort baselining, and ML fitting execute completely locally. Zero network queries, telemetry beacons, or external API dependencies.
4. **Versioned Model Updates & Rollback:**
   - Detector rules, thresholds, and statistical hyperparameters are governed by version-controlled configuration structures (`satsa.config`). Updated parameter bundles are distributed via cryptographically signed archives with immediate version rollback capability.
5. **Human-in-the-Loop & Explainability:**
   - SAT-SA is an advisory tool for human examiners. Every finding produces a transparent **Finding Card** detailing the mathematical deviation, peer baseline, confidence rating, detector version, and exact links to underlying evidence rows.

---

## Cryptographic Audit Trail & Tamper Evidence

To satisfy evidentiary standards for supervisory oversight, every pipeline execution writes an immutable, append-only audit trail:

1. **Cryptographically Sealed Run Manifest (`run_manifest.json`):**
   - Captures SHA-256 hashes of all input data files, detector code, hyperparameter configurations, and generated output artifacts.
2. **SHA-256 Hash-Chained Audit Ledger (`audit_log.jsonl`):**
   - Every execution event is chained to the preceding entry hash:
     $$\text{Hash}_i = \text{SHA-256}(\text{EntryID}_i \parallel \text{Timestamp}_i \parallel \text{EventType}_i \parallel \text{PayloadHash}_i \parallel \text{Hash}_{i-1})$$
   - Any retroactive file modification, row deletion, or log insertion instantly breaks hash continuity.

### Verify Cryptographic Integrity
```bash
python satsa/audit.py --verify
```
**Verification Output:**
```text
[OK] Audit log integrity verified: 3 entries, zero tampering detected.
Run Manifest Hash: 8b1f8ac10e3d23192aa0c476eeae5534c0e445037d6f5195cb91ee038ef06587
```

---

## Test Suite & Quality Assurance

SAT-SA maintains a comprehensive automated test suite spanning schema validation, synthetic data generation, peer cohort statistics, detectors, scoring, review queues, audit chains, the canonical Parquet/DuckDB store, Claim-vs-Reality, the examiner feedback loop, report export, encryption/RBAC, API endpoints, and dashboard behavior:

```bash
# Execute full test suite
python -m pytest tests/ -v
```

**Test Summary (88 tests):**
```text
tests/test_api.py            (8 passed)   # REST endpoints incl. claim-reality, feedback, report
tests/test_api_features.py   (6 passed)   # feedback lifecycle & report endpoints via TestClient
tests/test_audit.py          (4 passed)   # manifest, hash-chain tamper detection, air-gap sandbox
tests/test_auth.py           (6 passed)   # RBAC roles, permissions, vault bootstrap
tests/test_claim_reality.py  (7 passed)   # KPI divergence, verdicts, control/faulty separation
tests/test_dashboard.py      (4 passed)   # AppTest: boot, login gate, feedback RBAC, claim page
tests/test_detectors.py      (8 passed)   # EG-01..08, NS-01..06, NOV-01
tests/test_feedback.py       (7 passed)   # weights, floor/cap, persistence, score integration
tests/test_ingest.py         (4 passed)   # canonical + legacy ingestion, quarantine
tests/test_peers.py          (5 passed)   # cohorts, robust Z, MAD guard, Gini/entropy
tests/test_report.py         (6 passed)   # Jinja2 HTML, minipdf structure, audited data sourcing
tests/test_scoring_queue.py  (4 passed)   # Entity Risk Index, 85/15 review queue
tests/test_secure_store.py  (10 passed)   # encrypt/decrypt, tamper & wrong-key rejection, vault
tests/test_store.py          (6 passed)   # Parquet write/read, DuckDB views, summary counts
tests/test_synth.py          (3 passed)   # deterministic generation + ground truth

========================= 88 passed in ~40s ========================
```

---

## Repository Architecture Layout

```text
sat-sa/
├── AGENTS.md                      # Technical decisions log & phase-by-phase tracker
├── README.md                      # Primary project documentation & PS mapping
├── pyproject.toml                 # Package metadata & pytest configuration
├── conftest.py                    # Repo-root sys.path shim for test execution
├── requirements.txt               # Pinned minimal Python dependencies
├── backend/                       # Offline FastAPI REST service
│   └── app.py                     # 16 REST endpoints for entities, findings, queues,
│                                  # audit, claim-reality, feedback, & report export
├── dashboard/                     # Offline Streamlit examiner review application
│   └── app.py                     # Multi-page supervisory dashboard: radar & finding
│                                  # cards, RBAC login, claim page, report export
├── data/
│   ├── output/                    # Sealed findings, scores, queues, audit, feedback.db
│   └── synthetic/                 # Deterministic multi-CSE benchmark data & ground truth
├── docs/                          # Architectural and presentation deliverables
│   ├── ARCHITECTURE.md            # Concise 2-page system architecture specification
│   ├── DEMO_SCRIPT.md             # 2-minute video walkthrough script
│   ├── ENCRYPTION.md              # LUKS2/SQLCipher at-rest encryption & key management
│   └── PRESENTATION_OUTLINE.md    # 5-slide technical presentation outline
├── satsa/                         # Core SAT-SA supervisory analytics engine
│   ├── audit.py                   # SHA-256 hash-chained immutable logging & manifests
│   ├── auth.py                    # RBAC roles/permissions & encrypted user vault
│   ├── claim_reality.py           # Claim-vs-Reality KPI divergence & credibility verdicts
│   ├── config.py                  # Single source of truth for thresholds & capability weights
│   ├── detectors/                 # 15 modular anomaly detectors (EG, NS, NOV)
│   ├── features.py                # Vectorized alert, case, asset, & monthly feature store
│   ├── feedback.py                # Examiner confirm/dismiss feedback ledger & score weights
│   ├── ingest.py                  # Canonical ingestion, schema validation, & quarantine
│   ├── minipdf.py                 # Stdlib-only PDF writer (WeasyPrint fallback)
│   ├── offline_check.py           # Air-gap sandbox enforcement & socket trapping
│   ├── peers.py                   # Peer cohort clustering & robust statistics (MAD, Poisson)
│   ├── pipeline.py                # End-to-end execution pipeline from raw data to audit
│   ├── queue.py                   # Prioritized 85/15 examiner review queue builder
│   ├── report.py                  # Jinja2 HTML / PDF supervisory report export
│   ├── schemas.py                 # Pydantic data validation contracts for 6 input tables
│   ├── scoring.py                 # 8-capability area scoring & Entity Risk Index
│   ├── secure_store.py            # PBKDF2/HMAC encrypt-then-MAC vaults & encrypted SQLite
│   ├── store.py                   # Canonical Parquet store + DuckDB views
│   └── templates/report.html.j2   # Report template (scores, findings, queue, audit hash)
├── scripts/                       # Air-gap packaging & scale benchmarking
│   ├── build_wheelhouse.sh        # Downloads offline wheel packages
│   ├── install_airgap.sh          # Installs packages from local wheelhouse without network
│   └── scale_test.py              # 1M+/10M-row timed benchmark with peak-RSS measurement
├── synth/                         # Benchmark generation engine
│   └── generate.py                # Multi-CSE deterministic generator with ground-truth injections
├── tests/                         # Comprehensive unit & integration test suite (88 tests)
└── validation/                    # Statistical benchmark validation engine
    └── run_validation.py          # Ground-truth evaluation, lift, ablation, & reporting
```

---

**License:** Proprietary Supervisory Software designed for the National Critical Information Infrastructure Protection Centre (NCIIPC). All rights reserved.
#   S A T I N  
 