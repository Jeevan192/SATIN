# SAT-SA: 5-Slide Executive Presentation Outline

**Context:** Presentation to the Grand Jury & Technical Evaluation Panel (NCIIPC Problem Statement)  
**Strict Limit:** Exactly 5 Slides  

---

### Slide 1: The Problem & The Core Insight
- **Title:** SAT-SA: Supervisory Analytics Tool for SOC Assessment
- **Subtitle:** Measuring the Execution Gap and Negative Space Across Critical Sector SOCs
- **Key Talking Points:**
  - *The Supervisory Challenge:* NCIIPC does not need another SIEM or real-time alert monitor. It needs an objective supervisory lens to evaluate whether Critical Sector Entities (CSEs) actually run effective SOCs or simply game compliance metrics.
  - *The Core Insight:* **"Policies dictate what a SOC claims; periodic case records show what it actually does. SAT-SA measures the gap."**
  - *Strict Boundaries (Out of Scope):* Zero real-time log ingestion, no SIEM alert firing, no central SOC monitoring platform, no cloud/external API dependencies.

---

### Slide 2: Layered Offline Architecture & Canonical Ingestion
- **Title:** 100% Air-Gapped, Peer-Relative Supervisory Engine
- **Visuals:** End-to-end layered pipeline diagram: Canonical Ingestion $\rightarrow$ Feature Layer $\rightarrow$ Peer Cohort Engine $\rightarrow$ Detectors $\rightarrow$ Scoring $\rightarrow$ Audit.
- **Key Talking Points:**
  - *Periodic Batch Ingestion:* Accepts standard CSV/JSON exports (Alerts, Cases, Workflow Events, Escalations, Assets, Profiles).
  - *Defensive Ingestion:* Vectorized Pydantic validation intercepts schema anomalies and foreign-key mismatches into a quarantine ledger without aborting batch runs.
  - *Dynamic Peer Cohorts:* Entities are partitioned by sector, asset scale, and operating model (in-house vs. MSSP). Hierarchical cohort fallbacks and MAD-robust Z-scores prevent small-cohort distortion.
  - *Air-Gap Guarantee:* Operates strictly on CPU hardware with local DuckDB/Parquet; zero internet access required.

---

### Slide 3: Multi-Lane Detectors: Execution Gap, Negative Space & Novelty
- **Title:** Dual-Concept Detection Engine with Unsupervised ML Lane
- **Visuals:** Two-column comparison of Execution Gaps vs. Negative Space with detector summary metrics.
- **Key Talking Points:**
  - *Execution Gaps (EG-01 to EG-08):* Records exist but reveal metric gaming and superficial triage.
    - *EG-01:* Critical alerts closed in $< 3$ mins vs. peer median 45 mins ($p_5$ cutoff).
    - *EG-04:* Boilerplate investigation notes detected via character n-gram TF-IDF cosine similarity ($\ge 0.85$).
    - *EG-06 & EG-07:* SLA boundary dumping and analyst concentration (Gini $> 0.70$).
  - *Negative Space (NS-01 to NS-06):* The absence of expected evidence.
    - *NS-01:* Monitored Tier-1 critical assets generating zero alerts across the entire reporting quarter.
    - *NS-02:* Missing threat categories flagged via Poisson frequency suppression tests ($p < 0.01$).
  - *Novelty Lane (NOV-01):* Unsupervised Isolation Forest + Local Outlier Factor (LOF) identifying unknown multivariate operational drift without black-box opacity.

---

### Slide 4: Explainability, Human-in-the-Loop & Cryptographic Audit
- **Title:** Actionable Findings, Budgeted Queue & Tamper-Evident Integrity
- **Visuals:** Streamlit Finding Card mockup alongside SHA-256 hash-chain block diagram.
- **Key Talking Points:**
  - *Empowering the Human Examiner:* SAT-SA never makes automated disciplinary decisions. Every finding provides an explainable reason, peer comparison chart, statistical confidence, and clickable evidence row references.
  - *Diversified Review Queue:* Constructs a realistic, budgeted review cohort: **85% risk-weighted anomalies** + **15% uniform random control samples** to prevent entity gaming and eliminate selection bias.
  - *Immutable Cryptographic Audit Trail:* Every batch run produces a cryptographically sealed `run_manifest.json` and appends to an SHA-256 hash-chained `audit_log.jsonl`. Any file modification or parameter tampering breaks the cryptographic chain and triggers instant alerts.

---

### Slide 5: Empirical Benchmark Validation & Operational Deployment
- **Title:** Measured Ground-Truth Performance & Air-Gap Deployment
- **Visuals:** Precision/Recall @ Budget chart, Lift vs. Random Sampling bar graph, and Ablation breakdown.
- **Key Talking Points:**
  - *Measured Ground-Truth Benchmark (39,211 alerts across 12 CSEs):*
    - **2.28x Lift** over random sampling at a 10% examiner review budget.
    - **27.8% Precision@5%** and **26.7% Precision@10%** on subtle and strong injected faults.
    - *Spearman Rank Correlation:* $\rho = 0.3601$ between SAT-SA Entity Risk Index and injected fault density.
  - *Ablation Proof:* Demonstrates that rules alone achieve only 10.3% precision, while the integrated Statistical + ML ensemble achieves 26.7% precision.
  - *Production Readiness:* Offline wheelhouse installation via `install_airgap.sh`, sub-5-second runtime on 39,000 alerts, and ready-to-deploy FastAPI + Streamlit review interfaces.
