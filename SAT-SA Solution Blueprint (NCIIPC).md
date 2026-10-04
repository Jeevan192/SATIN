# SAT-SA: Supervisory Analytics Tool for SOC Assessment

### Problem Analysis, Tool Stack and Winning Workflow (NCIIPC)

---

## 1. What the problem really is

NCIIPC does not want a SOC, a SIEM or a threat detector. It wants a **supervisory lens**: a tool that reads *what SOCs did* (alerts, cases, escalations, closures) and tells an examiner **which entity, which process and which 20 alerts to look at manually**.

One-line pitch: **"Policies say what a SOC claims. Case data shows what it actually does. SAT-SA measures the gap."**

Three things judges will test you on, hidden between the lines:

| Hidden expectation | How to answer it |
| --- | --- |
| Triage *the reviewer's time*, not the alerts | Output is a ranked review queue with a stated review budget, not a list of "malicious" events |
| "Negative space" is the novelty | Detect absence using peer expectation models, not just anomalies in existing data |
| Human stays in charge | Every flag shows rule/stat, evidence rows, peer baseline and a "why flagged" sentence; no black box |
| Air-gapped is a hard gate | Zero cloud, zero external API, zero LLM-as-a-service. Offline install bundle is part of the demo |
| Validation vs manual review | Show recall of seeded and expert-labelled weaknesses within the top-k review budget vs random sampling |

**Out of scope (do not build, say so on slide 1):** real-time monitoring, log collection, SIEM, central SOC, national monitoring platform.

---

## 2. Two core concepts to model

**A. Execution Gaps** (evidence exists but contradicts claimed effectiveness) Quick closures, no investigation notes, critical alerts closed unescalated, template investigations, metric gaming (e.g. closing fast to hit MTTR).

**B. Negative Space** (expected evidence is missing) Critical assets with no telemetry, missing alert categories, cases without escalation records, activity far below peers, blind spots in the asset inventory vs alert coverage.

Design rule: every detector is tagged `EXECUTION_GAP` or `NEGATIVE_SPACE` and maps to one or more of the 8 capability areas (detection, investigation, escalation, response, SecOps, governance, discipline, resilience).

---

## 3. Solution architecture (offline, layered)

```
 [CSE periodic submissions: CSV / JSON / DB export / API]
                    |
 1. INGEST     adapters + schema mapper + validators + quarantine of bad rows
                    |
 2. CANONICAL STORE   Parquet + DuckDB (columnar, local, fast)  |  SQLite (audit, config)
                    |
 3. FEATURE LAYER     per-alert, per-case, per-asset, per-entity-month features
                    |
 4. DETECTION ENGINE
      a. Rule/heuristic detectors (known indicators)
      b. Statistical detectors (robust z, MAD, CUSUM, change-point)
      c. Peer-baseline engine (cohort percentile, expected-vs-observed)
      d. Unsupervised ML (Isolation Forest, LOF) for unknown unknowns
      e. Text similarity (MinHash/TF-IDF) for template investigations
                    |
 5. SCORING & PRIORITISATION   entity risk index, sample priority, review queue
                    |
 6. EXPLAINABILITY & AUDIT     reason codes, evidence pointers, hash-chained run log
                    |
 7. PRESENTATION   dashboard (Streamlit/FastAPI+React), drill-down, PDF/HTML reports
```

### Tool stack (all open source, installable from an offline wheelhouse)

| Layer | Choice | Why |
| --- | --- | --- |
| Language | Python 3.11 | Ecosystem, easy offline packaging |
| Data | Polars + DuckDB + Parquet | Millions of rows on a laptop; SQL drill-down |
| Validation | Pydantic / pandera | Schema contracts per source |
| Stats/ML | scikit-learn, statsmodels, ruptures (change-point), SciPy | Interpretable, CPU-only |
| Text | scikit-learn TF-IDF + datasketch MinHash/LSH | Near-duplicate notes without any LLM |
| Explainability | Rule reason codes + SHAP (tree models) + percentile-vs-peer | Auditable by non-data people |
| API/UI | FastAPI + Streamlit (fast) or React + Plotly (polished) | Offline CDN-free assets |
| Audit | SQLite + SHA-256 hash chain, signed run manifest | Tamper-evident traceability |
| Packaging | Docker image tar + offline wheelhouse + `make install-airgap` | Proves air-gap deployability |
| Reports | Jinja2 + WeasyPrint (PDF/HTML) | No external services |

**AI/ML disclosure block (required by the PS):** model architecture (Isolation Forest, \~200 trees; LOF; optional gradient-boosted ranker trained on examiner labels), hardware (8 cores, 32 GB RAM, no GPU needed), offline train/infer (training on local labelled review outcomes, inference via batch jobs), model update (signed model bundle imported by USB, versioned, with rollback), explainability controls (reason codes, SHAP, peer percentile), auditability (model hash, feature snapshot and config stored per run).

---

## 4. Canonical data model (what you ask CSEs to submit)

| Table | Key fields |
| --- | --- |
| `alerts` | alert_id, entity_id, asset_id, source_tool, category, severity, created_ts, acknowledged_ts, closed_ts, disposition |
| `cases` | case_id, alert_ids, analyst_id (pseudonymised), opened_ts, closed_ts, status, closure_code, notes_text (optional) |
| `workflow_events` | case_id, step, actor_role, ts (assign, enrich, escalate, approve, close) |
| `escalations` | case_id, from_tier, to_tier, ts, reason, outcome |
| `assets` | asset_id, entity_id, criticality, type, owner, in_scope_monitoring (bool) |
| `entity_profile` | entity_id, sector, size band, SOC model (in-house/MSSP), tool inventory |

Minimisation: no raw logs, PCAPs or customer data. Free-text notes are optional and processed only as hashed shingles, so the tool never needs to expose content beyond the evidence view.

---

## 5. Analytics methodology: detector catalogue

Build 20+ detectors; show \~12 well in the demo. Each yields: `detector_id, type, entity, severity_weight, evidence_rows, peer_percentile, reason_text`.

### Execution-gap detectors

| ID | Signal | Method |
| --- | --- | --- |
| EG-01 | High/critical alerts closed unusually fast | Time-to-close vs severity-specific peer distribution (robust z, p5 cutoff) |
| EG-02 | Critical closed with no escalation | Rule + expected escalation rate from peers |
| EG-03 | Acknowledged but no investigative activity | Ack-to-first-action gap, zero workflow events between ack and close |
| EG-04 | Template-driven closures | MinHash similarity of notes and closure codes, diversity entropy |
| EG-05 | Repeat alerts on same asset, no root cause | Recurrence count per asset-rule within window and no remediation/change record |
| EG-06 | Metric gaming | Closure clustering at SLA boundaries, end-of-shift or month-end bursts, bimodal time-to-close |
| EG-07 | Analyst concentration | Few analysts closing most critical cases, abnormal per-analyst throughput |
| EG-08 | Disposition skew | False-positive rate far above or below peers, rising over time (CUSUM) |

### Negative-space detectors

| ID | Signal | Method |
| --- | --- | --- |
| NS-01 | Critical assets with no telemetry | Asset inventory anti-join with alerts and event counts per period |
| NS-02 | Missing expected alert categories | Peer category-mix profile; flag categories with observed far below expected (Poisson test) |
| NS-03 | Alerts with no case, cases with no escalation | Referential completeness checks across tables |
| NS-04 | Unexpectedly low activity | Volume vs size-adjusted peer expectation (quantile regression) |
| NS-05 | Silent periods | Time-series gaps, change-point on volume (ruptures/PELT) |
| NS-06 | Coverage blind spots | Criticality-weighted coverage ratio: monitored critical assets / total |
| NS-07 | Workload inconsistency | Alerts per analyst-hour vs cases investigated, implied "impossible throughput" |

### Unknown-unknown layer

Isolation Forest/LOF on the entity-month feature vector, with cohort normalisation. Each anomaly is decomposed into its top contributing features and translated into plain-language reasons. Anything the ML flags but no rule explains goes to a "novel pattern" lane so examiners can label it and feed it back.

---

## 6. Scoring and prioritisation (the part judges remember)

1. **Detector score** = severity weight x deviation strength x data-confidence.
2. **Entity Supervisory Risk Index (0-100)** = weighted blend per the 8 capability areas, shown as a radar plus peer-percentile, with a trend arrow.
3. **Review Queue Builder:** given the examiner's budget (e.g. "I can review 40 cases for Entity X"), pick samples using **risk-weighted stratified sampling**: top-risk cases plus a random control slice (10-20%) to stay unbiased and calibrate detectors.
4. **Confidence labels:** High / Medium / Low depending on data completeness, so missing data is itself a finding and not silently hidden.
5. **Anti-gaming:** randomised control sample and rotating thresholds, so an entity cannot tune behaviour to the tool.

---

## 7. Explainability and auditability

Each flag opens a **Finding Card**:

- Plain-language reason ("34 of 36 critical alerts closed in under 4 min, peer median 47 min, p1").
- Evidence table (click-through to the underlying alert/case rows).
- Peer comparison chart and time trend.
- Detector ID, version, parameters, input data hash.
- Examiner action: Confirm / Dismiss / Needs more data (feeds validation and re-ranking).

Audit trail: every run writes a **signed manifest** (data file hashes, code version, config, model hash, output hash) into a hash-chained log. Any finding can be re-generated bit-for-bit.

---

## 8. Validation methodology (mandatory section)

1. **Synthetic benchmark with seeded ground truth.** Generator builds multi-entity SOC data (normal behaviour from realistic distributions) and injects known execution gaps and negative-space cases at varied intensity. Produces labelled truth.
2. **Expert-label replay.** Provide a labelling UI and protocol: NCIIPC examiners label a sample; compare with tool ranking.
3. **Metrics:** Precision@k, Recall@k of confirmed weaknesses within a fixed review budget, lift vs random sampling and vs the current "sample N% per entity" approach, entity-ranking correlation (Spearman/Kendall) with expert ranking, false-positive burden (examiner minutes wasted).
4. **Ablation:** rules only, stats only, ML only, full ensemble, to justify each layer.
5. **Robustness:** noisy and missing fields, varying CSE sizes, adversarial gaming test (entity adjusts closure timing; does detection hold?).
6. **Reproducibility:** fixed seeds, published benchmark scripts, results table in README.

Target statement for slides: "At a 10% review budget, SAT-SA surfaces X% of seeded weaknesses vs Y% for random sampling" (fill with your real measured numbers; never present invented ones).

---

## 9. End-to-end workflow

```
CSE periodic export -> validate/quarantine -> load to canonical store
 -> compute features -> run detectors + peer baselines -> score
 -> Supervisor dashboard: entity ranking -> entity profile -> finding cards
 -> generate review queue within budget -> examiner reviews & labels
 -> labels feed calibration/re-ranking -> signed report + audit manifest
```

Supervisor journey (use as demo script): *Portfolio view -> pick top-risk entity -> radar shows weak escalation + coverage gaps -> open a finding -> drill to evidence -> add to review queue -> export report.*

---

## 10. Non-functional and deployment

- **Scale:** columnar processing; target 10M+ alerts across 50+ entities on a single 8-core/32 GB box, full run in minutes (benchmark and report it).
- **Hardware:** CPU-only server or workstation; 500 GB SSD; optional second node for UI.
- **Security:** role-based access (admin, supervisor, auditor), local auth, encrypted data at rest (LUKS/SQLCipher), pseudonymised analyst IDs, no outbound network (firewall rule + startup check proves it).
- **Updates:** signed offline bundles via removable media; versioned detector packs and model files.
- **Ops estimate:** 1 admin part-time, quarterly detector review with examiners.

---

## 11. Deliverables checklist (stay strictly inside these)

| Deliverable | Content that wins |
| --- | --- |
| **Source code link** | Clean repo: `ingest/ detectors/ scoring/ explain/ api/ ui/ synth/ tests/ docs/`; CI tests; pinned deps; sample data |
| **README + setup** | 3-command install (online and air-gapped), sample dataset, screenshots, benchmark table, folder map, offline proof |
| **Architecture doc (max 2 pages)** | Page 1: diagram, data flow, tool stack, AI/ML disclosure. Page 2: detector catalogue summary, scoring, explainability/audit, validation, deployment and infra |
| **Demo video (max 2 min)** | 0:00 problem (10s) -> 0:10 ingest multi-CSE data -> 0:30 portfolio risk ranking -> 0:55 finding card + evidence drill-down -> 1:20 negative-space catch -> 1:35 review queue + validation lift -> 1:50 air-gapped close |
| **Presentation (max 5 slides)** | S1 Problem + insight (claims vs evidence). S2 Architecture (offline). S3 Detectors: execution gap + negative space + novelty. S4 Explainability, audit, human-in-loop. S5 Validation results + deployment + impact |

Also map in the README the PS sections: functional requirements 1-17, deployment (offline), the 8 deliverables, validation and success criterion, so judges can tick boxes quickly.

---

## 12. Innovation extras (the "Additional Supervisory Insights" weight)

- **Claim-vs-Reality Index:** compare an entity's self-reported KPIs (MTTR, closure %) with evidence-derived measures.
- **Goodhart detector:** metric-satisfying but risk-neutral behaviour (SLA-edge closures).
- **Coverage heatmap** of critical assets vs telemetry (instant negative-space visual).
- **Peer cohorting** by sector/size/SOC model so comparisons are fair.
- **Examiner feedback loop** that adapts weights while keeping every change versioned.
- **Analyst workload plausibility check** (impossible throughput).
- **Supervisory early-warning trend:** entity deterioration over quarters.

---

## 13. Pitfalls to avoid

1. Drifting into "real-time threat detection": it is out of scope.
2. Calling anything "malicious"; say "requires supervisory attention".
3. Black-box deep learning with no reasons; offline GPU dependence.
4. Quoting accuracy numbers from toy data without describing the benchmark honestly.
5. Over-long docs: respect the 2-page, 2-minute and 5-slide limits.
6. Ignoring missing-data confidence: absence must be reported as absence, not as "clean".

## 14. Suggested build plan

| Phase | Output |
| --- | --- |
| Days 1-2 | Schema, synthetic generator with ground truth |
| Days 3-5 | Ingest + store + features + 8 execution-gap detectors |
| Days 6-7 | Negative-space detectors + peer baseline engine |
| Days 8-9 | Scoring, review-queue builder, explainability and audit chain |
| Days 10-11 | Dashboard, drill-down, report export |
| Day 12 | Validation runs, benchmark table, air-gap packaging |
| Days 13-14 | README, 2-page doc, 5 slides, 2-min demo, dry run |