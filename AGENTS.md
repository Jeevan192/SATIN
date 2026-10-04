# AGENTS.md - SAT-SA Supervisory Analytics Tool for SOC Assessment

## 1. Project in 5 Lines
SAT-SA is an offline supervisory analytics tool for the NCIIPC problem statement.
It reads periodic batch submissions (CSV/JSON) of SOC alerts and case-management data across Critical Sector Entities (CSEs) to compare them against peer cohorts.
Core concept 1: EXECUTION_GAP - records exist but contradict claimed effectiveness (fast closure of critical alerts, template investigations, SLA-boundary dumping).
Core concept 2: NEGATIVE_SPACE - expected telemetry/evidence is missing (silent critical assets, missing threat categories, suppressed volume).
Out of scope: real-time monitoring, telemetry/log ingestion, SIEM features, central SOC, national monitoring platform, cloud/SaaS/external API/hosted model dependencies, and runtime internet access.

## 2. Hard Rules
- **Allowed existing paths to read/edit:**
  `analytics/execution_gaps.py`, `analytics/negative_space.py`, `analytics/supervisory_engine.py`, `backend/app.py`, `dashboard/app.py`, `data/sample_alerts.csv`, `data/asset_inventory.csv`, `requirements.txt`, `.gitignore`, `.dockerignore`
- **Allowed directories to create files in:**
  `satsa/`, `synth/`, `validation/`, `tests/`, `docs/`, `scripts/`, `data/synthetic/`, `data/output/`, plus root `README.md` and root `AGENTS.md`.
- **Must NOT open, read, list recursively, grep, index, or summarise:**
  `__pycache__/`, `*.pyc`, `.git/`, `venv/`, `.venv/`, `node_modules/`, `data/sbom/`, `data/vulnerabilities/`, `security-assurance/`, `soc-evidence/`, `compose.yaml`, `CONTAINERS.md`, `.env`, `.env.example`, or any file in `data/output/` > 100 lines (use head -20 or python summary).
- **Command rules:** Never run `find /`, `ls -R` from repo root, `grep -r` over repo root, or `tree` without allow-list path. Non-recursive `ls <allowed-dir>` only. No web browsing, no external APIs, no docker, no unauthorized pip packages. Targeted ranges only for files > ~200 lines.
- **Tech-stack limits:** Offline, minimal, Python 3.11+. Allowed packages: `pandas`, `numpy`, `scipy`, `scikit-learn`, `ruptures`, `datasketch`, `pydantic`, `fastapi`, `uvicorn`, `streamlit`, `plotly`, `jinja2`, `pytest`, `pyarrow`. Absolutely no network, no cloud.

## 3. Current Status
| Phase | Description | Status | Date | Verifying Command |
|---|---|---|---|---|
| Phase 0 | Cleanup & Repo Hygiene | DONE | 2026-10-04 | `git status --ignored; ls` |
| Phase 1 | Canonical Schema + Ingest | DONE | 2026-10-04 | `python -m pytest tests/test_ingest.py -v` (4 passed) |
| Phase 2 | Synthetic Generator | DONE | 2026-10-04 | `python -m pytest tests/test_synth.py -v` (3 passed) |
| Phase 3 | Features + Peers | DONE | 2026-10-04 | `python -m pytest tests/test_peers.py -v` (5 passed) |
| Phase 4 | Detectors (EG, NS, NOV) | DONE | 2026-10-04 | `python -m pytest tests/test_detectors.py -v` (8 passed) |
| Phase 5 | Scoring + Review Queue | DONE | 2026-10-04 | `python -m pytest tests/test_scoring_queue.py -v` (4 passed) |
| Phase 6 | Audit + Explainability | DONE | 2026-10-04 | `python -m pytest tests/test_audit.py -v; python satsa/audit.py --verify` (3 passed) |
| Phase 7 | Validation Engine | DONE | 2026-10-04 | `python validation/run_validation.py --seed 42` |
| Phase 8 | API + Dashboard | TODO | - | - |
| Phase 9 | Tests + Documentation | TODO | - | - |

## 4. Architecture Snapshot
- `satsa/config.py`: Thresholds, capability area weights, paths (single source of truth).
- `satsa/schemas.py`: Pydantic validation schemas for the 6 input tables.
- `satsa/ingest.py`: CSV/JSON loader, schema validation, quarantine router, legacy adapter.
- `satsa/features.py`: Per-alert, per-case, per-asset, per-entity-month feature engineering.
- `satsa/peers.py`: Peer cohort partitioning and robust statistics (median/MAD, empirical percentiles).
- `satsa/detectors/`: Modular detectors returning structured `Finding` objects (EG-01..08, NS-01..06, NOV-01).
- `satsa/scoring.py`: Severity-weighted deviation scoring and 8-capability area Entity Risk Index.
- `satsa/queue.py`: Examiner manual review queue builder (85% risk diversified + 15% random control).
- `satsa/audit.py`: SHA-256 hash-chained immutable run log and signed run manifest.
- `satsa/pipeline.py`: End-to-end execution pipeline from raw input to audited findings.
- `synth/generate.py`: Deterministic multi-CSE synthetic data generator with ground truth injections.
- `validation/run_validation.py`: Ground truth benchmark (precision/recall@k, lift, ablation, correlation).
- `backend/app.py`: Offline FastAPI service serving output findings and queue.
- `dashboard/app.py`: Streamlit supervisory review interface with drill-downs and audit tools.

## 5. Detector Registry
| Detector ID | Concept | Description | Status | Tested | Recall |
|---|---|---|---|---|---|
| EG-01 | EXECUTION_GAP | Critical/High alert closure speed anomaly (cohort p5 / z < -2.5) | DONE | Y | Active |
| EG-02 | EXECUTION_GAP | Critical/High closure without escalation vs cohort expectation | DONE | Y | Active |
| EG-03 | EXECUTION_GAP | Acknowledged alerts with zero workflow investigation events | DONE | Y | Active |
| EG-04 | EXECUTION_GAP | Template-driven investigation notes (MinHash/TF-IDF) & entropy | DONE | Y | Active |
| EG-05 | EXECUTION_GAP | Repeat alerts on same asset+rule without remediation | DONE | Y | Active |
| EG-06 | EXECUTION_GAP | Closure bunching at SLA boundaries or shift/month ends | DONE | Y | Active |
| EG-07 | EXECUTION_GAP | Analyst closure concentration (Gini / top-1 share vs cohort) | DONE | Y | Active |
| EG-08 | EXECUTION_GAP | Disposition skew drift (CUSUM on false-positive rate) | DONE | Y | Active |
| NS-01 | NEGATIVE_SPACE | Monitored critical assets with zero alerts/events in period | DONE | Y | Active |
| NS-02 | NEGATIVE_SPACE | Expected alert categories absent/suppressed (Poisson test) | DONE | Y | Active |
| NS-03 | NEGATIVE_SPACE | Alerts without cases / cases without mandatory escalations | DONE | Y | Active |
| NS-04 | NEGATIVE_SPACE | Total alert volume below size-adjusted peer expectation | DONE | Y | Active |
| NS-05 | NEGATIVE_SPACE | Silent operational periods (volume gap / change-point detection) | DONE | Y | Active |
| NS-06 | NEGATIVE_SPACE | Criticality-weighted monitoring coverage ratio vs peers | DONE | Y | Active |
| NOV-01 | NOVEL | IsolationForest + LOF on cohort-normalized entity-month features | DONE | Y | Active |

## 6. Validation Results
*Measured from execution of `validation/run_validation.py` (Run date: 2026-10-04, Seed: 42, Dataset: 12 entities, 39,211 alerts):*

| Review Budget | Items Examined | True Positives | Precision@k | Recall@k | Lift vs Random (200 trials) | Lift vs Uniform 5% |
|---|---|---|---|---|---|---|
| 5% Budget | 1,246 | 346 | **27.8%** | **7.3%** | **2.12x** | **1.54x** |
| 10% Budget | 2,495 | 666 | **26.7%** | **14.0%** | **2.28x** | **1.54x** |
| 20% Budget | 4,990 | 1,315 | **26.4%** | **27.7%** | **1.90x** | **1.50x** |

- **Spearman Rank Correlation (rho):** `0.3601` (p-value: `0.25`)
- **Ablation Study (at 10% budget):**
  - Rules Only: 685 findings, Precision: 10.3%, Recall: 5.4%
  - Stats Only: 1,718 findings, Precision: 26.5%, Recall: 13.9%
  - ML Only: 13 findings, Precision: 6.7%, Recall: 3.5%
  - Full SAT-SA Ensemble: 2,416 findings, Precision: 26.7%, Recall: 14.0%

## 7. Decisions Log
- 2026-10-04: Baseline committed to git; initiated Phase 0 cleanup.
- 2026-10-04: Removed containerization, live SIEM evidence, and vulnerability scanning artifacts to strictly enforce offline supervisory scope.
- 2026-10-04: Implemented canonical schemas with Pydantic and vectorized quarantine router in `satsa/ingest.py`; added legacy adapter for backward compatibility with `sample_alerts.csv` and `asset_inventory.csv`.
- 2026-10-04: Implemented deterministic multi-CSE synthetic generator (`synth/generate.py`) generating 12 entities (4 clean controls, 8 with subtle/strong fault injections across all EG-01..08 and NS-01..06) + `ground_truth.csv`.
- 2026-10-04: Implemented `satsa/features.py` (granular alert/case/asset/entity/monthly metrics) and `satsa/peers.py` (hierarchical cohort fallback manager, MAD-guarded robust Z, Poisson expected-count models, empirical percentiles).
- 2026-10-04: Implemented all 15 detectors in `satsa/detectors/` (EG-01..08, NS-01..06, NOV-01) returning structured `Finding` objects with peer deviations, percentiles, confidence, evidence references, and thresholds in `satsa/config.py`.
- 2026-10-04: Implemented `satsa/scoring.py` (severity-weighted deviation scoring, 8 capability area sub-scores, Entity Supervisory Risk Index 0-100, QoQ trend) and `satsa/queue.py` (budgeted 85% risk diversified + 15% random control queue with explainable selection reasons).
- 2026-10-04: Implemented `satsa/audit.py` (SHA-256 hash-chained immutable audit log with tamper detection and cryptographically sealed `run_manifest.json`) and `satsa/pipeline.py` (end-to-end supervisory pipeline from raw input to audited outputs).
- 2026-10-04: Implemented `validation/run_validation.py` and measured ground-truth benchmark metrics: 2.28x lift vs random sampling at 10% budget, 27.8% precision@5%, and detector ablation comparison.

## 8. Known Issues / Risks
- Existing legacy `analytics/` and `dashboard/app.py` use hardcoded heuristic rules that must be replaced by peer-relative detectors.
- Offline requirement demands strict airgap installation support (wheelhouse scripts).

## 9. Backlog to Reach SIH 2026 Winner Level
### NEXT UP
1. [ ] Phase 8: API + Dashboard (`backend/app.py`, `dashboard/app.py`).
2. [ ] Phase 9: Tests + Documentation (`README.md`, `docs/ARCHITECTURE.md`).

### Full Backlog
- [ ] Offline-only proof: startup check that fails if any outbound network call is attempted; documented in README
- [x] Peer-based (not hard-coded) thresholds in every detector
- [x] At least 12 detectors implemented with unit tests, plus the novelty lane
- [x] Subtle fault cases in synthetic data (not only obvious ones) and 3+ clean control entities
- [x] Review-queue builder with budget, diversification and random control slice
- [ ] Finding card with reason, evidence drill-down, peer chart, detector version/parameters
- [x] Hash-chained audit log with tamper test
- [x] Validation report: precision@k / recall@k, lift vs random and vs uniform sampling, ablation, all measured
- [ ] Scale test at 1M and 10M rows with measured runtime and memory
- [ ] Anti-gaming robustness test (entity adapts behaviour; does detection hold?)
- [ ] Claim-vs-reality index (self-reported KPIs vs evidence-derived metrics)
- [ ] Coverage heatmap and trend/early-warning view
- [ ] Missing-data confidence labels shown in the UI
- [ ] Examiner feedback loop (confirm/dismiss) that re-weights ranking with versioned changes
- [ ] README PS-requirement mapping table (requirements 1-17, deployment, deliverables, validation)
- [ ] Clean repo hygiene: no caches/binaries committed, pytest green, requirements minimal

## 10. Deliverables Checklist
- [ ] GitHub repo ready & clean
- [ ] README.md with complete setup and PS mapping
- [ ] docs/ARCHITECTURE.md (strictly <= 2 pages)
- [ ] Demo video script outline (max 2 min) in docs/
- [ ] 5-slide presentation outline in docs/

## Gap Analysis (Phase 7)
- **Weakest judging criteria:** User interface and supervisory examiner workflows: the web API and Streamlit examiner dashboard need to present finding drill-downs, peer cohort charts, and review queues.
- **Single highest-value next improvement:** Implement Phase 8: modern offline FastAPI backend (`backend/app.py`) and Streamlit supervisory review interface (`dashboard/app.py`) with portfolio radar charts, finding cards, and audit tools.
- **Scope drift check:** Zero network access; validation benchmark executed 100% offline with local Monte Carlo trials and pure mathematical statistics.
