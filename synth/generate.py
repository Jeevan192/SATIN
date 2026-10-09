"""Synthetic multi-CSE dataset generator for SAT-SA.

Generates realistic, deterministic SOC data across multiple Critical Sector Entities (CSEs),
injecting both subtle and strong EXECUTION_GAP and NEGATIVE_SPACE faults.
Outputs canonical CSV tables and a ground_truth.csv benchmark key.
"""

import argparse
from datetime import datetime, timedelta
import logging
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from satsa.config import PATHS


logger = logging.getLogger(__name__)


ENTITIES_CONFIG = [
    # Banking Cohort
    {"entity_id": "CSE-BANK-01", "sector": "banking", "size_band": "Tier-1", "soc_model": "in-house", "faults": [], "role": "clean_control"},
    {"entity_id": "CSE-BANK-02", "sector": "banking", "size_band": "Tier-1", "soc_model": "in-house", "faults": ["EG-01_strong", "EG-02_strong"], "role": "faulty"},
    {"entity_id": "CSE-BANK-03", "sector": "banking", "size_band": "Tier-2", "soc_model": "hybrid", "faults": ["EG-04_subtle", "EG-07_subtle"], "role": "faulty"},
    {"entity_id": "CSE-BANK-04", "sector": "banking", "size_band": "Tier-3", "soc_model": "outsourced", "faults": ["NS-04_strong", "EG-06_strong"], "role": "faulty"},

    # Energy Cohort
    {"entity_id": "CSE-ENGY-01", "sector": "energy", "size_band": "Tier-1", "soc_model": "in-house", "faults": [], "role": "clean_control"},
    {"entity_id": "CSE-ENGY-02", "sector": "energy", "size_band": "Tier-1", "soc_model": "in-house", "faults": ["NS-01_strong", "NS-06_strong"], "role": "faulty"},
    {"entity_id": "CSE-ENGY-03", "sector": "energy", "size_band": "Tier-2", "soc_model": "hybrid", "faults": ["EG-03_subtle", "EG-05_subtle"], "role": "faulty"},
    {"entity_id": "CSE-ENGY-04", "sector": "energy", "size_band": "Tier-3", "soc_model": "outsourced", "faults": ["NS-05_strong", "EG-08_strong"], "role": "faulty"},

    # Telecom Cohort
    {"entity_id": "CSE-TELC-01", "sector": "telecom", "size_band": "Tier-1", "soc_model": "in-house", "faults": [], "role": "clean_control"},
    {"entity_id": "CSE-TELC-02", "sector": "telecom", "size_band": "Tier-1", "soc_model": "in-house", "faults": ["NS-02_strong", "NS-03_strong"], "role": "faulty"},
    {"entity_id": "CSE-TELC-03", "sector": "telecom", "size_band": "Tier-2", "soc_model": "hybrid", "faults": ["EG-01_subtle", "EG-04_subtle"], "role": "faulty"},
    {"entity_id": "CSE-TELC-04", "sector": "telecom", "size_band": "Tier-3", "soc_model": "outsourced", "faults": [], "role": "clean_control"},
]

SECTOR_CATEGORIES = {
    "banking": ["Authentication Anomaly", "Data Exfiltration", "Privilege Escalation", "Malware Detection", "Phishing", "Suspicious API Transaction"],
    "energy": ["Authentication Anomaly", "Data Exfiltration", "Privilege Escalation", "Malware Detection", "SCADA Command Anomaly", "Protocol Violation"],
    "telecom": ["Authentication Anomaly", "Data Exfiltration", "Privilege Escalation", "Malware Detection", "DDoS Flood", "BGP Route Anomaly"],
}

TEMPLATE_NOTES = [
    "Automated triage complete. Host verified compliant. No malicious action identified. Closing case as standard benign.",
    "Automated triage complete. Host verified compliant. No malicious activity identified. Closing case as standard benign.",
    "Automated triage complete. Host verified compliant. No malicious behavior identified. Closing case as standard benign.",
]

NORMAL_NOTES = [
    "Investigated anomalous outbound connection on asset. Correlated with authorized backup maintenance window. False positive.",
    "User reported suspicious MFA prompt. Confirmed legitimate VPN login from authorized branch IP. Resolved.",
    "Detected unauthorized port scan from staging subnet. Firewall rule updated and source IP quarantined for 24h.",
    "High volume database query reviewed with DBA on duty. Approved data migration script. Ticket closed.",
    "Endpoint detection flagged test script in developer workspace. Signed binary verified against repository hash.",
    "Multiple failed password attempts followed by lock. User contacted IT helpdesk for password reset.",
    "Unusual PowerShell execution detected. Process tree verified as scheduled administrative maintenance job.",
]


def _attach_kpi_claims(
    entities_df: pd.DataFrame,
    alerts_df: pd.DataFrame,
    cases_df: pd.DataFrame,
    esc_df: pd.DataFrame,
    assets_df: pd.DataFrame,
    seed: int,
) -> pd.DataFrame:
    """Attach self-reported KPI claims to entities (Claim-vs-Reality inputs).

    Evidence metrics mirror ``satsa.claim_reality`` exactly:

    * ``claimed_mttc_min``       -- median (closed - ack) minutes over critical/high alerts
    * ``claimed_coverage_pct``   -- monitored critical assets with >=1 alert (%)
    * ``claimed_fp_rate_pct``    -- false-positive disposition share of all alerts (%)
    * ``claimed_escalation_pct`` -- escalated share of critical/high alerts (%)

    Clean-control CSEs report honestly (small jitter); faulty CSEs inflate
    their claims so the Claim-vs-Reality Index exposes them. Claims are drawn
    from a dedicated RNG so the main generation stream (and therefore the
    committed dataset) stays bit-identical regardless of this injection.
    """
    role_by_eid = {e["entity_id"]: e.get("role", "faulty") for e in ENTITIES_CONFIG}
    claim_rng = np.random.default_rng(seed + 991)

    a = alerts_df
    ack = pd.to_datetime(a["ack_ts"], errors="coerce")
    closed = pd.to_datetime(a["closed_ts"], errors="coerce")
    close_min = ((closed - ack).dt.total_seconds().clip(lower=0)) / 60.0
    ch_mask = a["severity"].isin(["critical", "high"])

    # An alert is escalated iff its case appears in the escalations table.
    esc_case_ids = set(esc_df["case_id"].dropna()) if not esc_df.empty else set()
    escalated_alerts = (
        set(cases_df.loc[cases_df["case_id"].isin(esc_case_ids), "alert_id"])
        if not cases_df.empty and not esc_df.empty
        else set()
    )
    escalated = a["alert_id"].isin(escalated_alerts)

    monitored_crit = assets_df[
        (assets_df["criticality"] == "critical") & (assets_df["monitoring_expected"])
    ]
    alerted_assets = set(a["asset_id"].dropna())

    claims: Dict[str, Dict[str, Optional[float]]] = {}
    for eid in entities_df["entity_id"]:
        mask = a["entity_id"] == eid
        ch = mask & ch_mask
        honest = role_by_eid.get(eid, "faulty") == "clean_control"

        # ---- Evidence-side metrics (identical to satsa.claim_reality) ----
        mttc_ev = float(close_min[ch].median()) if ch.any() else None
        mc = monitored_crit[monitored_crit["entity_id"] == eid]
        cov_ev = (
            100.0 * sum(1 for aid in mc["asset_id"] if aid in alerted_assets) / len(mc)
            if len(mc) > 0
            else None
        )
        n_ent = int(mask.sum())
        fp_ev = 100.0 * float((a.loc[mask, "disposition"] == "false_positive").mean()) if n_ent else None
        esc_ev = 100.0 * float(escalated[ch].mean()) if ch.any() else None

        # ---- Claim bias: honest jitter vs flattering inflation ----
        if honest:
            mttc = mttc_ev * claim_rng.uniform(0.97, 1.08) if mttc_ev is not None else None
            cov = min(100.0, cov_ev * claim_rng.uniform(0.97, 1.03)) if cov_ev is not None else None
            fp = fp_ev * claim_rng.uniform(0.9, 1.08) if fp_ev is not None else None
            esc = min(100.0, esc_ev * claim_rng.uniform(0.95, 1.03)) if esc_ev is not None else None
        else:
            mttc = mttc_ev * claim_rng.uniform(0.35, 0.65) if mttc_ev is not None else None
            cov = min(100.0, cov_ev + claim_rng.uniform(15.0, 30.0)) if cov_ev is not None else None
            fp = fp_ev * claim_rng.uniform(0.25, 0.55) if fp_ev is not None else None
            esc = min(100.0, esc_ev + claim_rng.uniform(15.0, 30.0)) if esc_ev is not None else None

        claims[eid] = {
            "claimed_mttc_min": round(mttc, 1) if mttc is not None else None,
            "claimed_coverage_pct": round(cov, 1) if cov is not None else None,
            "claimed_fp_rate_pct": round(fp, 1) if fp is not None else None,
            "claimed_escalation_pct": round(esc, 1) if esc is not None else None,
        }

    out = entities_df.copy()
    for col in ("claimed_mttc_min", "claimed_coverage_pct", "claimed_fp_rate_pct", "claimed_escalation_pct"):
        out[col] = out["entity_id"].map(lambda e, c=col: claims.get(e, {}).get(c))
    return out


def generate_synthetic_dataset(
    seed: int = 42,
    scale: float = 1.0,
    out_dir: Path = PATHS.synthetic_dir,
    start_date: datetime = datetime(2026, 3, 1, 0, 0, 0),
    days: int = 180,
) -> Tuple[Dict[str, pd.DataFrame], pd.DataFrame]:
    """Generate deterministic synthetic multi-CSE SOC dataset and ground truth table."""
    rng = np.random.default_rng(seed)
    out_dir.mkdir(parents=True, exist_ok=True)

    entities_df = pd.DataFrame([
        {k: v for k, v in ent.items() if k not in ("faults", "role")}
        for ent in ENTITIES_CONFIG
    ])

    ground_truth_records: List[Dict[str, Any]] = []
    assets_records: List[Dict[str, Any]] = []
    alerts_records: List[Dict[str, Any]] = []
    cases_records: List[Dict[str, Any]] = []
    workflow_records: List[Dict[str, Any]] = []
    escalation_records: List[Dict[str, Any]] = []

    # 1. Generate Assets per Entity
    entity_assets_map: Dict[str, List[Dict[str, Any]]] = {}
    for ent in ENTITIES_CONFIG:
        eid = ent["entity_id"]
        size = ent["size_band"]
        if size == "Tier-1":
            n_assets = int(rng.integers(150, 200) * max(0.5, min(scale, 2.0)))
        elif size == "Tier-2":
            n_assets = int(rng.integers(80, 120) * max(0.5, min(scale, 2.0)))
        else:
            n_assets = int(rng.integers(40, 60) * max(0.5, min(scale, 2.0)))

        ent_assets = []
        for a_idx in range(1, n_assets + 1):
            aid = f"{eid}-AST-{a_idx:04d}"
            # Criticality mix: 15% critical, 25% high, 40% medium, 20% low
            crit_val = rng.random()
            if crit_val < 0.15:
                crit = "critical"
            elif crit_val < 0.40:
                crit = "high"
            elif crit_val < 0.80:
                crit = "medium"
            else:
                crit = "low"

            atype = rng.choice(["database_server", "domain_controller", "app_server", "scada_controller", "firewall", "workstation"])
            monitored = True

            # Injection NS-06: Monitoring coverage deficit (CSE-ENGY-02 unmonitored assets)
            if "NS-06_strong" in ent["faults"] and crit in ("critical", "high") and rng.random() < 0.45:
                monitored = False

            rec = {
                "asset_id": aid,
                "entity_id": eid,
                "criticality": crit,
                "asset_type": atype,
                "monitoring_expected": monitored,
            }
            ent_assets.append(rec)
            assets_records.append(rec)

        entity_assets_map[eid] = ent_assets

    assets_df = pd.DataFrame(assets_records)

    # 2. Generate Alerts, Cases, Workflows, Escalations per Entity
    global_alert_counter = 1
    global_case_counter = 1

    for ent in ENTITIES_CONFIG:
        eid = ent["entity_id"]
        sector = ent["sector"]
        size = ent["size_band"]
        faults = ent["faults"]
        ent_assets = entity_assets_map[eid]

        # Base volume scaled
        if size == "Tier-1":
            base_vol = int(rng.integers(3800, 4800) * scale)
        elif size == "Tier-2":
            base_vol = int(rng.integers(2600, 3400) * scale)
        else:
            base_vol = int(rng.integers(1800, 2400) * scale)

        # Injection NS-04: Total volume suppressed (60-80% below peer expectation)
        if "NS-04_strong" in faults:
            orig_vol = base_vol
            base_vol = int(base_vol * 0.20)
            ground_truth_records.append({
                "entity_id": eid,
                "fault_type": "SUPPRESSED_ALERT_VOLUME",
                "detector_expected": "NS-04",
                "scope": f"entity:{eid}",
                "intensity": "strong",
            })

        # Asset selection setup
        all_asset_ids = [a["asset_id"] for a in ent_assets]
        crit_asset_ids = [a["asset_id"] for a in ent_assets if a["criticality"] == "critical"]
        other_asset_ids = [a["asset_id"] for a in ent_assets if a["criticality"] != "critical"]

        # Injection NS-01: Critical assets silent (reserve 4 critical assets that never alert)
        silent_crit_assets: List[str] = []
        active_crit_asset_ids = list(crit_asset_ids)
        if "NS-01_strong" in faults and len(crit_asset_ids) >= 4:
            silent_crit_assets = crit_asset_ids[:4]
            active_crit_asset_ids = crit_asset_ids[4:]
            for s_ast in silent_crit_assets:
                ground_truth_records.append({
                    "entity_id": eid,
                    "fault_type": "SILENT_CRITICAL_ASSET",
                    "detector_expected": "NS-01",
                    "scope": f"asset:{s_ast}",
                    "intensity": "strong",
                })

        # Active assets pool (must strictly exclude silent critical assets)
        active_asset_ids = [aid for aid in all_asset_ids if aid not in silent_crit_assets]

        # Injection NS-06 ground truth
        if "NS-06_strong" in faults:
            ground_truth_records.append({
                "entity_id": eid,
                "fault_type": "COVERAGE_RATIO_DEFICIT",
                "detector_expected": "NS-06",
                "scope": f"entity:{eid}",
                "intensity": "strong",
            })

        # Categories
        allowed_cats = list(SECTOR_CATEGORIES[sector])
        if "NS-02_strong" in faults:
            missing_cat = "Data Exfiltration"
            if missing_cat in allowed_cats:
                allowed_cats.remove(missing_cat)
                ground_truth_records.append({
                    "entity_id": eid,
                    "fault_type": "MISSING_ALERT_CATEGORY",
                    "detector_expected": "NS-02",
                    "scope": f"category:{missing_cat}",
                    "intensity": "strong",
                })

        # Analysts pool
        num_analysts = 6 if size == "Tier-1" else (4 if size == "Tier-2" else 3)
        analysts = [f"{eid}-ANL-{i:02d}" for i in range(1, num_analysts + 1)]
        analyst_star = analysts[0]

        # Injection NS-05 Setup: Silent period (7 days in month 4)
        silent_start = start_date + timedelta(days=100)
        silent_end = silent_start + timedelta(days=7)
        if "NS-05_strong" in faults:
            ground_truth_records.append({
                "entity_id": eid,
                "fault_type": "SILENT_OPERATIONAL_PERIOD",
                "detector_expected": "NS-05",
                "scope": f"period:{silent_start.strftime('%Y-%m-%d')}_to_{silent_end.strftime('%Y-%m-%d')}",
                "intensity": "strong",
            })

        # Generate timestamps across the window
        offsets_sec = rng.uniform(0, days * 86400, size=base_vol)
        offsets_sec.sort()

        # Repeat alert asset for EG-05
        eg05_asset = other_asset_ids[0] if other_asset_ids else all_asset_ids[0]
        eg05_alert_count = 0
        if "EG-05_subtle" in faults:
            ground_truth_records.append({
                "entity_id": eid,
                "fault_type": "REPEAT_ALERTS_NO_REMEDIATION",
                "detector_expected": "EG-05",
                "scope": f"asset:{eg05_asset}",
                "intensity": "subtle",
            })

        for i, off in enumerate(offsets_sec):
            alert_dt = start_date + timedelta(seconds=float(off))

            # Skip generation if inside silent period for NS-05
            if "NS-05_strong" in faults and silent_start <= alert_dt <= silent_end:
                continue

            alert_id = f"ALT-{eid}-{global_alert_counter:07d}"
            global_alert_counter += 1

            # Category
            cat = str(rng.choice(allowed_cats))

            # Severity
            s_val = rng.random()
            if s_val < 0.08:
                sev = "critical"
            elif s_val < 0.28:
                sev = "high"
            elif s_val < 0.65:
                sev = "medium"
            else:
                sev = "low"

            # Asset assignment
            if "EG-05_subtle" in faults and i % 15 == 0 and eg05_alert_count < 25:
                ast_id = eg05_asset
                cat = "Authentication Anomaly"
                eg05_alert_count += 1
            elif sev == "critical":
                ast_id = str(rng.choice(active_crit_asset_ids if active_crit_asset_ids else active_asset_ids))
            else:
                ast_id = str(rng.choice(active_asset_ids if active_asset_ids else all_asset_ids))

            # Ack latency (median 5 mins)
            ack_sec = max(30.0, float(rng.lognormal(mean=5.5, sigma=0.6)))
            ack_dt = alert_dt + timedelta(seconds=ack_sec)

            # Healthy closure duration per severity
            if sev == "critical":
                close_sec = float(rng.lognormal(mean=9.2, sigma=0.4))  # ~2.5 hours
            elif sev == "high":
                close_sec = float(rng.lognormal(mean=8.5, sigma=0.5))  # ~1.4 hours
            elif sev == "medium":
                close_sec = float(rng.lognormal(mean=7.5, sigma=0.6))  # ~30 mins
            else:
                close_sec = float(rng.lognormal(mean=6.8, sigma=0.6))  # ~15 mins

            # Injected Fault: EG-01 Fast closure of critical/high alerts
            is_eg01_injected = False
            if "EG-01_strong" in faults and sev in ("critical", "high") and rng.random() < 0.85:
                close_sec = float(rng.uniform(45.0, 180.0))  # 45s - 3 min!
                is_eg01_injected = True
            elif "EG-01_subtle" in faults and sev in ("critical", "high") and rng.random() < 0.50:
                close_sec = float(rng.uniform(300.0, 720.0))  # 5 min - 12 min
                is_eg01_injected = True

            if is_eg01_injected:
                ground_truth_records.append({
                    "entity_id": eid,
                    "fault_type": "FAST_CRITICAL_CLOSURE",
                    "detector_expected": "EG-01",
                    "scope": f"alert:{alert_id}",
                    "intensity": "strong" if "EG-01_strong" in faults else "subtle",
                })

            # Injected Fault: EG-06 SLA boundary bunching (closures clustered right at 58-59 mins)
            if "EG-06_strong" in faults and rng.random() < 0.40:
                close_sec = float(rng.uniform(3480.0, 3595.0))  # 58-60 mins (1-hour SLA)
                if i % 10 == 0:
                    ground_truth_records.append({
                        "entity_id": eid,
                        "fault_type": "SLA_BOUNDARY_BUNCHING",
                        "detector_expected": "EG-06",
                        "scope": f"alert:{alert_id}",
                        "intensity": "strong",
                    })

            closed_dt = ack_dt + timedelta(seconds=close_sec)

            # Disposition calculation
            # Injected Fault: EG-08 Disposition skew drift in month 4-6
            fp_prob = 0.40
            if "EG-08_strong" in faults and alert_dt >= start_date + timedelta(days=90):
                # Drift steadily to 0.85
                progress = min(1.0, (alert_dt - (start_date + timedelta(days=90))).days / 90.0)
                fp_prob = 0.40 + (0.48 * progress)

            disp = "false_positive" if rng.random() < fp_prob else "true_positive"

            alerts_records.append({
                "alert_id": alert_id,
                "entity_id": eid,
                "asset_id": ast_id,
                "category": cat,
                "severity": sev,
                "created_ts": alert_dt.isoformat(),
                "ack_ts": ack_dt.isoformat(),
                "closed_ts": closed_dt.isoformat(),
                "disposition": disp,
            })

            # Injected Fault: NS-03 Alerts without case
            skip_case = False
            if "NS-03_strong" in faults and sev in ("critical", "high") and rng.random() < 0.35:
                skip_case = True
                ground_truth_records.append({
                    "entity_id": eid,
                    "fault_type": "ALERT_WITHOUT_CASE",
                    "detector_expected": "NS-03",
                    "scope": f"alert:{alert_id}",
                    "intensity": "strong",
                })

            if skip_case:
                continue

            # Case creation
            case_id = f"CAS-{eid}-{global_case_counter:07d}"
            global_case_counter += 1

            # Analyst assignment
            # Injected Fault: EG-07 Analyst concentration (analyst_star gets 80% of critical/high cases)
            if "EG-07_subtle" in faults and sev in ("critical", "high") and rng.random() < 0.78:
                assigned_analyst = analyst_star
                if i % 15 == 0:
                    ground_truth_records.append({
                        "entity_id": eid,
                        "fault_type": "ANALYST_CONCENTRATION",
                        "detector_expected": "EG-07",
                        "scope": f"case:{case_id}",
                        "intensity": "subtle",
                    })
            else:
                assigned_analyst = str(rng.choice(analysts))

            # Case notes & closure code
            # Injected Fault: EG-04 Template notes & low entropy
            if ("EG-04_subtle" in faults or "EG-04_strong" in faults) and rng.random() < 0.85:
                note = str(rng.choice(TEMPLATE_NOTES))
                code = "standard_triage_close"
                if i % 10 == 0:
                    ground_truth_records.append({
                        "entity_id": eid,
                        "fault_type": "TEMPLATE_INVESTIGATION",
                        "detector_expected": "EG-04",
                        "scope": f"case:{case_id}",
                        "intensity": "strong" if "EG-04_strong" in faults else "subtle",
                    })
            else:
                note = str(rng.choice(NORMAL_NOTES))
                code = "remediated" if disp == "true_positive" else "benign_fp"

            cases_records.append({
                "case_id": case_id,
                "alert_id": alert_id,
                "analyst_id": assigned_analyst,
                "opened_ts": ack_dt.isoformat(),
                "closed_ts": closed_dt.isoformat(),
                "status": "closed",
                "closure_code": code,
                "notes_text": note,
            })

            # Workflow Events
            # Injected Fault: EG-03 Acknowledged no work
            has_wf = True
            if "EG-03_subtle" in faults and rng.random() < 0.35:
                has_wf = False
                ground_truth_records.append({
                    "entity_id": eid,
                    "fault_type": "ACK_NO_WORK",
                    "detector_expected": "EG-03",
                    "scope": f"case:{case_id}",
                    "intensity": "subtle",
                })

            if has_wf:
                mid_ts = ack_dt + (closed_dt - ack_dt) * 0.4
                workflow_records.append({
                    "case_id": case_id,
                    "step": "triage_investigation",
                    "actor_role": "analyst",
                    "ts": mid_ts.isoformat(),
                })

            # Escalation logic: baseline probability rises with severity
            esc_prob = 0.70 if sev == "critical" else (0.40 if sev == "high" else (0.15 if sev == "medium" else 0.03))

            # Injected Fault: EG-02 Critical closed without escalation
            if "EG-02_strong" in faults and sev in ("critical", "high"):
                esc_prob = 0.02
                ground_truth_records.append({
                    "entity_id": eid,
                    "fault_type": "CRITICAL_WITHOUT_ESCALATION",
                    "detector_expected": "EG-02",
                    "scope": f"case:{case_id}",
                    "intensity": "strong",
                })

            if rng.random() < esc_prob:
                esc_ts = ack_dt + (closed_dt - ack_dt) * 0.6
                escalation_records.append({
                    "case_id": case_id,
                    "from_tier": "Tier-1",
                    "to_tier": "Tier-2",
                    "ts": esc_ts.isoformat(),
                    "outcome": "investigated_and_resolved",
                })

        # Ground truth entry for EG-08
        if "EG-08_strong" in faults:
            ground_truth_records.append({
                "entity_id": eid,
                "fault_type": "DISPOSITION_SKEW_DRIFT",
                "detector_expected": "EG-08",
                "scope": f"period:{start_date.strftime('%Y-%m-%d')}_to_{(start_date + timedelta(days=days)).strftime('%Y-%m-%d')}",
                "intensity": "strong",
            })

    alerts_df = pd.DataFrame(alerts_records)
    cases_df = pd.DataFrame(cases_records)
    wf_df = pd.DataFrame(workflow_records)
    esc_df = pd.DataFrame(escalation_records)
    ground_truth_df = pd.DataFrame(ground_truth_records)

    # Self-reported KPI claims (Claim-vs-Reality inputs); see helper docstring.
    entities_df = _attach_kpi_claims(entities_df, alerts_df, cases_df, esc_df, assets_df, seed)

    # Export to target output directory
    alerts_df.to_csv(out_dir / "alerts.csv", index=False)
    cases_df.to_csv(out_dir / "cases.csv", index=False)
    wf_df.to_csv(out_dir / "workflow_events.csv", index=False)
    esc_df.to_csv(out_dir / "escalations.csv", index=False)
    assets_df.to_csv(out_dir / "assets.csv", index=False)
    entities_df.to_csv(out_dir / "entities.csv", index=False)
    ground_truth_df.to_csv(out_dir / "ground_truth.csv", index=False)

    dataset_dict = {
        "alerts": alerts_df,
        "cases": cases_df,
        "workflow_events": wf_df,
        "escalations": esc_df,
        "assets": assets_df,
        "entities": entities_df,
    }
    return dataset_dict, ground_truth_df


def main():
    parser = argparse.ArgumentParser(description="Deterministic synthetic SOC dataset generator for SAT-SA.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility (default: 42)")
    parser.add_argument("--scale", type=float, default=1.0, help="Volume scale multiplier (1.0 = ~35k-45k rows, 0.1 = quick test, 10.0 = scale test)")
    parser.add_argument("--out-dir", type=str, default="data/synthetic", help="Output directory path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    out_p = Path(args.out_dir)
    logger.info("Generating synthetic dataset (seed=%s, scale=%s) into %s...", args.seed, args.scale, out_p)
    dataset, gt = generate_synthetic_dataset(seed=args.seed, scale=args.scale, out_dir=out_p)
    logger.info("Generation complete.")
    logger.info("Entities: %s | Assets: %s | Alerts: %s", len(dataset["entities"]), len(dataset["assets"]), len(dataset["alerts"]))
    logger.info("Cases: %s | Workflow Events: %s | Escalations: %s", len(dataset["cases"]), len(dataset["workflow_events"]), len(dataset["escalations"]))
    logger.info("Ground Truth: %s injection records saved to %s", len(gt), out_p / "ground_truth.csv")


if __name__ == "__main__":
    main()
