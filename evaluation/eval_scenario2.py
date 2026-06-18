"""
eval_scenario2.py
Evaluates the full LLM-assisted mitigation pipeline (Scenario 2).

Metrics:
    Detection:
        - detection_rate  (= Recall / TPR): triggered / total GT-attack flows
        - alert_count:    number of flows that triggered the pipeline
        - false_positives: triggered flows where YaTC label != ground_truth

    Processing Time (only triggered flows):
        - t_detect, t_generate, t_validate, t_deploy, t_total
        - mean, median, min, max, stdev per category and overall

    Rule Validity:
        - validity_rate:  valid rules / triggered flows
        - per category breakdown

Usage:
    python3 eval_scenario2.py \
        --log    /usr/ShieldGPT/output/online/pipeline_log.jsonl \
        --output /usr/ShieldGPT/output/eval_scenario2.json
"""

import os
import json
import argparse
import logging
import statistics
from collections import defaultdict
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

ATTACK_CATEGORIES = ["LDAP", "MSSQL", "NetBIOS", "Syn", "UDP"]


# ── Load log ──────────────────────────────────────────────────────────────────

def load_log(log_path: str) -> list[dict]:
    entries = []
    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logger.warning(f"Skipping malformed line: {e}")
    logger.info(f"Loaded {len(entries)} log entries from {log_path}")
    return entries


# ── Helper ────────────────────────────────────────────────────────────────────

def _get_ground_truth(e: dict) -> str:
    """
    Ground truth comes from pipeline.py --category argument,
    stored as 'ground_truth' in each log entry.
    Falls back to inferring from flow_key if not set.
    """
    gt = e.get("ground_truth")
    if gt:
        return gt
    # fallback: infer from flow_key e.g. "SYN_flow_001" → "Syn"
    flow_key = (e.get("flow_key") or "").lower()
    for cat in ATTACK_CATEGORIES:
        if cat.lower() in flow_key:
            return cat
    return "unknown"


def _stat(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    return {
        "n":      len(values),
        "mean":   round(statistics.mean(values),             3),
        "median": round(statistics.median(values),           3),
        "min":    round(min(values),                         3),
        "max":    round(max(values),                         3),
        "stdev":  round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
    }


# ── Detection ─────────────────────────────────────────────────────────────────

def eval_detection(entries: list[dict]) -> dict:
    """
    Per-category and overall:
      - total_flows:      all flows with this GT category
      - alert_count:      flows where triggered=True  (TP + FP)
      - true_positives:   triggered AND YaTC label matches GT
      - false_positives:  triggered AND YaTC label does NOT match GT
      - false_negatives:  not triggered (missed attacks)
      - detection_rate:   TP / total_flows  (= Recall)

    NOTE: In Scenario 2 only attack traffic is replayed, so
    classic FP (benign triggered) cannot occur. FP here means
    the pipeline triggered but YaTC classified the flow into
    the WRONG attack category (e.g. GT=Syn but YaTC says MSSQL).
    """
    by_gt = defaultdict(list)
    for e in entries:
        gt = _get_ground_truth(e)
        by_gt[gt].append(e)

    results = {}

    for cat in ATTACK_CATEGORIES:
        flows = by_gt.get(cat, [])
        if not flows:
            continue

        total = len(flows)

        # TP: triggered AND correct label
        tp = sum(
            1 for e in flows
            if e.get("triggered", False)
            and (e.get("attack_label") or "").lower() == cat.lower()
        )

        # FP: triggered BUT wrong label (misclassified by YaTC)
        fp = sum(
            1 for e in flows
            if e.get("triggered", False)
            and (e.get("attack_label") or "").lower() != cat.lower()
        )

        # FN: not triggered at all
        fn = sum(1 for e in flows if not e.get("triggered", False))

        alert_count    = tp + fp          # everything that triggered
        detection_rate = tp / total if total > 0 else 0.0

        # FP breakdown: which wrong label did YaTC assign?
        fp_breakdown = defaultdict(int)
        for e in flows:
            if e.get("triggered", False) and \
               (e.get("attack_label") or "").lower() != cat.lower():
                fp_breakdown[e.get("attack_label") or "unknown"] += 1

        # FN breakdown: why not triggered?
        fn_low_score      = sum(
            1 for e in flows
            if not e.get("triggered", False)
            and (e.get("attack_label") or "").lower() == cat.lower()
        )
        fn_wrong_label    = sum(
            1 for e in flows
            if not e.get("triggered", False)
            and (e.get("attack_label") or "").lower() != cat.lower()
        )

        results[cat] = {
            "total_flows":     total,
            "alert_count":     alert_count,
            "true_positives":  tp,
            "false_positives": fp,
            "false_negatives": fn,
            "detection_rate":  round(detection_rate, 4),
            "fp_breakdown":    dict(fp_breakdown),   # which wrong label caused FP
            "fn_low_score":    fn_low_score,         # correct label but score < threshold
            "fn_wrong_label":  fn_wrong_label,       # wrong label → not triggered
        }

    # ── Macro averages ────────────────────────────────────────────────────────
    vals = [v for k, v in results.items() if k in ATTACK_CATEGORIES]
    if vals:
        results["_macro"] = {
            "total_flows":     sum(v["total_flows"]     for v in vals),
            "alert_count":     sum(v["alert_count"]     for v in vals),
            "true_positives":  sum(v["true_positives"]  for v in vals),
            "false_positives": sum(v["false_positives"] for v in vals),
            "false_negatives": sum(v["false_negatives"] for v in vals),
            "detection_rate":  round(
                statistics.mean(v["detection_rate"] for v in vals), 4),
        }

    return results


# ── Processing time ───────────────────────────────────────────────────────────

def eval_timing(entries: list[dict]) -> dict:
    """
    Timing for triggered flows only (pipeline was actually executed).

    t_detect   = timestamp when YaTC finished classification
    t_generate = timestamp after LLM returned response
    t_validate = timestamp after rule validation
    t_deploy   = timestamp after deployment to klusids
    t_total    = t_deploy - t_detect  (end-to-end reaction time)

    Derived durations:
        phase_generate = t_generate - t_detect
        phase_validate = t_validate - t_generate
        phase_deploy   = t_deploy   - t_validate
    """
    triggered = [e for e in entries if e.get("triggered", False)]

    if not triggered:
        return {"error": "No triggered entries found"}

    def _phase(e, t_start_key, t_end_key):
        t0 = e.get(t_start_key)
        t1 = e.get(t_end_key)
        if t0 and t1:
            return round(t1 - t0, 3)
        return None

    phase_gen  = [v for e in triggered
                  if (v := _phase(e, "t_detect",   "t_generate")) is not None]
    phase_val  = [v for e in triggered
                  if (v := _phase(e, "t_generate", "t_validate")) is not None]
    phase_dep  = [v for e in triggered
                  if (v := _phase(e, "t_validate", "t_deploy"))   is not None]
    totals     = [e["t_total"] for e in triggered if e.get("t_total") is not None]

    result = {
        "phase_generate": _stat(phase_gen),   # LLM inference time
        "phase_validate": _stat(phase_val),   # rule validation time
        "phase_deploy":   _stat(phase_dep),   # SSH deploy time
        "t_total":        _stat(totals),      # end-to-end reaction time
    }

    # Per-category breakdown
    by_cat = defaultdict(list)
    for e in triggered:
        cat = e.get("attack_label") or _get_ground_truth(e)
        if e.get("t_total") is not None:
            by_cat[cat].append(e["t_total"])

    result["per_category_t_total"] = {
        cat: _stat(vals) for cat, vals in by_cat.items()
    }

    return result


# ── Rule validity ─────────────────────────────────────────────────────────────

def eval_rule_validity(entries: list[dict]) -> dict:
    """
    Rule validity for triggered flows:
      - validity_rate:  valid rules / triggered flows
      - retry_rate:     flows that needed at least one retry
      - per category breakdown
    """
    triggered = [e for e in entries if e.get("triggered", False)]
    if not triggered:
        return {"error": "No triggered entries found"}

    n         = len(triggered)
    n_valid   = sum(1 for e in triggered if e.get("rule_valid", False))
    n_retried = sum(1 for e in triggered if (e.get("retry_count") or 0) > 0)

    # Per-category
    by_cat = defaultdict(list)
    for e in triggered:
        cat = e.get("attack_label") or _get_ground_truth(e)
        by_cat[cat].append(e)

    per_cat = {}
    for cat, flows in by_cat.items():
        n_cat   = len(flows)
        n_v     = sum(1 for e in flows if e.get("rule_valid", False))
        n_r     = sum(1 for e in flows if (e.get("retry_count") or 0) > 0)
        per_cat[cat] = {
            "triggered":    n_cat,
            "valid":        n_v,
            "validity_rate": round(n_v / n_cat, 4) if n_cat > 0 else 0.0,
            "retried":      n_r,
            "retry_rate":   round(n_r / n_cat, 4) if n_cat > 0 else 0.0,
        }

    return {
        "n_triggered":   n,
        "n_valid":       n_valid,
        "validity_rate": round(n_valid / n, 4) if n > 0 else 0.0,
        "n_retried":     n_retried,
        "retry_rate":    round(n_retried / n, 4) if n > 0 else 0.0,
        "per_category":  per_cat,
    }


# ── Output ────────────────────────────────────────────────────────────────────

def save_results(results: dict, output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"Results saved to: {output_path}")


def print_summary(results: dict):
    SEP = "=" * 68

    # ── Detection ─────────────────────────────────────────────────────────────
    det   = results.get("detection", {})
    macro = det.get("_macro", {})

    print(f"\n{SEP}")
    print("SCENARIO 2 — PIPELINE EVALUATION RESULTS")
    print(SEP)

    print(f"\n── Detection ──")
    print(f"{'Category':<12} {'Flows':>6} {'Alerts':>7} {'TP':>5} "
          f"{'FP':>5} {'FN':>5} {'DetRate':>8}")
    print("-" * 52)
    for cat in ATTACK_CATEGORIES:
        r = det.get(cat)
        if not r:
            continue
        print(f"{cat:<12} {r['total_flows']:>6} {r['alert_count']:>7} "
              f"{r['true_positives']:>5} {r['false_positives']:>5} "
              f"{r['false_negatives']:>5} {r['detection_rate']:>8.1%}")
        # FP breakdown (only if FP > 0)
        if r.get("fp_breakdown"):
            for wrong_lbl, cnt in sorted(r["fp_breakdown"].items(),
                                         key=lambda x: -x[1]):
                print(f"  {'':10} └ FP: YaTC={wrong_lbl}: {cnt}")
        # FN breakdown
        if r.get("fn_low_score", 0) > 0 or r.get("fn_wrong_label", 0) > 0:
            print(f"  {'':10} └ FN low-score={r['fn_low_score']}  "
                  f"wrong-label={r['fn_wrong_label']}")
    print("-" * 52)
    print(f"{'TOTAL':<12} {macro.get('total_flows',0):>6} "
          f"{macro.get('alert_count',0):>7} "
          f"{macro.get('true_positives',0):>5} "
          f"{macro.get('false_positives',0):>5} "
          f"{macro.get('false_negatives',0):>5} "
          f"{macro.get('detection_rate',0):>8.1%}")

    # ── Processing time ───────────────────────────────────────────────────────
    tim = results.get("timing", {})
    print(f"\n── Processing Time (triggered flows only) ──")
    print(f"{'Phase':<18} {'mean':>7} {'median':>7} {'min':>7} "
          f"{'max':>7} {'stdev':>7} {'n':>4}")
    print("-" * 62)
    for key, label in [
        ("phase_generate", "LLM inference"),
        ("phase_validate", "Rule validate"),
        ("phase_deploy",   "Deploy SSH"),
        ("t_total",        "End-to-end"),
    ]:
        s = tim.get(key, {})
        if not s or s.get("n", 0) == 0:
            continue
        print(f"{label:<18} {s['mean']:>7.2f} {s['median']:>7.2f} "
              f"{s['min']:>7.2f} {s['max']:>7.2f} "
              f"{s['stdev']:>7.2f} {s['n']:>4}")

    # Per-category t_total
    per_cat_t = tim.get("per_category_t_total", {})
    if per_cat_t:
        print(f"\n  t_total per category:")
        print(f"  {'Category':<12} {'mean':>7} {'median':>7} {'min':>7} "
              f"{'max':>7} {'n':>4}")
        print("  " + "-" * 42)
        for cat, s in per_cat_t.items():
            if s.get("n", 0) == 0:
                continue
            print(f"  {cat:<12} {s['mean']:>7.2f} {s['median']:>7.2f} "
                  f"{s['min']:>7.2f} {s['max']:>7.2f} {s['n']:>4}")

    # ── Rule validity ─────────────────────────────────────────────────────────
    val = results.get("rule_validity", {})
    print(f"\n── Rule Validity ──")
    print(f"Triggered flows : {val.get('n_triggered', 0)}")
    print(f"Valid rules     : {val.get('n_valid', 0)}")
    print(f"Validity rate   : {val.get('validity_rate', 0):.1%}")
    print(f"Retry rate      : {val.get('retry_rate', 0):.1%}")

    per_cat_v = val.get("per_category", {})
    if per_cat_v:
        print(f"\n  {'Category':<12} {'Triggered':>10} {'Valid':>6} "
              f"{'ValidRate':>10} {'Retried':>8}")
        print("  " + "-" * 50)
        for cat, v in per_cat_v.items():
            print(f"  {cat:<12} {v['triggered']:>10} {v['valid']:>6} "
                  f"{v['validity_rate']:>10.1%} {v['retried']:>8}")

    print(f"\n{SEP}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate full LLM pipeline performance (Scenario 2)"
    )
    parser.add_argument(
        "--log",
        default="/usr/ShieldGPT/output/online/pipeline_log.jsonl",
        help="Path to pipeline_log.jsonl"
    )
    parser.add_argument(
        "--output",
        default="/usr/ShieldGPT/output/eval_scenario2.json",
        help="Output JSON path"
    )
    args = parser.parse_args()

    if not Path(args.log).exists():
        logger.error(f"Log file not found: {args.log}")
        exit(1)

    entries = load_log(args.log)

    results = {
        "detection":     eval_detection(entries),
        "timing":        eval_timing(entries),
        "rule_validity": eval_rule_validity(entries),
        "config": {
            "n_entries": len(entries),
            "log_path":  args.log,
        }
    }

    save_results(results, args.output)
    print_summary(results)