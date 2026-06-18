"""
eval_scenario2_offline.py
Evaluates Snort 3 IPS performance from alert_fast.txt (Scenario 2 — LLM-generated rules).

Same structure as eval_scenario1.py but uses SID ranges from llm_generated_rules.rules.

Metrics computed per attack category:
    - alert_count       : total alerts fired by category SIDs
    - tp_count          : alerts from correct category SIDs (ground truth)
    - fp_count          : alerts from wrong category SIDs
    - tp_rate           : tp_count / total_alerts
    - fp_rate           : fp_count / total_alerts
    - unclassified      : alerts from Community Rules (not our SIDs)

SID mapping (llm_generated_rules.rules):
    1000001-1000086  : SYN Flood               (86 rules)
    1000087-1000162  : LDAP Amplification      (76 rules)
    1000163-1000240  : MSSQL Amplification     (78 rules)
    1000241-1000336  : UDP Flood               (96 rules)
    1000337-1000396  : NetBIOS Amplification   (60 rules)

Usage:
    python3 eval_scenario2_offline.py \
        --alert_log /var/log/snort/alert_fast.txt \
        --category LDAP \
        --output /usr/ShieldGPT/output/eval_scenario2_offline_LDAP.json \
        [--ssh]
"""

import os
import re
import json
import argparse
import subprocess
import logging
from pathlib import Path
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

IDS_VM_HOST = "luser@10.34.0.28"
SSH_PORT    = "2222"

ATTACK_CATEGORIES = ["LDAP", "MSSQL", "NetBIOS", "Syn", "UDP", "benign"]

# SID ranges per category (inclusive) — llm_generated_rules.rules
SID_CATEGORY_MAP = {
    "Syn":     range(1000001, 1000087),   # 1000001-1000086  (86 rules)
    "LDAP":    range(1000087, 1000163),   # 1000087-1000162  (76 rules)
    "MSSQL":   range(1000163, 1000241),   # 1000163-1000240  (78 rules)
    "UDP":     range(1000241, 1000337),   # 1000241-1000336  (96 rules)
    "NetBIOS": range(1000337, 1000397),   # 1000337-1000396  (60 rules)
}

def sid_to_category(sid: int) -> str:
    """Map a SID to its attack category. Returns 'community' if not in our rules."""
    for cat, r in SID_CATEGORY_MAP.items():
        if sid in r:
            return cat
    return "community"


# ── Alert log loader ──────────────────────────────────────────────────────────

def load_alert_log(alert_log_path: str, via_ssh: bool = False) -> str:
    if via_ssh:
        logger.info("Loading alert log from klusids via SSH...")
        result = subprocess.run(
            ["ssh", "-p", SSH_PORT, IDS_VM_HOST,
             f"sudo -n cat {alert_log_path}"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            logger.error(f"SSH error: {result.stderr}")
            return ""
        return result.stdout
    else:
        with open(alert_log_path, "r") as f:
            return f.read()


# ── Alert parser ──────────────────────────────────────────────────────────────

def parse_alert_fast(log_text: str) -> list[dict]:
    """
    Parse Snort alert_fast.txt into list of alert dicts.
    Extracts SID from [gid:sid:rev] field.
    """
    alerts = []
    pattern = re.compile(
        r"\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+"   # [gid:sid:rev]
        r"(.+?)\s+\[\*\*\]"                        # msg
        r".*?\{(\w+)\}"                            # proto
        r"\s+(\S+)\s+->\s+(\S+)"                  # src -> dst
    )
    for line in log_text.splitlines():
        m = pattern.search(line)
        if m:
            alerts.append({
                "gid":      int(m.group(1)),
                "sid":      int(m.group(2)),
                "rev":      int(m.group(3)),
                "msg":      m.group(4).strip(),
                "proto":    m.group(5),
                "src":      m.group(6),
                "dst":      m.group(7),
                "category": sid_to_category(int(m.group(2))),
            })
    return alerts


# ── Metrics computation ───────────────────────────────────────────────────────

def compute_metrics(alerts: list[dict], ground_truth: str) -> dict:
    """
    Compute TP/FP metrics based on SID-to-category mapping.

    TP           = alert whose SID belongs to the ground_truth category
    FP           = alert whose SID belongs to a different attack category
    Unclassified = alert from Community Rules (not our SIDs)
    """
    total        = len(alerts)
    tp_count     = 0
    fp_count     = 0
    unclassified = 0

    cat_counts   = defaultdict(int)
    fp_breakdown = defaultdict(int)

    for alert in alerts:
        cat = alert["category"]
        cat_counts[cat] += 1

        if cat == ground_truth:
            tp_count += 1
        elif cat == "community":
            unclassified += 1
        else:
            fp_count += 1
            fp_breakdown[cat] += 1

    tp_rate = round(tp_count / total, 4) if total > 0 else 0.0
    fp_rate = round(fp_count / total, 4) if total > 0 else 0.0

    return {
        "ground_truth":   ground_truth,
        "total_alerts":   total,
        "tp_count":       tp_count,
        "fp_count":       fp_count,
        "unclassified":   unclassified,
        "tp_rate":        tp_rate,
        "fp_rate":        fp_rate,
        "fp_breakdown":   dict(fp_breakdown),
        "per_category":   dict(cat_counts),
    }


# ── Output ────────────────────────────────────────────────────────────────────

def save_results(results: dict, output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"Results saved to: {output_path}")


def print_summary(results: dict):
    gt    = results["ground_truth"]
    total = results["total_alerts"]
    tp    = results["tp_count"]
    fp    = results["fp_count"]
    unc   = results["unclassified"]

    print("\n" + "="*65)
    print("SCENARIO 2 — LLM-GENERATED RULES EVALUATION RESULTS")
    print("="*65)
    print(f"Ground truth category : {gt}")
    print(f"Total alerts          : {total}")
    print(f"TP ({gt:8s})         : {tp:>10}  ({results['tp_rate']:.2%})")
    print(f"FP (other categories) : {fp:>10}  ({results['fp_rate']:.2%})")
    if total > 0:
        print(f"Unclassified          : {unc:>10}  ({unc/total:.2%})")
    print()

    if results["fp_breakdown"]:
        print("FP breakdown:")
        for cat, count in sorted(results["fp_breakdown"].items(),
                                  key=lambda x: x[1], reverse=True):
            pct = count / total if total > 0 else 0
            print(f"  {cat:<14} {count:>8}  ({pct:.2%})")
        print()

    print(f"{'Category':<14} {'Alerts':>10}  {'TP':>8}  {'FP':>8}")
    print("-"*44)
    for cat in ATTACK_CATEGORIES:
        count = results["per_category"].get(cat, 0)
        if cat == gt:
            tp_pct = f"{count/total:.2%}" if total > 0 else "0.00%"
            fp_pct = "—"
        else:
            tp_pct = "—"
            fp_pct = f"{count/total:.2%}" if total > 0 else "0.00%"
        print(f"{cat:<14} {count:>10}  {tp_pct:>8}  {fp_pct:>8}")
    unc_count = results["per_category"].get("community", 0)
    print(f"{'community':<14} {unc_count:>10}  {'—':>8}  {'—':>8}")
    print("="*65)

    print("\nSID ranges (llm_generated_rules.rules):")
    for cat, r in SID_CATEGORY_MAP.items():
        print(f"  {cat:<10}: {r.start}–{r.stop - 1}  ({len(r)} rules)")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate Snort IPS performance (Scenario 2 — LLM-generated rules)"
    )
    parser.add_argument(
        "--alert_log",
        default="/var/log/snort/alert_fast.txt",
        help="Path to alert_fast.txt"
    )
    parser.add_argument(
        "--category",
        required=True,
        choices=ATTACK_CATEGORIES,
        help="Ground truth attack category being replayed"
    )
    parser.add_argument(
        "--output",
        default="/usr/ShieldGPT/output/eval_scenario2_offline.json",
        help="Output JSON path"
    )
    parser.add_argument(
        "--ssh",
        action="store_true",
        help="Load alert log from klusids via SSH"
    )
    args = parser.parse_args()

    log_text = load_alert_log(args.alert_log, via_ssh=args.ssh)
    if not log_text:
        logger.error("No alert log content — exiting")
        exit(1)

    alerts = parse_alert_fast(log_text)
    logger.info(f"Parsed {len(alerts)} alerts")

    results = compute_metrics(alerts, args.category)
    save_results(results, args.output)
    print_summary(results)
