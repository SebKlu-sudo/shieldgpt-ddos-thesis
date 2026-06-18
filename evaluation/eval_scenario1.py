"""
eval_scenario1.py
Evaluates Snort 3 IPS performance from alert_fast.txt (Scenario 1).

Metrics computed per attack category:
    - alert_count       : total alerts fired
    - detection_rate    : fraction of attack flows that triggered >= 1 alert
    - false_positive_rate: fraction of benign flows that triggered an alert

Usage:
    python3 eval_scenario1.py \
        --alert_log  /var/log/snort/alert_fast.txt \
        --pcap_dir   /tmp/attack_clean \
        --output     /usr/ShieldGPT/output/eval_scenario1.json

Reads alert_fast.txt from klusids via SSH or locally.
Reads attack_clean/*.pcap filenames to determine ground-truth categories.
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

IDS_VM_HOST   = "luser@10.34.0.28"
SSH_PORT      = "2222"

# Attack categories matching filter_attack_pcap.py output names
ATTACK_CATEGORIES = ["LDAP", "MSSQL", "NetBIOS", "Syn", "UDP"]


# ── Alert log parser ──────────────────────────────────────────────────────────

def parse_alert_fast(log_text: str) -> list[dict]:
    """
    Parse Snort alert_fast.txt into list of alert dicts.

    alert_fast format:
    MM/DD-HH:MM:SS.usec  [**] [gid:sid:rev] msg [**] [Classification: ...] [Priority: N] {PROTO} src:port -> dst:port
    """
    alerts = []
    # Regex for alert_fast format
    pattern = re.compile(
        r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)"   # timestamp
        r"\s+\[\*\*\]\s+\[\d+:(\d+):\d+\]\s+"       # sid
        r"(.+?)\s+\[\*\*\]"                           # msg
        r".*?\{(\w+)\}"                               # proto
        r"\s+(\S+)\s+->\s+(\S+)"                     # src -> dst
    )
    for line in log_text.splitlines():
        m = pattern.search(line)
        if m:
            alerts.append({
                "timestamp": m.group(1),
                "sid":       m.group(2),
                "msg":       m.group(3).strip(),
                "proto":     m.group(4),
                "src":       m.group(5),
                "dst":       m.group(6),
            })
    return alerts


def load_alert_log(alert_log_path: str, via_ssh: bool = False) -> str:
    """Load alert_fast.txt locally or from klusids via SSH."""
    if via_ssh:
        logger.info(f"Loading alert log from klusids via SSH...")
        result = subprocess.run(
            ["ssh", "-p", SSH_PORT, IDS_VM_HOST,
             f"sudo -n cat {alert_log_path}"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            logger.error(f"SSH error: {result.stderr}")
            return ""
        return result.stdout
    else:
        with open(alert_log_path, "r") as f:
            return f.read()


# ── PCAP ground truth ─────────────────────────────────────────────────────────

def load_ground_truth(pcap_dir: str) -> dict:
    """
    Build ground truth from attack_clean PCAP filenames.
    Returns dict: {category: flow_count}
    Uses pcap filenames like LDAP_clean.pcap, benign_clean.pcap
    """
    gt = {}
    for pcap_file in Path(pcap_dir).glob("*.pcap"):
        name = pcap_file.stem.replace("_clean", "")
        # Count packets as proxy for flows (or use fixed estimate)
        gt[name] = {"pcap": str(pcap_file)}
    return gt


# ── Metrics computation ───────────────────────────────────────────────────────

def compute_metrics(alerts: list[dict], pcap_dir: str) -> dict:
    """
    Compute per-category metrics from alerts.

    Since we don't have per-flow ground truth here,
    we measure:
    - alert_count per category (inferred from alert msg keywords)
    - total alerts
    - benign alerts (false positives)
    """
    results = {}

    # Count alerts per category by keyword matching in msg
    category_alerts = defaultdict(list)
    benign_alerts   = []

    category_keywords = {
        "LDAP":    ["ldap", "LDAP"],
        "MSSQL":   ["mssql", "MSSQL", "sql server", "SQL"],
        "NetBIOS": ["netbios", "NetBIOS", "nbns", "NBNS"],
        "Syn":     ["syn", "SYN", "flood", "dos"],
        "UDP":     ["udp", "UDP"],
    }

    for alert in alerts:
        msg_lower = alert["msg"].lower()
        matched = False
        for cat, keywords in category_keywords.items():
            if any(kw.lower() in msg_lower for kw in keywords):
                category_alerts[cat].append(alert)
                matched = True
                break
        if not matched:
            category_alerts["other"].append(alert)

    # Total stats
    total_alerts = len(alerts)
    logger.info(f"Total alerts parsed: {total_alerts}")

    # Per-category results
    # For FP rate: alerts from a category PCAP that belong to another category
    # We approximate: alerts fired during benign traffic = false positives
    # Since we replay one category at a time:
    # FP = alerts from OTHER categories fired during THIS category replay
    for cat in ATTACK_CATEGORIES:
        n_alerts    = len(category_alerts.get(cat, []))
        n_other     = sum(len(v) for k, v in category_alerts.items()
                          if k != cat and k != "other")
        n_total_cat = n_alerts + n_other

        # True Positive rate proxy: alerts matching this category / total alerts
        tp_rate = round(n_alerts / total_alerts, 4) if total_alerts > 0 else 0.0
        # False Positive rate proxy: alerts from other categories during this replay
        fp_rate = round(n_other / total_alerts, 4) if total_alerts > 0 else 0.0

        results[cat] = {
            "alert_count":    n_alerts,
            "tp_rate_proxy":  tp_rate,
            "fp_rate_proxy":  fp_rate,
            "other_alerts":   n_other,
            "alerts_sample":  [a["msg"] for a in category_alerts.get(cat, [])[:3]],
        }
        logger.info(f"  {cat:12s}: {n_alerts} alerts (TP proxy={tp_rate:.2%}, FP proxy={fp_rate:.2%})")

    # Benign / false positives
    n_other = len(category_alerts.get("other", []))
    results["_summary"] = {
        "total_alerts":        total_alerts,
        "unclassified_alerts": n_other,
        "categories":          list(category_alerts.keys()),
    }

    return results


def compute_detection_rates(alerts: list[dict], pcap_dir: str) -> dict:
    """
    Compute detection rate per category.
    Requires per-flow PCAP dir with known ground-truth flows.
    Counts unique src IPs per category as proxy for flow count.
    """
    rates = {}

    # Group alerts by dst IP (victim) and src (attacker)
    # and try to map to attack categories
    category_src_ips = defaultdict(set)
    category_keywords = {
        "LDAP":    ["ldap", "LDAP"],
        "MSSQL":   ["mssql", "MSSQL", "sql"],
        "NetBIOS": ["netbios", "nbns"],
        "Portmap": ["portmap", "rpc"],
        "Syn":     ["syn", "flood", "dos"],
        "UDP":     ["udp flood", "udp"],
        "UDPLag":  ["lag", "udp-lag"],
    }

    for alert in alerts:
        msg_lower = alert["msg"].lower()
        for cat, keywords in category_keywords.items():
            if any(kw.lower() in msg_lower for kw in keywords):
                category_src_ips[cat].add(alert["src"].split(":")[0])
                break

    # Count flows per category from pcap dir
    for cat in ATTACK_CATEGORIES:
        pcap_path = Path(pcap_dir) / f"{cat}_clean.pcap"
        n_detected = len(category_src_ips.get(cat, set()))
        rates[cat] = {
            "unique_src_ips_detected": n_detected,
            "pcap_exists": pcap_path.exists(),
        }

    return rates


# ── Output ────────────────────────────────────────────────────────────────────

def save_results(results: dict, output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"Results saved to: {output_path}")


def print_summary(results: dict):
    print("\n" + "="*65)
    print("SCENARIO 1 — SNORT IPS EVALUATION RESULTS")
    print("="*65)
    summary = results.get("_summary", {})
    print(f"Total alerts       : {summary.get('total_alerts', 0)}")
    print(f"Unclassified alerts: {summary.get('unclassified_alerts', 0)}")
    print()
    print(f"{'Category':<14} {'Alerts':>8} {'TP proxy':>10} {'FP proxy':>10}")
    print("-"*46)
    for cat in ATTACK_CATEGORIES:
        r = results.get(cat, {})
        print(f"{cat:<14} {r.get('alert_count', 0):>8} "
              f"{r.get('tp_rate_proxy', 0):>10.2%} "
              f"{r.get('fp_rate_proxy', 0):>10.2%}")
    print("="*65)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate Snort IPS performance (Scenario 1)"
    )
    parser.add_argument(
        "--alert_log",
        default="/var/log/snort/alert_fast.txt",
        help="Path to alert_fast.txt (local or on klusids)"
    )
    parser.add_argument(
        "--category",
        required=True,
        choices=ATTACK_CATEGORIES,
        help="Attack category currently being replayed (e.g. SYN, LDAP)"
    )
    parser.add_argument(
        "--pcap_dir",
        default="/tmp/attack_clean",
        help="Directory with attack_clean/*.pcap files"
    )
    parser.add_argument(
        "--output",
        default="/usr/ShieldGPT/output/eval_scenario1.json",
        help="Output JSON path"
    )
    parser.add_argument(
        "--ssh",
        action="store_true",
        help="Load alert log from klusids via SSH"
    )
    args = parser.parse_args()

    # Load alert log
    log_text = load_alert_log(args.alert_log, via_ssh=args.ssh)
    if not log_text:
        logger.error("No alert log content — exiting")
        exit(1)

    # Parse alerts
    alerts = parse_alert_fast(log_text)
    logger.info(f"Parsed {len(alerts)} alerts from {args.alert_log}")
    logger.info(f"Current category: {args.category}")

    # Compute metrics
    metrics   = compute_metrics(alerts, args.pcap_dir)
    det_rates = compute_detection_rates(alerts, args.pcap_dir)

    # Merge
    for cat in ATTACK_CATEGORIES:
        metrics[cat].update(det_rates.get(cat, {}))

    # Add ground truth category
    metrics["_config"] = {
        "category": args.category,
        "total_alerts": len(alerts),
    }

    # TP/FP based on known category
    cat_alerts  = metrics.get(args.category, {}).get("alert_count", 0)
    other_alerts = sum(
        metrics.get(c, {}).get("alert_count", 0)
        for c in ATTACK_CATEGORIES if c != args.category
    )
    total = len(alerts)
    metrics[args.category]["tp"]      = cat_alerts
    metrics[args.category]["fp"]      = other_alerts
    metrics[args.category]["tp_rate"] = round(cat_alerts / total, 4) if total > 0 else 0
    metrics[args.category]["fp_rate"] = round(other_alerts / total, 4) if total > 0 else 0

    # Save and print
    save_results(metrics, args.output)
    print_summary(metrics)
