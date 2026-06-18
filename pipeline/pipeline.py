"""
pipeline.py
Main evaluation pipeline for LLM-assisted DDoS mitigation.

Two modes:
    --mode offline  : process pre-split flow PCAPs from disk
    --mode online   : capture live traffic via scapy.sniff(),
                      build per-flow PCAPs on the fly, classify and
                      generate rules in real time

Architecture:
    klusids (10.34.0.28):
        tcpreplay -i ens160 --dstipmap 0.0.0.0/0:10.34.0.28
        Snort 3 IPS on ens160 → alert_fast.txt

    kllums (10.34.0.29, this script):
        online mode:
            scapy.sniff() on ens160
            → per-flow PCAPs (6 packets) → yatc_online.classify_flow()
            → LLM → rule_deployer → SSH → klusids

        offline mode:
            read pre-split flow PCAPs from disk
            → yatc_online.classify_flow()
            → LLM → rule_deployer → SSH → klusids

Usage:
    # Online (live capture, stop after 100 flows):
    python3 pipeline.py --mode online --interface ens160 --max_flows 100

    # Offline (pre-split PCAPs):
    python3 pipeline.py --mode offline --pcap_dir /data/cic-ddos2019/pcap/flows
"""

import os
import sys
import time
import json
import logging
import argparse
import threading
from pathlib import Path
from openai import OpenAI
from scapy.all import sniff, wrpcap

# ── Local imports ─────────────────────────────────────────────────────────────
from yatc_online         import classify_flow
from pcap2text_ddos2019  import generate_digest
from prompt_builder      import build_prompt
from rule_extractor      import extract_rules
from rule_validator      import validate_rules
from rule_deployer       import deploy_rules
from attack_descriptions import SYSTEM_PROMPT

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
YATC_THRESHOLD        = 0.85
MAX_RETRIES           = 3
LLM_MODEL             = "gpt-4o"
LLM_TEMPERATURE       = 0.2
LLM_MAX_TOKENS        = 2048
FLOW_PKT_LIMIT        = 6        # packets per flow (matches YaTC training)
CAPTURE_INTERFACE     = "ens160"
FLOW_TMP_DIR          = "/tmp/pipeline_flows"
GROUND_TRUTH_CATEGORY = None     # set via --category argument

client = OpenAI()  # uses OPENAI_API_KEY


# ── LLM inference ─────────────────────────────────────────────────────────────

def llm_generate(prompt: str, extra_context: str = "") -> tuple[str, float]:
    """Submit prompt to GPT-4o. Returns (response_text, latency_s)."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    if extra_context:
        messages.append({"role": "user", "content": extra_context})
    messages.append({"role": "user", "content": prompt})

    t0 = time.time()
    response = client.chat.completions.create(
        model=LLM_MODEL,
        temperature=LLM_TEMPERATURE,
        max_tokens=LLM_MAX_TOKENS,
        messages=messages,
    )
    return response.choices[0].message.content, time.time() - t0


# ── Core pipeline ─────────────────────────────────────────────────────────────

def process_flow(pcap_path: str) -> dict:
    """
    Run the full pipeline for a single flow PCAP file.
    Returns a structured log entry with all evaluation metrics.
    """
    flow_key = Path(pcap_path).stem
    log_entry = {
        "flow_key":      flow_key,
        "pcap_path":     pcap_path,
        "ground_truth":  GROUND_TRUTH_CATEGORY,
        "attack_label":  None,
        "yatc_score":    None,
        "triggered":     False,
        "t_detect":      None,
        "t_generate":    None,
        "t_validate":    None,
        "t_deploy":      None,
        "t_total":       None,
        "rule_valid":    False,
        "retry_count":   0,
        "rule_type":     None,
        "analysis":      None,
        "rule_text":     None,
        "deploy_errors": [],
    }

    # ── Step 1: YaTC classification ───────────────────────────────────────────
    try:
        label, score = classify_flow(pcap_path)
    except Exception as e:
        logger.error(f"[{flow_key}] YaTC error: {e}")
        return log_entry

    log_entry["attack_label"] = label
    log_entry["yatc_score"]   = round(score, 4)
    t_detect = time.time()
    log_entry["t_detect"] = t_detect
    logger.info(f"[{flow_key}] YaTC: {label} ({score:.4f})")

    # ── Step 2: Trigger check ─────────────────────────────────────────────────
    if score < YATC_THRESHOLD or label == "benign":
        return log_entry
    log_entry["triggered"] = True
    logger.info(f"[{flow_key}] Triggered — invoking LLM")

    # ── Step 3: Feature extraction ────────────────────────────────────────────
    try:
        digest = generate_digest(pcap_path)
        digest["yatc_label"] = label
        digest["yatc_score"] = score
        prompt = build_prompt(digest)
    except Exception as e:
        logger.error(f"[{flow_key}] Feature extraction error: {e}")
        return log_entry

    # ── Step 4: LLM inference with retry ─────────────────────────────────────
    parsed        = None
    extra_context = ""

    for attempt in range(1, MAX_RETRIES + 1):
        logger.info(f"[{flow_key}] LLM attempt {attempt}/{MAX_RETRIES}")
        try:
            response, latency = llm_generate(prompt, extra_context)
            t_generate = time.time()
            log_entry["t_generate"] = t_generate
            logger.info(f"[{flow_key}] LLM response ({latency:.2f}s)")
        except Exception as e:
            logger.error(f"[{flow_key}] LLM error: {e}")
            log_entry["retry_count"] = attempt
            continue

        # ── Step 5: Rule extraction ───────────────────────────────────────────
        parsed = extract_rules(response)
        log_entry["rule_type"] = parsed["rule_type"]
        log_entry["analysis"]  = parsed["analysis"]
        log_entry["rule_text"] = parsed["rules"]

        if not parsed["valid"]:
            logger.warning(f"[{flow_key}] No ---RULES--- delimiter")
            extra_context = (
                "Your previous response did not contain the ---RULES--- "
                "delimiter. Please separate your analysis from your rules "
                "using exactly: ---RULES---"
            )
            log_entry["retry_count"] = attempt
            continue

        # ── Step 6: Rule validation ───────────────────────────────────────────
        validation = validate_rules(parsed["snort_rules"])
        t_validate = time.time()
        log_entry["t_validate"] = t_validate

        if validation["valid"]:
            log_entry["rule_valid"] = True
            logger.info(f"[{flow_key}] Rule valid ({parsed['rule_type']})")
            break
        else:
            logger.warning(f"[{flow_key}] Validation failed: {validation['errors']}")
            extra_context = (
                f"Your previous response contained invalid rules. "
                f"Errors: {'; '.join(validation['errors'])}. "
                f"Please correct the rules."
            )
            log_entry["retry_count"] = attempt

    # ── Step 7: Deployment ────────────────────────────────────────────────────
    if log_entry["rule_valid"] and parsed:
        logger.info(f"[{flow_key}] Deploying to klusids...")
        result = deploy_rules(parsed["snort_rules"])
        log_entry["t_deploy"]      = result["t_deploy"]
        log_entry["deploy_errors"] = result["errors"]
        log_entry["t_total"]       = round(
            result["t_deploy"] - t_detect, 3
        )
        if result["success"]:
            logger.info(f"[{flow_key}] Deployed: {result['deployed']}")
        else:
            logger.error(f"[{flow_key}] Deploy errors: {result['errors']}")
    else:
        logger.warning(f"[{flow_key}] No valid rule after {MAX_RETRIES} attempts")

    return log_entry


# ── Online mode — scapy.sniff() ───────────────────────────────────────────────

def run_pipeline_online(interface: str, output_dir: str, duration: int,
                        category: str = None, max_flows: int = 100):
    """
    Capture live traffic via scapy.sniff(), build per-flow PCAPs
    on the fly and process each flow through the full pipeline.

    Stops after max_flows complete flows have been queued,
    regardless of remaining duration.
    """
    import queue

    os.makedirs(output_dir,  exist_ok=True)
    os.makedirs(FLOW_TMP_DIR, exist_ok=True)

    suffix        = f"_{category}" if category else ""
    log_path      = os.path.join(output_dir, f"pipeline_log{suffix}.jsonl")
    flow_packets  = {}
    lock          = threading.Lock()
    pcap_queue    = queue.Queue()
    flow_count    = 0
    stop_sniff    = threading.Event()   # set when max_flows reached

    logger.info(f"[ONLINE] Will stop after {max_flows} complete flows")

    # ── Worker thread ─────────────────────────────────────────────────────────
    def worker():
        while True:
            item = pcap_queue.get()
            if item is None:
                break
            try:
                entry = process_flow(item)
                with open(log_path, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception as e:
                logger.error(f"[worker] Error processing {item}: {e}")
            finally:
                pcap_queue.task_done()

    worker_thread = threading.Thread(target=worker, daemon=True)
    worker_thread.start()

    # ── Packet callback ───────────────────────────────────────────────────────
    def on_packet(pkt):
        nonlocal flow_count

        if stop_sniff.is_set():
            return
        if not pkt.haslayer("IP"):
            return

        ip = pkt["IP"]
        try:
            sport = pkt.sport
            dport = pkt.dport
        except AttributeError:
            sport, dport = 0, 0

        flow_key = f"{ip.src}_{sport}_{ip.proto}_{ip.dst}_{dport}"

        with lock:
            if stop_sniff.is_set():
                return

            flow_packets.setdefault(flow_key, [])
            flow_packets[flow_key].append(pkt)

            if len(flow_packets[flow_key]) < FLOW_PKT_LIMIT:
                return

            # Flow complete
            pkts      = flow_packets.pop(flow_key)
            pcap_path = os.path.join(FLOW_TMP_DIR, f"{flow_key}.pcap")
            wrpcap(pcap_path, pkts)
            pcap_queue.put(pcap_path)
            flow_count += 1
            logger.info(f"[ONLINE] Flow {flow_count}/{max_flows} queued")

            if flow_count >= max_flows:
                logger.info(f"[ONLINE] Reached {max_flows} flows — stopping capture")
                stop_sniff.set()

    logger.info(f"[ONLINE] Sniffing on {interface} (timeout={duration}s) ...")
    sniff(
        iface=interface,
        prn=on_packet,
        store=False,
        timeout=duration,
        stop_filter=lambda _: stop_sniff.is_set(),
        filter="ip and not (tcp port 2222)",
    )
    logger.info(f"[ONLINE] Capture done ({flow_count} flows) — draining queue ...")

    pcap_queue.join()
    pcap_queue.put(None)
    worker_thread.join()

    logger.info(f"[ONLINE] All {flow_count} flows processed.")
    _print_summary(log_path)


# ── Offline mode ──────────────────────────────────────────────────────────────

def run_pipeline_offline(pcap_dir: str, output_dir: str, max_flows: int = 0):
    """Process pre-split flow PCAPs from disk."""
    os.makedirs(output_dir, exist_ok=True)
    log_path   = os.path.join(output_dir, "pipeline_log.jsonl")
    pcap_files = sorted(Path(pcap_dir).rglob("*.pcap"))

    if not pcap_files:
        logger.error(f"No PCAP files found in {pcap_dir}")
        return

    if max_flows > 0:
        pcap_files = pcap_files[:max_flows]
        logger.info(f"[OFFLINE] Limited to {max_flows} flows")

    logger.info(f"[OFFLINE] Processing {len(pcap_files)} flow PCAPs")

    for pcap_path in pcap_files:
        entry = process_flow(str(pcap_path))
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    _print_summary(log_path)


# ── Summary ───────────────────────────────────────────────────────────────────

def _print_summary(log_path: str):
    entries = []
    try:
        with open(log_path) as f:
            for line in f:
                entries.append(json.loads(line.strip()))
    except Exception:
        return

    n_total   = len(entries)
    n_trigger = sum(1 for e in entries if e.get("triggered"))
    n_valid   = sum(1 for e in entries if e.get("rule_valid"))
    latencies = [e["t_total"] for e in entries if e.get("t_total")]

    logger.info(f"\n{'='*50}")
    logger.info(f"Total flows    : {n_total}")
    logger.info(f"Triggered      : {n_trigger}")
    logger.info(f"Valid rules    : {n_valid}")
    if n_trigger > 0:
        logger.info(f"Validity rate  : {n_valid/n_trigger*100:.1f}%")
    if latencies:
        import statistics
        logger.info(f"Avg t_total    : {statistics.mean(latencies):.2f}s")
    logger.info(f"Log saved      : {log_path}")

    not_triggered = [e for e in entries if not e.get("triggered")]
    if not_triggered:
        from collections import Counter
        labels = Counter(e.get("attack_label", "unknown") for e in not_triggered)
        logger.info(f"Not triggered  : {len(not_triggered)} flows")
        for lbl, cnt in labels.most_common():
            score_avg = sum(e.get("yatc_score", 0) or 0 for e in not_triggered
                           if e.get("attack_label") == lbl) / cnt
            logger.info(f"  {lbl:<12}: {cnt:>4} flows  (avg score {score_avg:.3f})")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ShieldGPT evaluation pipeline"
    )
    parser.add_argument("--mode", choices=["offline", "online"], default="offline")
    parser.add_argument(
        "--category",
        choices=["LDAP", "MSSQL", "NetBIOS", "Syn", "UDP", "benign"],
        default=None,
        help="Ground truth attack category being replayed"
    )
    parser.add_argument(
        "--pcap_dir",
        default="/data/cic-ddos2019/pcap/flows",
        help="[offline] Directory with pre-split flow PCAPs"
    )
    parser.add_argument(
        "--interface",
        default=CAPTURE_INTERFACE,
        help="[online] Network interface for live capture"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=200,
        help="[online] Safety timeout in seconds (default: 200)"
    )
    parser.add_argument(
        "--max_flows",
        type=int,
        default=100,
        help="Stop after this many complete flows (default: 100)"
    )
    parser.add_argument("--output_dir", default="/usr/ShieldGPT/output/online")
    parser.add_argument("--threshold", type=float, default=YATC_THRESHOLD)
    parser.add_argument(
        "--pkt_limit",
        type=int,
        default=FLOW_PKT_LIMIT,
        help="Packets per flow before processing (default: 6)"
    )
    args = parser.parse_args()

    YATC_THRESHOLD        = args.threshold
    FLOW_PKT_LIMIT        = args.pkt_limit
    GROUND_TRUTH_CATEGORY = args.category

    if GROUND_TRUTH_CATEGORY:
        logger.info(f"Ground truth category: {GROUND_TRUTH_CATEGORY}")

    if args.mode == "online":
        run_pipeline_online(
            args.interface,
            args.output_dir,
            args.duration,
            args.category,
            args.max_flows,
        )
    else:
        run_pipeline_offline(
            args.pcap_dir,
            args.output_dir,
            args.max_flows,
        )