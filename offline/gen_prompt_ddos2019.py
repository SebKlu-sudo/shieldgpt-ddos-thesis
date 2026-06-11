"""
gen_prompt_ddos2019.py
Generates LLM prompts from CIC-DDoS2019 CSV flow features.
The LLM generates Snort 3 rules only for signature-based detection
and inline blocking.
"""
 
import pandas as pd
import random
import os
import argparse
 
random.seed(0)
 
from attack_descriptions import ATTACK_DICT, SYSTEM_PROMPT
 
# CSV column name mapping
FEATURE_COLS = {
    "flow_duration":     " Flow Duration",
    "total_fwd_packets": " Total Fwd Packets",
    "total_bwd_packets": " Total Backward Packets",
    "flow_bytes_per_s":  "Flow Bytes/s",
    "flow_packets_per_s":"Flow Packets/s",
    "flow_iat_mean":     " Flow IAT Mean",
    "fwd_pkt_len_max":   " Fwd Packet Length Max",
    "fwd_pkt_len_mean":  " Fwd Packet Length Mean",
    "bwd_pkt_len_max":   " Bwd Packet Length Max",
    "bwd_pkt_len_mean":  " Bwd Packet Length Mean",
    "syn_flag_count":    " SYN Flag Count",
    "ack_flag_count":    " ACK Flag Count",
    "rst_flag_count":    " RST Flag Count",
    "active_mean":       " Active Mean",
}
 
 
def build_traffic_description(row: pd.Series, label: str) -> str:
    """Format a CSV row into a natural language traffic description."""
    attack = ATTACK_DICT[label]
 
    def fmt(col, unit="", scale=1.0):
        try:
            v = float(row[FEATURE_COLS[col]]) * scale
            return f"{v:.2f} {unit}".strip()
        except Exception:
            return "N/A"
 
    lines = [
        f"The following are traffic statistical characteristics of "
        f"{attack['description']}",
        "",
        f"Attack type       : {attack['name']}",
        f"Flow duration     : {fmt('flow_duration', 'µs')}",
        f"Fwd packets       : {fmt('total_fwd_packets')}",
        f"Bwd packets       : {fmt('total_bwd_packets')}",
        f"Flow bytes/s      : {fmt('flow_bytes_per_s')}",
        f"Flow packets/s    : {fmt('flow_packets_per_s')}",
        f"Flow IAT mean     : {fmt('flow_iat_mean', 'µs')}",
        f"Fwd pkt len max   : {fmt('fwd_pkt_len_max', 'bytes')}",
        f"Fwd pkt len mean  : {fmt('fwd_pkt_len_mean', 'bytes')}",
        f"Bwd pkt len max   : {fmt('bwd_pkt_len_max', 'bytes')}",
        f"Bwd pkt len mean  : {fmt('bwd_pkt_len_mean', 'bytes')}",
        f"SYN flag count    : {fmt('syn_flag_count')}",
        f"ACK flag count    : {fmt('ack_flag_count')}",
        f"RST flag count    : {fmt('rst_flag_count')}",
        f"Active mean       : {fmt('active_mean', 'µs')}",
        "",
        "Step 1 - Analysis:",
        f"Analyse the traffic profile above and explain in 2-3 sentences "
        f"why it is indicative of a {attack['name']} attack.",
        "",
        "Step 2 - Mitigation:",
        "Write a Snort 3 rule that detects and blocks this specific attack "
        "based on the traffic characteristics above. The rule must include: "
        "action, protocol, src/dst IP/port, msg, sid, rev. Use "
        "detection_filter for rate-based detection where appropriate. "
        "Use $HOME_NET for the victim address. For the attacker address, "
        "use the specific source IP from the traffic profile if available, "
        "otherwise use $EXTERNAL_NET. "
        "Separate Step 1 and Step 2 with the delimiter: ---RULES---",
    ]
    return "\n".join(lines)
 
 
def generate_prompts(csv_dir: str, output_csv: str,
                     samples_per_class: int = 5):
    """
    Generate prompts for all attack categories found in csv_dir.
    Saves results to output_csv.
    """
    records = []
    for label, info in ATTACK_DICT.items():
        # Map label to CSV filename
        csv_map = {
            "Syn":     "Syn.csv",
            "LDAP":    "LDAP.csv",
            "MSSQL":   "MSSQL.csv",
            "NetBIOS": "NetBIOS.csv",
            "Portmap": "Portmap.csv",
            "UDP":     "UDP.csv",
            "UDPLag":  "UDPLag.csv",
        }
        csv_path = os.path.join(csv_dir, csv_map[label])
        if not os.path.exists(csv_path):
            print(f"[SKIP] {csv_path} not found")
            continue
 
        df = pd.read_csv(csv_path)
        df.columns = df.columns.str.strip()
 
        # Filter for attack label only
        label_col = "Label"
        if label_col in df.columns:
            df = df[df[label_col].str.strip() == label]
 
        # Drop rows with missing features
        feature_cols = list(FEATURE_COLS.values())
        available = [c.strip() for c in df.columns]
        feature_cols_clean = [
            c for c in feature_cols
            if c.strip() in available
        ]
        df = df.dropna(subset=feature_cols_clean)
 
        if len(df) == 0:
            print(f"[SKIP] No valid rows for {label}")
            continue
 
        # Sample
        n = min(samples_per_class, len(df))
        samples = df.sample(n, random_state=0)
 
        for _, row in samples.iterrows():
            prompt = build_traffic_description(row, label)
            records.append({
                "prompt":       prompt,
                "label":        label,
                "attack_name":  info["name"],
                "device":       "snort_only",
            })
        print(f"[OK] {label}: {n} prompts generated")
 
    out_df = pd.DataFrame(records)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    out_df.to_csv(output_csv, index=False)
    print(f"\n[DONE] {len(records)} prompts saved to {output_csv}")
    return out_df
 
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv_dir",
        default="/data/cic-ddos2019/csv/03-11",
        help="Directory containing CIC-DDoS2019 CSV files")
    parser.add_argument("--output_csv",
        default="/usr/ShieldGPT/output/attack_prompt_ddos2019_free_choice.csv",
        help="Output CSV path")
    parser.add_argument("--samples", type=int, default=5,
        help="Samples per attack category")
    args = parser.parse_args()
 
    generate_prompts(args.csv_dir, args.output_csv, args.samples)
