"""
filter_attack_pcap.py
Extracts clean per-attack PCAPs and a deduplicated benign PCAP
from the merged first_day.pcap using CSV label annotations.

Uses streaming PcapReader instead of rdpcap() to avoid loading
the entire PCAP into RAM.

Usage:
    python3 filter_attack_pcap.py \
        --merged /usr/ShieldGPT/datasets/cic-ddos2019/pcap/merged/first_day.pcap \
        --csv_dir /data/cic-ddos2019/csv/03-11 \
        --output_dir /data/cic-ddos2019/pcap/attack_clean
"""

import argparse
import os
import pandas as pd
from scapy.all import PcapReader, PcapWriter, IP, TCP, UDP


# CSV filename mapping
CSV_MAP = {
    "LDAP":    "LDAP.csv",
    "MSSQL":   "MSSQL.csv",
    "NetBIOS": "NetBIOS.csv",
    "Portmap": "Portmap.csv",
    "Syn":     "Syn.csv",
    "UDP":     "UDP.csv",
    "UDPLag":  "UDPLag.csv",
}

ATTACK_LABELS = {
    "LDAP":    "LDAP",
    "MSSQL":   "MSSQL",
    "NetBIOS": "NetBIOS",
    "Portmap": "Portmap",
    "Syn":     "Syn",
    "UDP":     "UDP",
    "UDPLag":  "UDPLag",
}

BENIGN_LABEL = "BENIGN"


def load_five_tuples(csv_path: str, label: str) -> set:
    """
    Load all Five-Tuples from a CSV that match the given label.
    Returns a set of (src_ip, src_port, proto, dst_ip, dst_port) tuples.
    """
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()

    df = df[df["Label"].str.strip() == label]

    five_tuples = set()
    for _, row in df.iterrows():
        try:
            t = (
                str(row["Source IP"]).strip(),
                str(int(float(row["Source Port"]))),
                str(int(float(row["Protocol"]))),
                str(row["Destination IP"]).strip(),
                str(int(float(row["Destination Port"]))),
            )
            five_tuples.add(t)
        except Exception:
            continue

    return five_tuples


def get_five_tuple(packet) -> tuple | None:
    """Extract five-tuple from a packet. Returns None if not IP."""
    try:
        if IP not in packet:
            return None

        src_ip  = packet[IP].src
        dst_ip  = packet[IP].dst
        proto   = str(packet[IP].proto)

        if TCP in packet:
            src_port = str(packet[TCP].sport)
            dst_port = str(packet[TCP].dport)
        elif UDP in packet:
            src_port = str(packet[UDP].sport)
            dst_port = str(packet[UDP].dport)
        else:
            src_port = "0"
            dst_port = "0"

        return (src_ip, src_port, proto, dst_ip, dst_port)
    except Exception:
        return None


def filter_pcap_streaming(merged_pcap: str, five_tuples: set,
                           output_path: str, desc: str = ""):
    """
    Stream through merged PCAP keeping only packets matching five_tuples.
    Uses PcapReader to avoid loading entire file into RAM.
    Checks both forward and reverse directions.
    """
    print(f"[INFO] Filtering {desc}: {len(five_tuples):,} five-tuples")
    print(f"[INFO] Streaming {merged_pcap} ...")

    matched   = 0
    total     = 0
    CHUNK     = 100000  # print progress every N packets

    with PcapWriter(output_path, append=False, sync=True) as writer:
        with PcapReader(merged_pcap) as reader:
            for pkt in reader:
                total += 1
                if total % CHUNK == 0:
                    print(f"  [{total:,} pkts read, {matched:,} matched]")

                ft = get_five_tuple(pkt)
                if ft is None:
                    continue

                src_ip, src_port, proto, dst_ip, dst_port = ft
                fwd = ft
                rev = (dst_ip, dst_port, proto, src_ip, src_port)

                if fwd in five_tuples or rev in five_tuples:
                    writer.write(pkt)
                    matched += 1

    size_mb = os.path.getsize(output_path) / 1024 / 1024
    print(f"[OK] {desc}: {matched:,} / {total:,} packets → "
          f"{output_path} ({size_mb:.1f} MB)")
    return matched


def main(args):
    os.makedirs(args.output_dir, exist_ok=True)

    # ── Per-attack filtering ───────────────────────────────────────────────
    for attack, csv_name in CSV_MAP.items():
        csv_path = os.path.join(args.csv_dir, csv_name)
        if not os.path.exists(csv_path):
            print(f"[SKIP] {csv_path} not found")
            continue

        label = ATTACK_LABELS[attack]
        print(f"\n{'='*50}")
        print(f"Processing {attack} (label='{label}')")

        five_tuples = load_five_tuples(csv_path, label)
        print(f"[INFO] Five-tuples loaded: {len(five_tuples):,}")

        output_path = os.path.join(args.output_dir, f"{attack}_clean.pcap")
        filter_pcap_streaming(args.merged, five_tuples, output_path, attack)

    # ── Benign filtering (deduplicated across all CSVs) ────────────────────
    print(f"\n{'='*50}")
    print("Processing BENIGN (deduplicated across all CSVs)")

    benign_tuples = set()
    for csv_name in CSV_MAP.values():
        csv_path = os.path.join(args.csv_dir, csv_name)
        if not os.path.exists(csv_path):
            continue
        tuples = load_five_tuples(csv_path, BENIGN_LABEL)
        before = len(benign_tuples)
        benign_tuples.update(tuples)
        added = len(benign_tuples) - before
        print(f"[INFO] {csv_name}: +{added:,} benign tuples "
              f"(total: {len(benign_tuples):,})")

    output_path = os.path.join(args.output_dir, "benign_clean.pcap")
    filter_pcap_streaming(args.merged, benign_tuples, output_path, "BENIGN")

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'='*50}")
    print("Summary:")
    for f in sorted(os.listdir(args.output_dir)):
        if f.endswith(".pcap"):
            size = os.path.getsize(
                os.path.join(args.output_dir, f)) / 1024 / 1024
            print(f"  {f}: {size:.1f} MB")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--merged",
        default="/usr/ShieldGPT/datasets/cic-ddos2019/pcap/merged/first_day.pcap",
        help="Path to merged first_day.pcap")
    parser.add_argument("--csv_dir",
        default="/data/cic-ddos2019/csv/03-11",
        help="Directory with CIC-DDoS2019 CSV files")
    parser.add_argument("--output_dir",
        default="/data/cic-ddos2019/pcap/attack_clean",
        help="Output directory for clean PCAPs")
    args = parser.parse_args()
    main(args)
