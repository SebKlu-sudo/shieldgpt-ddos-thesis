"""
pcap2text_ddos2019.py
Adapted from ShieldGPT/test/pcap2text.py for use in the CIC-DDoS2019
automated mitigation pipeline.

Key differences from the original:
- All comments and output in English
- Returns the feature dict directly instead of writing to JSON
- Adds SYN/ACK/RST flag counts as separate fields (relevant for DDoS)
- Handles division-by-zero for zero-duration flows (e.g. single-packet flows)
- Integrated into prompt_builder.py — no CSV lookup needed
- Preserves real src_ip/dst_ip from the live PCAP for accurate rule generation

Usage (standalone):
    python3 pcap2text_ddos2019.py --pcap /path/to/flow.pcap

Usage (as module):
    from pcap2text_ddos2019 import generate_digest
    features = generate_digest("/path/to/flow.pcap")
"""

from scapy.all import rdpcap, IP, TCP, UDP
import numpy as np
import json
import argparse
import os


def generate_digest(pcap_file_path: str,
                    write_json: bool = False) -> dict | None:
    """
    Extract flow-level statistical features from a per-flow PCAP file.

    Parameters
    ----------
    pcap_file_path : str
        Path to a PCAP file containing packets from a single flow.
    write_json : bool
        If True, also write the feature dict to a .json file alongside
        the PCAP. Default False (pipeline uses the return value directly).

    Returns
    -------
    dict
        Feature dictionary with flow statistics and per-packet details,
        or None if the PCAP contains fewer than 2 packets.
    """
    try:
        packets = rdpcap(pcap_file_path)
    except Exception as e:
        print(f"[ERROR] Cannot read {pcap_file_path}: {e}")
        return None

    if len(packets) < 2:
        return None

    # ── Flow-level statistics ─────────────────────────────────────────────

    total_packets = len(packets)
    bytes_list    = [len(p) for p in packets]
    total_bytes   = sum(bytes_list)

    min_pkt_size  = min(bytes_list)
    max_pkt_size  = max(bytes_list)
    avg_pkt_size  = total_bytes / total_packets
    std_pkt_size  = float(np.std(bytes_list))

    intervals = [
        float(packets[i + 1].time) - float(packets[i].time)
        for i in range(total_packets - 1)
    ]
    min_interval = min(intervals)
    max_interval = max(intervals)
    avg_interval = sum(intervals) / len(intervals)
    std_interval = float(np.std(intervals))

    fct = float(packets[-1].time) - float(packets[0].time)

    # Guard against zero-duration flows (e.g. all packets same timestamp)
    if fct > 0:
        packet_rate = total_packets / fct
        byte_rate   = total_bytes   / fct
    else:
        packet_rate = 0.0
        byte_rate   = 0.0

    # ── Five-tuple from first packet ──────────────────────────────────────

    first = packets[0]
    src_ip   = first[IP].src   if IP in first else ""
    dst_ip   = first[IP].dst   if IP in first else ""
    raw_proto = first[IP].proto if IP in first else 0
    proto    = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(raw_proto, str(raw_proto))

    if proto == "TCP" and TCP in first:
        src_port = first[TCP].sport
        dst_port = first[TCP].dport
    elif proto == "UDP" and UDP in first:
        src_port = first[UDP].sport
        dst_port = first[UDP].dport
    else:
        src_port = ""
        dst_port = ""

    # ── Aggregate TCP flag counts (DDoS-relevant) ─────────────────────────

    syn_count = 0
    ack_count = 0
    rst_count = 0
    fin_count = 0

    for p in packets:
        if TCP in p:
            flags = p[TCP].flags
            if flags & 0x02: syn_count += 1  # SYN
            if flags & 0x10: ack_count += 1  # ACK
            if flags & 0x04: rst_count += 1  # RST
            if flags & 0x01: fin_count += 1  # FIN

    # ── Per-packet details (first 5 packets) ─────────────────────────────

    packet_info = []
    for p in packets[:5]:
        if IP not in p:
            continue
        entry = {
            "packet_size (byte)": len(p),
            "timestamp":          float(p.time),
            "tcp_flags":          str(p[TCP].flags)    if TCP in p else "",
            "tcp_window_size":    p[TCP].window         if TCP in p else "",
            "payload":            "",
        }
        # Decode payload — fall back to hex repr on binary data
        try:
            if TCP in p:
                entry["payload"] = p[TCP].payload.original.decode("utf-8")
            elif UDP in p:
                entry["payload"] = p[UDP].payload.original.decode("utf-8")
        except Exception:
            try:
                raw = p[TCP].payload.original if TCP in p \
                      else p[UDP].payload.original
                entry["payload"] = raw.hex()[:64]  # truncate long payloads
            except Exception:
                entry["payload"] = ""

        packet_info.append(entry)

    # ── Assemble result dict ──────────────────────────────────────────────

    result = {
        # Five-tuple (real values from live PCAP — not from CSV)
        "src_ip":   src_ip,
        "src_port": src_port,
        "dst_ip":   dst_ip,
        "dst_port": dst_port,
        "proto":    proto,

        # Flow statistics
        "total_packets":                  total_packets,
        "total_bytes":                    total_bytes,
        "min_packet_size (byte)":         round(min_pkt_size,  3),
        "max_packet_size (byte)":         round(max_pkt_size,  3),
        "avg_packet_size (byte)":         round(avg_pkt_size,  3),
        "std_packet_size (byte)":         round(std_pkt_size,  3),
        "min_packet_interval (second)":   round(min_interval,  6),
        "max_packet_interval (second)":   round(max_interval,  6),
        "avg_packet_interval (second)":   round(avg_interval,  6),
        "std_packet_interval (second)":   round(std_interval,  6),
        "flow_completion_time (second)":  round(fct,           6),
        "packet_rate (per second)":       round(packet_rate,   3),
        "byte_rate (byte per second)":    round(byte_rate,     3),

        # TCP flag counts (DDoS-relevant — not in original generate_digest)
        "syn_flag_count": syn_count,
        "ack_flag_count": ack_count,
        "rst_flag_count": rst_count,
        "fin_flag_count": fin_count,

        # Per-packet details
        "packet_info": packet_info,
    }

    if write_json:
        json_path = pcap_file_path.replace(".pcap", ".json")
        with open(json_path, "w") as f:
            json.dump(result, f, indent=2)

    return result


def digest_to_prompt_text(features: dict, attack_label: str,
                           attack_description: str) -> str:
    """
    Convert a feature dict returned by generate_digest() into the
    natural language text block that is embedded in the LLM prompt.

    Parameters
    ----------
    features : dict
        Output of generate_digest().
    attack_label : str
        Short attack label, e.g. "Syn", "LDAP".
    attack_description : str
        Full attack description from the attack_dict in gen_prompt.py.

    Returns
    -------
    str
        Formatted text block ready for insertion into the prompt template.
    """
    lines = [
        f"The following are traffic statistical characteristics of a "
        f"{attack_description}",
        "",
        f"Attack type             : {attack_label}",
        f"Source IP               : {features['src_ip']}",
        f"Source port             : {features['src_port']}",
        f"Destination IP          : {features['dst_ip']}",
        f"Destination port        : {features['dst_port']}",
        f"Protocol                : {features['proto']}",
        f"Total packets           : {features['total_packets']}",
        f"Total bytes             : {features['total_bytes']}",
        f"Avg packet size         : {features['avg_packet_size (byte)']} bytes",
        f"Max packet size         : {features['max_packet_size (byte)']} bytes",
        f"Packet rate             : {features['packet_rate (per second)']} pkt/s",
        f"Byte rate               : {features['byte_rate (byte per second)']} B/s",
        f"Flow duration           : {features['flow_completion_time (second)']} s",
        f"Avg packet interval     : {features['avg_packet_interval (second)']} s",
        f"SYN flag count          : {features['syn_flag_count']}",
        f"ACK flag count          : {features['ack_flag_count']}",
        f"RST flag count          : {features['rst_flag_count']}",
        f"FIN flag count          : {features['fin_flag_count']}",
    ]

    lines.append("")
    lines.append("First 5 packets:")
    for i, pkt in enumerate(features.get("packet_info", []), 1):
        lines.append(f"  Packet {i}:")
        lines.append(f"    Size      : {pkt['packet_size (byte)']} bytes")
        lines.append(f"    Timestamp : {pkt['timestamp']}")
        if pkt["tcp_flags"]:
            lines.append(f"    TCP flags : {pkt['tcp_flags']}")
        if pkt["tcp_window_size"]:
            lines.append(f"    TCP window: {pkt['tcp_window_size']}")
        if pkt["payload"]:
            lines.append(f"    Payload   : {pkt['payload'][:80]}")

    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract flow features from a per-flow PCAP file."
    )
    parser.add_argument("--pcap", required=True,
                        help="Path to input PCAP file")
    parser.add_argument("--json", action="store_true",
                        help="Write output to JSON file alongside PCAP")
    args = parser.parse_args()

    result = generate_digest(args.pcap, write_json=args.json)
    if result:
        print(json.dumps(result, indent=2))
    else:
        print("[ERROR] Could not extract features — fewer than 2 packets.")
