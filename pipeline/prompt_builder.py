"""
prompt_builder.py
Builds the LLM prompt from a feature digest dict.
 
Called by pipeline.py:
    digest = generate_digest(pcap_path)
    digest["yatc_label"] = label
    digest["yatc_score"] = score
    prompt = build_prompt(digest)
 
Returns a ready-to-submit prompt string.
"""
 
from attack_descriptions import ATTACK_DICT, SYSTEM_PROMPT
 
 
def build_prompt(digest: dict) -> str:
    """
    Build a complete LLM prompt from a feature digest dict.
 
    Parameters
    ----------
    digest : dict
        Output from generate_digest() with yatc_label and yatc_score appended.
 
    Returns
    -------
    str : ready-to-submit prompt string
    """
    label = digest.get("yatc_label", "unknown")
    score = digest.get("yatc_score", 0.0)
 
    attack_info = ATTACK_DICT.get(label, {
        "name":        label,
        "description": f"a {label} attack.",
    })
 
    traffic_text = _format_features(digest, attack_info, score)
 
    prompt_lines = [
        traffic_text,
        "",
        "Step 1 - Analysis:",
        f"Analyse the traffic profile above and explain in 2-3 sentences "
        f"why it is indicative of a {attack_info['name']} attack.",
        "",
        "Step 2 - Mitigation:",
        "Write a Snort 3 rule that detects and blocks this specific attack "
        "based on the traffic characteristics above. The rule must include: "
        "action, protocol, src/dst IP/port, msg, sid, rev. Use "
        "detection_filter for rate-based detection where appropriate. "
        "Use $HOME_NET for the victim address. For the attacker address, "
        "use the specific source IP from the traffic profile if available, "
        "otherwise use $EXTERNAL_NET.",
        "Separate Step 1 and Step 2 with the delimiter: ---RULES---",
    ]
 
    return "\n".join(prompt_lines)
 
 
def _format_features(digest: dict,
                     attack_info: dict,
                     yatc_score: float) -> str:
    """Format digest dict into natural language traffic description."""
 
    lines = [
        f"The following are traffic statistical characteristics of "
        f"{attack_info['description']}",
        "",
        f"Attack type             : {attack_info['name']}",
        f"YaTC confidence         : {yatc_score:.2%}",
        "",
        # Five-tuple — real values from live PCAP
        f"Source IP               : {digest.get('src_ip', 'N/A')}",
        f"Source port             : {digest.get('src_port', 'N/A')}",
        f"Destination IP          : {digest.get('dst_ip', 'N/A')}",
        f"Destination port        : {digest.get('dst_port', 'N/A')}",
        f"Protocol                : {digest.get('proto', 'N/A')}",
        "",
        # Flow statistics
        f"Total packets           : {digest.get('total_packets', 'N/A')}",
        f"Total bytes             : {digest.get('total_bytes', 'N/A')}",
        f"Packet rate (pkt/s)     : {_fmt(digest, 'packet_rate (per second)')}",
        f"Byte rate (B/s)         : {_fmt(digest, 'byte_rate (byte per second)')}",
        f"Flow duration (s)       : {_fmt(digest, 'flow_completion_time (second)', 6)}",
        f"Avg packet interval (s) : {_fmt(digest, 'avg_packet_interval (second)', 6)}",
        f"Avg packet size (bytes) : {_fmt(digest, 'avg_packet_size (byte)')}",
        f"Max packet size (bytes) : {_fmt(digest, 'max_packet_size (byte)')}",
        "",
        # TCP flags
        f"SYN flag count          : {digest.get('syn_flag_count', 0)}",
        f"ACK flag count          : {digest.get('ack_flag_count', 0)}",
        f"RST flag count          : {digest.get('rst_flag_count', 0)}",
        f"FIN flag count          : {digest.get('fin_flag_count', 0)}",
    ]
 
    # Per-packet details (first 3)
    packet_info = digest.get("packet_info", [])
    if packet_info:
        lines.append("")
        lines.append("First packets detail:")
        for i, pkt in enumerate(packet_info[:3], 1):
            lines.append(
                f"  Packet {i}: "
                f"size={pkt.get('packet_size (byte)', 'N/A')} bytes  "
                f"flags={pkt.get('tcp_flags', '-')}  "
                f"window={pkt.get('tcp_window_size', '-')}"
            )
 
    return "\n".join(lines)
 
 
def _fmt(d: dict, key: str, decimals: int = 2) -> str:
    """Format a float from digest dict safely."""
    val = d.get(key)
    if val is None:
        return "N/A"
    try:
        return f"{float(val):.{decimals}f}"
    except (ValueError, TypeError):
        return str(val)
 
 
# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Quick test with dummy digest
    test_digest = {
        "src_ip": "10.34.0.29", "src_port": 12345,
        "dst_ip": "10.34.0.28", "dst_port": 80,
        "proto": "TCP",
        "total_packets": 6, "total_bytes": 360,
        "packet_rate (per second)": 100.0,
        "byte_rate (byte per second)": 6000.0,
        "flow_completion_time (second)": 0.06,
        "avg_packet_interval (second)": 0.01,
        "avg_packet_size (byte)": 60.0,
        "max_packet_size (byte)": 74.0,
        "syn_flag_count": 6, "ack_flag_count": 0,
        "rst_flag_count": 0, "fin_flag_count": 0,
        "packet_info": [],
        "yatc_label": "SYN", "yatc_score": 0.94,
    }
    print(build_prompt(test_digest))
