# Evaluation Preparation

This folder contains scripts to prepare clean per-category PCAPs for Scenario 1 and Scenario 2 evaluation.

---

## Overview

The CIC-DDoS2019 dataset contains merged traffic captures where multiple attack categories overlap in time. Before running the evaluation scenarios, clean per-category PCAPs must be extracted and preprocessed for replay.

```
Step 1: filter_attack_pcap.py  — extract clean per-category PCAPs from merged capture
Step 2: tcprewrite             — rewrite destination IP (and MACs if needed)
Step 3: tcpreplay              — replay traffic against klusids
```

---

## Step 1 — Extract Clean Per-Category PCAPs

Filters the merged PCAP by five-tuple matching against the labeled CSV flows to produce one clean PCAP per attack category.

```bash
python filter_attack_pcap.py \
    --csv_dir /data/cic-ddos2019/csv/03-11/ \
    --pcap_merged /data/cic-ddos2019/pcap/merged.pcap \
    --output_dir /data/cic-ddos2019/pcap/attack_clean/
```

Output:
```
/data/cic-ddos2019/pcap/attack_clean/
├── LDAP.pcap
├── MSSQL.pcap
├── NetBIOS.pcap
├── SYN.pcap
└── UDP.pcap
```

---

## Step 2 — Rewrite IP and MAC Addresses

The original PCAPs were captured in a different network environment. Before replay, the destination IP must be rewritten to match `klusids` (`10.34.0.28`) so that Snort 3 recognises the traffic as directed at `HOME_NET`.

### Case A — tcpreplay runs directly on klusids (no switch)

Only destination IP rewriting is needed — no MAC rewriting required since the traffic stays on the same host.

```bash
tcprewrite \
    --dstipmap=0.0.0.0/0:10.34.0.28 \
    --infile=/data/cic-ddos2019/pcap/attack_clean/SYN.pcap \
    --outfile=/tmp/SYN_rewritten.pcap
mv /tmp/SYN_rewritten.pcap \
    /usr/ShieldGPT/datasets/cic-ddos2019/pcap/attack_clean/SYN.pcap
```

### Case B — tcpreplay runs on kllums, traffic forwarded via switch to klusids

Both destination IP **and** MAC addresses must be rewritten. The switch uses the destination MAC to forward frames to the correct port. Without correct MACs the switch cannot resolve the destination from its CAM table and discards the frames.

```bash
tcprewrite \
    --dstipmap=0.0.0.0/0:10.34.0.28 \
    --enet-dmac=00:50:56:a5:d2:cf \
    --enet-smac=00:50:56:a5:b7:94 \
    --infile=/data/cic-ddos2019/pcap/attack_clean/SYN.pcap \
    --outfile=/tmp/SYN_rewritten.pcap
mv /tmp/SYN_rewritten.pcap \
    /usr/ShieldGPT/datasets/cic-ddos2019/pcap/attack_clean/SYN.pcap
```

| Parameter | Value | Description |
|---|---|---|
| `--dstipmap` | `0.0.0.0/0:10.34.0.28` | Rewrite all dst IPs to klusids |
| `--enet-dmac` | `00:50:56:a5:d2:cf` | klusids MAC address (ens160) |
| `--enet-smac` | `00:50:56:a5:b7:94` | kllums MAC address (ens160) |

> **Note:** Source IP addresses are preserved unchanged to maintain the original traffic characteristics (inter-arrival times, packet rates) that the pipeline relies on for feature extraction.

### All categories at once (Case B):

```bash
for cat in LDAP MSSQL NetBIOS SYN UDP; do
    echo "Rewriting $cat..."
    tcprewrite \
        --dstipmap=0.0.0.0/0:10.34.0.28 \
        --enet-dmac=00:50:56:a5:d2:cf \
        --enet-smac=00:50:56:a5:b7:94 \
        --infile=/data/cic-ddos2019/pcap/attack_clean/${cat}.pcap \
        --outfile=/tmp/${cat}_rewritten.pcap && \
    mv /tmp/${cat}_rewritten.pcap \
        /usr/ShieldGPT/datasets/cic-ddos2019/pcap/attack_clean/${cat}.pcap
    echo "$cat done"
done
```

---

## Step 3 — Replay Traffic

```bash
# On klusids or kllums depending on setup:
sudo tcpreplay -i ens160 --topspeed \
    /usr/ShieldGPT/datasets/cic-ddos2019/pcap/attack_clean/SYN.pcap
```

---

## Snort 3 Preparation

### Installation

Snort 3.12.2.0 must be installed on klusids. If not already installed, follow the official Snort 3 installation guide: https://www.snort.org/documents

### Configuration — snort.lua

Set `HOME_NET` and `EXTERNAL_NET` in `/usr/local/etc/snort/snort.lua`:

```lua
HOME_NET = '10.34.0.28/32'
EXTERNAL_NET = '!$HOME_NET'
```

Include both rule files in the `ips` section:

```lua
ips =
{
    rules = [[
        include /usr/local/etc/snort/rules/snort3-community.rules
        include /usr/local/etc/snort/rules/human_written.rules
        include /usr/local/etc/snort/rules/llm_generated.rules
    ]]
}
```

### Rule Files

Copy the rule files from the `snort/` folder in this repository to klusids:

```bash
scp -P 2222 snort/human_written.rules \
    luser@10.34.0.28:/usr/local/etc/snort/rules/human_written.rules

# llm_generated.rules starts empty — filled at runtime by rule_deployer.py
touch /usr/local/etc/snort/rules/llm_generated.rules
```

### sudoers — passwordless commands

The pipeline needs passwordless sudo on klusids for rule deployment and log access. Add to `/etc/sudoers` on klusids:

```
luser ALL=(ALL) NOPASSWD: /usr/bin/tee, /usr/bin/kill, /usr/bin/wc, /usr/bin/tail, /bin/cat, /usr/bin/truncate
```

### Start Snort

```bash
# On klusids:
sudo truncate -s 0 /var/log/snort/alert_fast.txt

sudo /usr/local/bin/snort \
    -c /usr/local/etc/snort/snort.lua \
    --daq afpacket \
    --daq-dir /usr/local/lib/daq \
    --plugin-path /usr/local/lib/snort \
    -i ens160 -Q \
    -A alert_fast \
    -l /var/log/snort
```

| Flag | Description |
|---|---|
| `-c` | Snort configuration file |
| `--daq afpacket` | Use afpacket DAQ for inline IPS mode |
| `-i ens160` | Network interface to monitor |
| `-Q` | Inline IPS mode (drop/alert on matched rules) |
| `-A alert_fast` | Fast alert format for log parsing |
| `-l /var/log/snort` | Log directory |

### Reload Rules without Restart

After `rule_deployer.py` appends new rules to `llm_generated.rules`, Snort reloads via SIGHUP:

```bash
sudo kill -SIGHUP $(cat /var/run/snort/snort.pid)
```

- Always write to a temporary file first (`/tmp/`) when `--infile` and `--outfile` would be the same path — `tcprewrite` truncates the output file while reading, corrupting the PCAP.
- File permissions: ensure the PCAP is readable by root (`chmod o+r`).
- Snort must be running in inline IPS mode (`-Q`) on klusids before replaying traffic.
