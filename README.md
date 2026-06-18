# ShieldGPT DDoS Mitigation — Master's Thesis

**"Towards LLM-Assisted Automated DDoS Mitigation"**
Sebastian Klupsch, 2026

This repository contains all code and configuration for the master's thesis implementation of an LLM-assisted automated DDoS mitigation system using Snort 3, YaTC, and GPT-4o.

---

## System Overview

```
CIC-DDoS2019 Dataset
        ↓
Dataset Preparation (merge → cut → split → pcap2img)
        ↓
YaTC Pre-training + Fine-tuning (classifier/)
        ↓
┌─────────────────────────────────────────────────────┐
│                  Online Pipeline                    │
│  tcpreplay → Snort 3 (klusids)                      │
│  scapy.sniff() → YaTC → GPT-4o → Snort Rule         │
│  rule_extractor → rule_validator → rule_deployer    │
└─────────────────────────────────────────────────────┘
        ↓
Evaluation (Scenario 1: Human-written Rules vs
            Scenario 2: LLM-generated Rules)
```

---

## Repository Structure

```
shieldgpt-ddos-thesis/
├── pcap_tool/              C++ tool for splitting PCAPs into per-flow PCAPs
├── dataset_preparation/    Scripts for preparing the CIC-DDoS2019 dataset
├── classifier/             YaTC pre-training and fine-tuning
├── pipeline/               Online LLM mitigation pipeline
├── offline/                Offline LLM evaluation scripts
├── evaluation/             Scenario 1 and 2 evaluation scripts
└── snort/                  Snort 3 rule files
```

---

## Infrastructure

| Host | IP | Role |
|---|---|---|
| klusids | 10.34.0.28 | IDS-VM: Snort 3 IPS, SSH Port 2222 |
| kllums | 10.34.0.29 | GPU-VM: YaTC, Pipeline, tcpreplay, SSH Port 2222 |

---

## Requirements

```bash
pip install scapy openai pandas tqdm torch timm
apt install snort tcpreplay tcprewrite libpcap-dev libboost-program-options-dev
```

Python dependencies are listed in `requirements.txt`.

---

## Quick Start

### 1. Build the PCAP splitter

```bash
cd pcap_tool
bash compile.sh
```

### 2. Prepare the dataset

See `dataset_preparation/README.md` for full instructions.

### 3. Pre-train YaTC

```bash
cd classifier
bash run_pretrain_yatc.sh
```

### 4. Fine-tune YaTC

```bash
bash run_finetune_yatc.sh
```

### 4. Run Scenario 1 (Human-written Rules)
```bash
# On klusids: start Snort
sudo /usr/local/bin/snort -c /usr/local/etc/snort/snort.lua \
    --daq afpacket --daq-dir /usr/local/lib/daq \
    --plugin-path /usr/local/lib/snort \
    -i ens160 -Q -A alert_fast -l /var/log/snort

# On kllums: replay traffic
sudo tcpreplay -i ens160 --topspeed \
    /usr/ShieldGPT/datasets/cic-ddos2019/pcap/attack_clean/SYN.pcap

# Evaluate
python evaluation/eval_scenario1.py \
    --alert_log /var/log/snort/alert_fast.txt \
    --category Syn \
    --output /usr/ShieldGPT/output/eval_scenario1_Syn.json \
    --ssh
```

### 5. Run Scenario 2 (LLM-generated Rules)
```bash
# On klusids: start Snort
sudo /usr/local/bin/snort -c /usr/local/etc/snort/snort.lua \
    --daq afpacket --daq-dir /usr/local/lib/daq \
    --plugin-path /usr/local/lib/snort \
    -i ens160 -Q -A alert_fast -l /var/log/snort

# On kllums: start pipeline (example for SYN category)
sudo -E LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH \
    /usr/shieldgpt-yatc-env/bin/python3 /usr/ShieldGPT/chat/pipeline.py \
    --mode online \
    --category Syn \
    --duration 200 \
    --pkt_limit 6 \
    --threshold 0.85

# Evaluate
python evaluation/eval_scenario2_offline.py \
    --alert_log /var/log/snort/alert_fast.txt \
    --category Syn \
    --output /usr/ShieldGPT/output/eval_scenario2_offline_Syn.json \
    --ssh
```
## Modifications vs Original ShieldGPT

- `pipeline.py`: single entrypoint, scapy.sniff(), YaTC-only trigger, Snort-only rules
- `yatc_online.py`: reduced to classify_flow(), checkpoint-20.pth, nb_classes=7
- `prompt_builder.py`: accepts digest dict, Snort-only prompt
- `rule_extractor.py`: returns snort_rules list directly
- `rule_validator.py`: Snort-only validation
- `rule_deployer.py`: Snort-only deployment via SSH
- `attack_descriptions.py`: Snort-only SYSTEM_PROMPT
- `classifier/fine-tune.py`: batch_size 64→256, epochs 100→20, nb_classes=7
- `pcap_tool/pcap_split/main.cpp`: LRU fix, null pointer fix, immediate writer close

---

## Dataset

CIC-DDoS2019 — see `dataset_preparation/README.md`

Original dataset: https://www.unb.ca/cic/datasets/ddos-2019.html

---

## License

MIT License — see LICENSE
