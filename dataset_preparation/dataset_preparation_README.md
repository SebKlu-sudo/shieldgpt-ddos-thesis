# Dataset Preparation — CIC-DDoS2019

This folder contains all scripts to prepare the CIC-DDoS2019 dataset for YaTC training and evaluation.

---

## Step 0 — Download the Dataset

1. Go to: https://www.unb.ca/cic/datasets/ddos-2019.html
2. Download the **03-11** folder (March 11, 2019) — this contains the attack traffic used in this thesis.
3. You need two things:
   - **PCAP files**: the raw network captures
   - **CSV files**: the labeled flow features

The directory structure should look like:

```
/data/cic-ddos2019/
├── csv/
│   └── 03-11/
│       ├── LDAP.csv
│       ├── MSSQL.csv
│       ├── NetBIOS.csv
│       ├── Portmap.csv
│       ├── Syn.csv
│       ├── UDP.csv
│       └── UDPLag.csv
└── pcap/
    └── 03-11/
        ├── SAT-03-11-2018_0.pcap
        ├── SAT-03-11-2018_1.pcap
        └── ...
```

> **Note:** Only the **03-11** folder is used in this thesis. The attack categories used are: LDAP, MSSQL, NetBIOS, SYN, UDP. Portmap and UDPLag are excluded due to class imbalance (Portmap: F1=0.007) and redundancy.

---

## Pipeline Overview

```
Step 1: merge_pcap.py      — merge all raw PCAPs into one file
Step 2: cut.sh             — extract per-category PCAPs from CSV labels
Step 3: split.sh           — split per-category PCAPs into per-flow PCAPs
Step 4: pcap2img.py        — convert flow PCAPs to images for YaTC
Step 5: split_train_test.py — split flows into train/test sets
```

---

## Step 1 — Merge PCAPs

Merges all raw PCAP files from the 03-11 folder into a single file.

```bash
python merge_pcap.py \
    --input_dir /data/cic-ddos2019/pcap/03-11/ \
    --output /data/cic-ddos2019/pcap/merged.pcap
```

---

## Step 2 — Cut per-category PCAPs

Extracts per-category PCAPs from the merged PCAP using the CSV flow labels. Each category gets its own clean PCAP.

```bash
bash cut.sh
```

Output:
```
/data/cic-ddos2019/pcap/attack/
├── LDAP.pcap
├── MSSQL.pcap
├── NetBIOS.pcap
├── SYN.pcap
└── UDP.pcap
```

---

## Step 3 — Split into per-flow PCAPs

Splits each category PCAP into individual per-flow PCAPs using the `splitter` binary from `pcap_tool/`.

```bash
bash split.sh
```

> **Note:** The splitter binary must be compiled first. Run `bash pcap_tool/compile.sh` from the repo root. See `pcap_tool/README.md` for details on how the splitter works.

The splitter uses five-tuple flow identification (src_ip, dst_ip, src_port, dst_port, protocol) and limits each flow to 6 packets (`-l 6`).

Output:
```
/data/cic-ddos2019/pcap/flow_pcap_5_tuple/
├── LDAP/
│   ├── 172.16.0.5_900_17_10.34.0.28_12345.pcap
│   └── ...
├── MSSQL/
└── ...
```

---

## Step 4 — Convert to Images

Converts each per-flow PCAP into a fixed-size image (40x40 pixels) for YaTC input.

```bash
python pcap2img.py \
    --input_dir /data/cic-ddos2019/pcap/flow_pcap_5_tuple/ \
    --output_dir /data/cic-ddos2019/pcap/flow_image/
```

Output:
```
/data/cic-ddos2019/pcap/flow_image/
├── LDAP/
├── MSSQL/
├── NetBIOS/
├── SYN/
└── UDP/
```

---

## Step 5 — Train/Test Split

Splits the per-flow images into training and test sets (80/20).

```bash
python split_train_test.py \
    --input_dir /data/cic-ddos2019/pcap/flow_image/ \
    --output_dir /data/cic-ddos2019/pcap/train_test/
```

Output:
```
/data/cic-ddos2019/pcap/train_test/
├── train/
│   ├── LDAP/
│   ├── MSSQL/
│   └── ...
└── test/
    ├── LDAP/
    └── ...
```

This output is used directly by `classifier/run_finetune_yatc.sh` for YaTC fine-tuning.
