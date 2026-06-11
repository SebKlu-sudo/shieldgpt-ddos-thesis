"""
run_ddos2019.py
Submits prompts from gen_prompt_ddos2019.py to GPT-4o.
Parses responses into analysis + rules sections.
Detects Snort 3 rule validity.
Logs all evaluation metrics.
"""

import pandas as pd
import os
import time
import argparse
from openai import OpenAI
from tqdm import tqdm

from attack_descriptions import SYSTEM_PROMPT

client = OpenAI()  # uses OPENAI_API_KEY env variable


def gpt_generate(prompt: str, model: str = "gpt-4o",
                 temperature: float = 0.2,
                 max_tokens: int = 1024) -> tuple[str, float]:
    """Submit prompt to GPT-4o. Returns (response_text, latency_seconds)."""
    t0 = time.time()
    response = client.chat.completions.create(
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
    )
    latency = time.time() - t0
    return response.choices[0].message.content, latency


def extract_rules(response: str) -> dict:
    """
    Split response at ---RULES--- delimiter.
    Detect rule types: snort / iptables / sysctl / combined.
    """
    delimiter = "---RULES---"
    if delimiter in response:
        parts    = response.split(delimiter, 1)
        analysis = parts[0].strip()
        rules    = parts[1].strip()
        valid    = True
    else:
        analysis = ""
        rules    = response.strip()
        valid    = False

    # Detect rule types — Snort only
    rule_types  = []
    rules_lower = rules.lower()
    if ("alert " in rules_lower or
            "drop "    in rules_lower or
            "sid:"     in rules_lower or
            "msg:"     in rules_lower or
            "content:" in rules_lower or
            "dsize:"   in rules_lower):
        rule_types.append("snort")
    if not rule_types:
        rule_types.append("unknown")

    return {
        "analysis":  analysis,
        "rules":     rules,
        "valid":     valid,
        "rule_type": "+".join(rule_types),
    }


def run_pipeline(input_csv: str, output_dir: str, model: str = "gpt-4o"):
    """Run inference pipeline on all prompts in input_csv."""
    print(f"[INFO] Model      : {model}")
    print(f"[INFO] Input CSV  : {input_csv}")
    print(f"[INFO] Output dir : {output_dir}")

    df = pd.read_csv(input_csv)
    print(f"[INFO] Loaded {len(df)} prompts.")

    results       = []
    total_latency = 0.0

    for _, row in tqdm(df.iterrows(), total=len(df),
                       desc="Generating responses"):
        t_generate_start = time.time()
        response, latency = gpt_generate(row["prompt"], model=model)
        t_generate_end   = time.time()
        total_latency   += latency

        parsed = extract_rules(response)

        results.append({
            "prompt":           row["prompt"],
            "label":            row["label"],
            "attack_name":      row["attack_name"],
            "response":         response,
            "analysis":         parsed["analysis"],
            "rules":            parsed["rules"],
            "valid":            parsed["valid"],
            "rule_type":        parsed["rule_type"],
            "latency_s":        round(latency, 3),
            "t_generate_start": t_generate_start,
            "t_generate_end":   t_generate_end,
        })

    out_df   = pd.DataFrame(results)
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"ddos2019_responses_{model}.csv")
    out_df.to_csv(out_path, index=False)

    # Summary
    valid_count   = out_df["valid"].sum()
    invalid_count = len(out_df) - valid_count
    avg_latency   = total_latency / len(out_df)

    print(f"\n[DONE] Results saved to {out_path}")
    print(f"       Total prompts          : {len(out_df)}")
    print(f"       Valid (with ---RULES---): {valid_count}")
    print(f"       Invalid / empty        : {invalid_count}")
    print(f"       Avg LLM latency        : {avg_latency:.2f}s")
    print("\nRule type distribution:")
    print(out_df.groupby(["label", "rule_type"]).size().to_string())
    print("\nPer-attack validity:")
    print(out_df.groupby("label")["valid"].sum().to_string())

    return out_df


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_csv",
        default="/usr/ShieldGPT/output/attack_prompt_ddos2019_snort_only.csv")
    parser.add_argument("--output_dir",
        default="/usr/ShieldGPT/output")
    parser.add_argument("--model_name",
        default="gpt-4o")
    args = parser.parse_args()

    run_pipeline(args.input_csv, args.output_dir, args.model_name)
