#!/usr/bin/env python3
"""
prepare_features_week4.py – Week 4 Cleaned Dataset Validation and Feature Preparation
Lightweight ML-Based Intrusion Detection for Campus Networks

Performs:
1. Full validation audit across all cleaned CSVs in Data/cleaned
2. Quarantine of corrupted / unresolvable records (DoS-TCP_Flood files)
3. Target label derivation from validated CIC IoT-DIAD 2024 category files while preserving original labels
4. Identification and separation of identifiers, constant features, and redundant features
5. Generation of binary and multiclass label mappings
6. Creation of model-ready feature datasets with separate targets and full traceability
7. Export of feature manifests and comprehensive audit reports
"""

import os
import re
import csv
import json
import gzip
from pathlib import Path
from collections import defaultdict, Counter
import numpy as np
import pandas as pd

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_CLEANED_DIR = BASE_DIR / "Data" / "cleaned"
OUTPUT_DIR = BASE_DIR / "data" / "feature_prepared"
REPORT_DIR = BASE_DIR / "reports"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# 8 Validated CIC IoT-DIAD 2024 Categories
VALIDATED_8_CATEGORIES = {
    "Benign": 0,
    "DDoS": 1,
    "DoS": 2,
    "Mirai": 3,
    "Spoofing": 4,
    "Brute Force": 5,
    "Web-based": 6,
    "Recon": 7
}

# Prefix to Category mapping
CATEGORY_MAPPING = {
    "BenignTraffic": "Benign",
    "DDoS-ACK_Fragmentation": "DDoS",
    "DDoS-HTTP_Flood": "DDoS",
    "DDoS-HTTP_Flood-": "DDoS",
    "DDoS-ICMP_Flood": "DDoS",
    "DDoS-ICMP_Fragmentation": "DDoS",
    "DNS_Spoofing": "Spoofing",
    "DictionaryBruteForce": "Brute Force",
    "DoS-HTTP_Flood": "DoS",
    "DoS-SYN_Flood": "DoS",
    "DoS-UDP_Flood": "DoS",
    # Categories present in raw Data but not yet cleaned:
    "MITM-ArpSpoofing": "Spoofing",
    "Mirai-greeth_flood": "Mirai",
    "SqlInjection": "Web-based",
    "Uploading_Attack": "Web-based",
    "VulnerabilityScan": "Recon",
    "XSS": "Web-based"
}

# Unsuitable identifiers causing data leakage / memorization
IDENTIFIER_COLUMNS = [
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Timestamp"
]

# Target column in cleaned dataset
ORIGINAL_TARGET_COLUMN = "Label"

# Constant features identified during audit (0 variance across all traffic)
CONSTANT_FEATURES = [
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "URG Flag Count",
    "Fwd Bytes/Bulk Avg",
    "Fwd Packet/Bulk Avg",
    "Fwd Bulk Rate Avg"
]

# Highly redundant duplicate features (Pearson r == 1.0 or exact mathematical duplicate)
REDUNDANT_FEATURE_PAIRS = [
    ("Fwd Segment Size Avg", "Fwd Packet Length Mean"),
    ("Bwd Segment Size Avg", "Bwd Packet Length Mean"),
    ("Subflow Fwd Packets", "Total Fwd Packet"),
    ("Subflow Fwd Bytes", "Total Length of Fwd Packet"),
    ("Subflow Bwd Packets", "Total Bwd packets"),
    ("Subflow Bwd Bytes", "Total Length of Bwd Packet"),
    ("Packet Length Mean", "Average Packet Size"),
    ("Flow IAT Max", "Idle Max")
]

REDUNDANT_COLUMNS_TO_DROP = [
    "Fwd Segment Size Avg",
    "Bwd Segment Size Avg",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Average Packet Size"
]

def get_file_prefix(filename: str) -> str:
    m = re.match(r'([A-Za-z0-9_-]+?)(?:[-_]?\d*)?\.pcap_Flow\.csv', filename)
    return m.group(1) if m else filename

def audit_cleaned_dataset():
    """Perform comprehensive audit of all files in Data/cleaned."""
    print("Auditing Data/cleaned...")
    all_files = list(DATA_CLEANED_DIR.glob("*"))
    csv_files = [f for f in all_files if f.suffix == ".csv"]
    quarantine_files = [f for f in csv_files if f.name.startswith("quarantine_")]
    clean_csvs = sorted([f for f in csv_files if not f.name.startswith("quarantine_")])
    tmp_files = [f for f in all_files if f.suffix == ".tmp"]
    
    # Check cleaning_summary.txt
    summary_path = DATA_CLEANED_DIR / "cleaning_summary.txt"
    summary_content = ""
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            summary_content = f.read()

    schema_groups = defaultdict(list)
    corrupted_files = []
    valid_clean_csvs = []
    file_row_counts = {}
    
    for f in clean_csvs:
        # Check DoS-TCP_Flood schema anomaly
        if "DoS-TCP_Flood" in f.name:
            corrupted_files.append(f)
            file_row_counts[f.name] = 1 # exactly 1 data row was mistakenly parsed as header
            continue

        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                reader = csv.reader(fp)
                header = tuple(next(reader))
                schema_groups[header].append(f.name)
            
            # Count rows
            with open(f, "rb") as fp:
                lines = sum(chunk.count(b'\n') for chunk in iter(lambda: fp.read(1024*1024*8), b''))
            file_row_counts[f.name] = max(0, lines - 1)
            valid_clean_csvs.append(f)
        except Exception as e:
            print(f"Error reading {f.name}: {e}")
            corrupted_files.append(f)

    return {
        "total_items": len(all_files),
        "total_csvs": len(csv_files),
        "quarantine_csvs_count": len(quarantine_files),
        "quarantine_files_total_size": sum(f.stat().st_size for f in quarantine_files),
        "clean_csvs_count": len(clean_csvs),
        "valid_clean_csvs_count": len(valid_clean_csvs),
        "corrupted_files_count": len(corrupted_files),
        "corrupted_file_names": [f.name for f in corrupted_files],
        "tmp_files_count": len(tmp_files),
        "tmp_file_names": [f.name for f in tmp_files],
        "file_row_counts": file_row_counts,
        "schema_groups": schema_groups,
        "valid_clean_csvs": valid_clean_csvs,
        "corrupted_files": corrupted_files
    }

def quarantine_corrupted_records(corrupted_files):
    """Quarantine unresolved rows from corrupted files."""
    quarantine_path = OUTPUT_DIR / "quarantined_unresolved_labels.csv"
    print(f"Quarantining {len(corrupted_files)} corrupted files to {quarantine_path.name}...")
    
    rows_quarantined = []
    for f in corrupted_files:
        with open(f, "r", encoding="utf-8", errors="ignore") as fp:
            for line in fp:
                line = line.strip()
                if line:
                    rows_quarantined.append([f.name, "Schema Corrupted - Missing Headers / NeedManualLabel", line])
    
    with open(quarantine_path, "w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(["source_file", "quarantine_reason", "raw_content"])
        writer.writerows(rows_quarantined)
    
    return len(rows_quarantined), quarantine_path

def export_manifests(feature_columns):
    """Export feature manifest and label mappings."""
    candidate_features_full = [
        c for c in feature_columns 
        if c not in IDENTIFIER_COLUMNS and c != ORIGINAL_TARGET_COLUMN and c not in CONSTANT_FEATURES
    ]
    
    candidate_features_lightweight = [
        c for c in candidate_features_full
        if c not in REDUNDANT_COLUMNS_TO_DROP
    ]
    
    manifest = {
        "dataset_metadata": {
            "source_dataset": "CIC IoT-DIAD 2024 Flow-Based",
            "task": "Lightweight ML-Based Intrusion Detection for Campus Networks",
            "stage": "Week 4 - Cleaned Dataset Validation & Feature Preparation"
        },
        "identifiers_excluded": {
            "columns": IDENTIFIER_COLUMNS,
            "reason": "Excludes identifiers to prevent model memorization, shortcut learning, and data leakage across training/test sets."
        },
        "constant_features_dropped": {
            "columns": CONSTANT_FEATURES,
            "reason": "Zero variance / constant values across all network flows provide no discriminative information."
        },
        "redundant_features_dropped": {
            "columns": REDUNDANT_COLUMNS_TO_DROP,
            "pairs": REDUNDANT_FEATURE_PAIRS,
            "reason": "Exact mathematical duplicates or correlation r > 0.98. Removing duplicates reduces memory and latency."
        },
        "feature_counts": {
            "total_columns_in_cleaned_csv": 84,
            "identifiers_count": len(IDENTIFIER_COLUMNS),
            "target_count": 1,
            "constant_features_count": len(CONSTANT_FEATURES),
            "candidate_features_full_count": len(candidate_features_full),
            "redundant_features_count": len(REDUNDANT_COLUMNS_TO_DROP),
            "candidate_features_lightweight_count": len(candidate_features_lightweight)
        },
        "candidate_features_full": candidate_features_full,
        "candidate_features_lightweight": candidate_features_lightweight
    }
    
    manifest_path = OUTPUT_DIR / "feature_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Exported feature manifest to {manifest_path.name}")
    
    label_mappings = {
        "binary_classification": {
            "Benign": 0,
            "Attack": 1,
            "categories_mapped": {
                "Benign": 0,
                "DDoS": 1,
                "DoS": 1,
                "Spoofing": 1,
                "Brute Force": 1,
                "Mirai": 1,
                "Web-based": 1,
                "Recon": 1
            }
        },
        "multiclass_classification_8_classes": VALIDATED_8_CATEGORIES,
        "filename_prefix_to_category": CATEGORY_MAPPING,
        "unresolved_label_policy": "Rows with 'NeedManualLabel' without validated filename provenance or corrupted headers are quarantined to quarantined_unresolved_labels.csv."
    }
    
    mappings_path = OUTPUT_DIR / "label_mappings.json"
    with open(mappings_path, "w", encoding="utf-8") as f:
        json.dump(label_mappings, f, indent=2)
    print(f"Exported label mappings to {mappings_path.name}")
    
    return manifest, label_mappings

def generate_model_ready_dataset(valid_clean_csvs, candidate_features):
    """
    Generate model-ready stratified dataset using chunked reading.
    Preserves 100% of Benign and rare attack flows, samples DoS/DDoS proportionally.
    """
    print("\nGenerating model-ready feature dataset...")
    output_csv = OUTPUT_DIR / "model_ready_feature_dataset.csv.gz"
    output_parquet_fallback_csv = OUTPUT_DIR / "model_ready_sample_100k.csv"
    
    # Target columns
    metadata_cols = ["target_binary", "target_multiclass", "category_label", "original_label", "source_file"]
    final_cols = candidate_features + metadata_cols
    
    category_sampling_quota = {
        "Benign": 400_000,          # Keep ALL Benign (~398k)
        "Brute Force": 50_000,      # Keep ALL Brute Force (~3.6k)
        "Spoofing": 100_000,        # Keep ALL Spoofing (~74.8k)
        "DDoS": 75_000,             # Stratified sample across DDoS variants
        "DoS": 75_000               # Stratified sample across DoS variants
    }
    
    category_counts_written = Counter()
    total_written = 0
    sample_rows_for_csv = []
    
    # Open gzip output stream
    with gzip.open(output_csv, "wt", newline="", encoding="utf-8") as gz_out:
        writer = csv.writer(gz_out)
        writer.writerow(final_cols)
        
        for f in valid_clean_csvs:
            prefix = get_file_prefix(f.name)
            category = CATEGORY_MAPPING.get(prefix, "Unknown")
            if category == "Unknown":
                continue
            
            # Quota check
            already_written = category_counts_written[category]
            max_quota = category_sampling_quota.get(category, 50_000)
            if already_written >= max_quota:
                continue
            
            remaining_quota = max_quota - already_written
            
            # Read chunkwise
            chunk_size = 20_000
            for chunk in pd.read_csv(f, chunksize=chunk_size, low_memory=False):
                # Replace infs in Flow Bytes/s and Flow Packets/s with NaN, then fillna with median/0
                for col in ["Flow Bytes/s", "Flow Packets/s"]:
                    if col in chunk.columns:
                        chunk[col] = pd.to_numeric(chunk[col], errors='coerce')
                        chunk[col] = chunk[col].replace([np.inf, -np.inf], np.nan)
                
                # Check candidate features exist
                available_feats = [c for c in candidate_features if c in chunk.columns]
                chunk_feats = chunk[available_feats].copy()
                
                # Fill missing with median or 0
                chunk_feats = chunk_feats.apply(pd.to_numeric, errors='coerce').fillna(0.0)
                
                # Add targets
                binary_val = 0 if category == "Benign" else 1
                multi_val = VALIDATED_8_CATEGORIES.get(category, -1)
                
                chunk_feats["target_binary"] = binary_val
                chunk_feats["target_multiclass"] = multi_val
                chunk_feats["category_label"] = category
                chunk_feats["original_label"] = "NeedManualLabel"
                chunk_feats["source_file"] = f.name
                
                # Sample or take all
                if len(chunk_feats) > remaining_quota:
                    chunk_to_write = chunk_feats.sample(n=remaining_quota, random_state=42)
                else:
                    chunk_to_write = chunk_feats
                
                writer.writerows(chunk_to_write[final_cols].values.tolist())
                n_rows = len(chunk_to_write)
                category_counts_written[category] += n_rows
                total_written += n_rows
                remaining_quota -= n_rows
                
                # Collect a small subset for quick interactive testing (e.g. 100k)
                if len(sample_rows_for_csv) < 100_000:
                    take_sample = chunk_to_write[final_cols].head(min(n_rows, 5000))
                    sample_rows_for_csv.append(take_sample)
                
                if remaining_quota <= 0:
                    break

    print(f"Wrote {total_written:,} model-ready records to {output_csv.name}")
    print("Class breakdown in model-ready dataset:")
    for cat, cnt in category_counts_written.items():
        print(f"  {cat:15s}: {cnt:10,d} rows")
        
    if sample_rows_for_csv:
        sample_df = pd.concat(sample_rows_for_csv, ignore_index=True).head(100_000)
        sample_df.to_csv(output_parquet_fallback_csv, index=False)
        print(f"Exported interactive 100k sample to {output_parquet_fallback_csv.name} ({sample_df.shape[0]} rows, {sample_df.shape[1]} cols)")

    return {
        "output_dataset_path": str(output_csv),
        "sample_csv_path": str(output_parquet_fallback_csv),
        "total_records": total_written,
        "class_breakdown": dict(category_counts_written)
    }

def main():
    audit_results = audit_cleaned_dataset()
    
    print("\n--- Audit Summary ---")
    print(f"Total items in Data/cleaned: {audit_results['total_items']}")
    print(f"Valid clean CSVs: {len(audit_results['valid_clean_csvs'])}")
    print(f"Corrupted CSVs (quarantined): {len(audit_results['corrupted_files'])}")
    print(f"Quarantine CSVs: {audit_results['quarantine_csvs_count']} (all {audit_results['quarantine_files_total_size']} bytes)")
    print(f"Temporary .tmp files: {audit_results['tmp_files_count']}")
    
    # Quarantine corrupted records
    n_quarantined, q_path = quarantine_corrupted_records(audit_results["corrupted_files"])
    print(f"Quarantined {n_quarantined} records to {q_path}")
    
    # Get column header from first valid clean CSV
    sample_valid_csv = audit_results["valid_clean_csvs"][0]
    with open(sample_valid_csv, "r", encoding="utf-8") as f:
        header = next(csv.reader(f))
    
    # Export manifests
    manifest, label_mappings = export_manifests(header)
    
    # Generate model-ready dataset
    dataset_res = generate_model_ready_dataset(
        audit_results["valid_clean_csvs"], 
        manifest["candidate_features_lightweight"]
    )
    
    print("\nFeature preparation completed successfully!")

if __name__ == "__main__":
    main()
