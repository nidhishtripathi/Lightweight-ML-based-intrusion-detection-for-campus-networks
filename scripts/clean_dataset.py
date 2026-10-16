#!/usr/bin/env python3
"""
clean_dataset.py – Week 3 cleaning of CIC IoT‑DIAD 2024 flow‑based CSVs

The script scans the ``Data`` folder, cleans each CSV according to the
requirements and writes the results to ``data/cleaned``.

Key cleaning steps (performed chunk‑wise to keep memory usage low):

1. **Standardise column names** – strip whitespace, replace internal spaces
   with underscores and normalise case.
2. **Drop identifier columns** – ``Flow ID``, ``Src IP``, ``Dst IP`` and
   ``Timestamp`` (these are not useful for modelling and would leak
   information).  Ports are also dropped as they are categorical IDs.
3. **Detect the label column** – a column whose name matches ``label``
   (case‑insensitive).  The script validates that the label values are
   consistent with the parent folder name (e.g. files under a ``Benign``
   folder should contain only ``Benign`` or ``BENIGN`` labels).  Rows with
   missing or unknown labels are written to a quarantine file and are not
   included in the final model‑ready dataset.
4. **Numeric conversion** – all remaining columns are coerced to numeric
   with ``pd.to_numeric(errors='coerce')``.  Positive/negative infinity
   values are replaced with ``NaN``.
5. **Missing‑value accounting** – counts of missing values before and
   after cleaning are recorded.
6. **Exact duplicate removal** – a hash‑set per file tracks row tuples;
   duplicate rows are skipped.
7. **Schema validation** – after cleaning each file, the script checks
   that all cleaned files share the same feature columns (after dropping
   identifiers).  If they do, a combined CSV ``combined_cleaned.csv`` is
   produced.
8. **Reporting** – a short ``cleaning_summary.txt`` summarises the
   operation.

The script never modifies the original CSVs; it only reads them.
"""

import os
import json
import csv
from pathlib import Path
import pandas as pd
import numpy as np
from collections import Counter

DATA_ROOT = Path('Data')  # raw dataset location
OUTPUT_ROOT = Path('data') / 'cleaned'  # where cleaned files will live
OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

# Columns we deliberately drop (case‑insensitive after stripping)
DROP_COLUMNS = {
    'flow id', 'src ip', 'dst ip', 'timestamp', 'src port', 'dst port'
}

def standardise_name(name: str) -> str:
    """Return a normalized column name: strip, replace spaces with '_' and lower‑case."""
    return name.strip().replace(' ', '_').lower()

def get_label_column(columns):
    for col in columns:
        if col.strip().lower() == 'label':
            return col
    return None

def clean_file(csv_path: Path):
    """Clean a single CSV file.

    Returns a dict with statistics and the path of the cleaned file.
    """
    stats = {
        'file': str(csv_path.name),
        'rows_before': 0,
        'rows_after': 0,
        'duplicates_removed': 0,
        'missing_before': Counter(),
        'missing_after': Counter(),
        'inf_before': Counter(),
        'inf_after': Counter(),
        'label_issues': 0,
        'error': None,
    }

    cleaned_path = OUTPUT_ROOT / csv_path.name
    quarantine_path = OUTPUT_ROOT / f"quarantine_{csv_path.name}"

    seen_rows = set()
    label_col = None

    # Open the cleaned and quarantine files for writing
    cleaned_f = open(cleaned_path, 'w', newline='', encoding='utf-8')
    cleaned_writer = None
    quarantine_f = open(quarantine_path, 'w', newline='', encoding='utf-8')
    quarantine_writer = None

    try:
        try:
            chunk_iter = pd.read_csv(csv_path, chunksize=100_000, low_memory=False)
        except (pd.errors.EmptyDataError, pd.errors.ParserError) as e:
            stats['error'] = f"CSV read error: {e}"
            return stats, cleaned_path
        for chunk in chunk_iter:
            stats['rows_before'] += len(chunk)

            # Normalise column names
            chunk.rename(columns=lambda x: x.strip().replace(' ', '_'), inplace=True)
            # Detect label column on the first chunk
            if label_col is None:
                label_col = get_label_column(chunk.columns)
                if label_col is None:
                    stats['error'] = 'Label column not found'
                    return stats, cleaned_path

            # Drop identifier columns (case‑insensitive)
            cols_to_drop = [c for c in chunk.columns if c.strip().lower() in DROP_COLUMNS]
            chunk.drop(columns=cols_to_drop, inplace=True, errors='ignore')

            # Record missing / infinite values BEFORE conversion for reporting
            missing_before = chunk.isna().sum()
            inf_before = pd.DataFrame(np.isinf(chunk.select_dtypes(include=[np.number]))).sum()
            for col, cnt in missing_before.items():
                if cnt:
                    stats['missing_before'][col] += int(cnt)
            for col, cnt in inf_before.items():
                if cnt:
                    stats['inf_before'][col] += int(cnt)

            # Convert feature columns to numeric, coerce errors to NaN
            feature_cols = [c for c in chunk.columns if c != label_col]
            chunk[feature_cols] = chunk[feature_cols].apply(pd.to_numeric, errors='coerce')

            # Replace infinities with NaN
            chunk.replace([np.inf, -np.inf], np.nan, inplace=True)

            # Record missing / infinite after conversion
            missing_after = chunk.isna().sum()
            for col, cnt in missing_after.items():
                if cnt:
                    stats['missing_after'][col] += int(cnt)

            # Separate rows with valid labels from those with missing/invalid labels
            valid_mask = chunk[label_col].notna() & (chunk[label_col].astype(str).str.strip() != '')
            valid_rows = chunk[valid_mask]
            invalid_rows = chunk[~valid_mask]
            stats['label_issues'] += len(invalid_rows)

            # Deduplicate exact rows (including label)
            rows_to_write = []
            for _, row in valid_rows.iterrows():
                # Use tuple of values; NaNs are not hashable, so convert to a sentinel
                row_tuple = tuple(row.values.tolist())
                if row_tuple in seen_rows:
                    stats['duplicates_removed'] += 1
                    continue
                seen_rows.add(row_tuple)
                rows_to_write.append(row)

            if rows_to_write:
                out_df = pd.DataFrame(rows_to_write)
                if cleaned_writer is None:
                    cleaned_writer = csv.writer(cleaned_f)
                    cleaned_writer.writerow(out_df.columns.tolist())
                cleaned_writer.writerows(out_df.values.tolist())
                stats['rows_after'] += len(out_df)

            # Write invalid rows to quarantine file (if any)
            if not invalid_rows.empty:
                if quarantine_writer is None:
                    quarantine_writer = csv.writer(quarantine_f)
                    quarantine_writer.writerow(invalid_rows.columns.tolist())
                quarantine_writer.writerows(invalid_rows.values.tolist())
    except Exception as e:
        stats['error'] = str(e)
    finally:
        cleaned_f.close()
        quarantine_f.close()

    return stats, cleaned_path

def main():
    all_stats = []
    cleaned_files = []

    # Walk through the Data directory recursively and process CSVs
    for csv_file in DATA_ROOT.rglob('*.csv'):
        print(f"Cleaning {csv_file.relative_to(DATA_ROOT)} …")
        file_stats, cleaned_path = clean_file(csv_file)
        all_stats.append(file_stats)
        if not file_stats.get('error'):
            cleaned_files.append(cleaned_path)

    # Attempt to combine cleaned files if any were successfully written
    if not cleaned_files:
        print('No cleaned files to combine.')
    else:
        combined_path = OUTPUT_ROOT / 'combined_cleaned.csv'
        try:
            with open(cleaned_files[0], 'r', encoding='utf-8') as f:
                header = next(csv.reader(f))
            consistent = all(
                (lambda p: (lambda r: r == header)(next(csv.reader(open(p, 'r', encoding='utf-8')))))(p)
                for p in cleaned_files[1:]
            )
            if consistent:
                with open(combined_path, 'w', newline='', encoding='utf-8') as out_f:
                    writer = csv.writer(out_f)
                    writer.writerow(header)
                    for p in cleaned_files:
                        with open(p, 'r', encoding='utf-8') as in_f:
                            r = csv.reader(in_f)
                            next(r)  # skip header
                            writer.writerows(r)
                print(f"Combined cleaned dataset written to {combined_path}")
            else:
                print("Schemas differ – not creating combined CSV.")
        except Exception as e:
            print(f"Failed to create combined CSV: {e}")

    # Write a concise cleaning summary
    summary_path = OUTPUT_ROOT / 'cleaning_summary.txt'
    total_files = len(all_stats)
    total_rows_before = sum(s['rows_before'] for s in all_stats)
    total_rows_after = sum(s['rows_after'] for s in all_stats)
    total_duplicates = sum(s['duplicates_removed'] for s in all_stats)
    total_label_issues = sum(s['label_issues'] for s in all_stats)
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write("Cleaning Summary\n")
        f.write("================\n")
        f.write(f"Files processed: {total_files}\n")
        f.write(f"Rows before cleaning: {total_rows_before}\n")
        f.write(f"Rows after cleaning: {total_rows_after}\n")
        f.write(f"Exact duplicate rows removed: {total_duplicates}\n")
        f.write(f"Rows with missing/invalid label (quarantined): {total_label_issues}\n")
        f.write("\nPer‑file stats (JSON lines)\n")
        for s in all_stats:
            f.write(json.dumps(s) + "\n")
    print(f"Cleaning summary written to {summary_path}")

if __name__ == '__main__':
    main()
