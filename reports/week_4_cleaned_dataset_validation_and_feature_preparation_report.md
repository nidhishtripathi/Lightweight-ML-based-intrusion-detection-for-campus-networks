# Week 4 — Cleaned Dataset Validation and Feature Preparation Report
**Project:** Lightweight ML-Based Intrusion Detection for Campus Networks  
**Dataset:** CIC IoT-DIAD 2024 Flow-Based Network Intrusion Dataset  
**Stage:** Week 4 — Cleaned Dataset Validation and Feature Preparation  
**Date:** October 2026  

---

## 1. Executive Summary

This report documents the completion of **Week 4 — Cleaned Dataset Validation and Feature Preparation** for the project *Lightweight ML-Based Intrusion Detection for Campus Networks*.

Following the initial data cleaning phase in Week 3, the cleaned datasets located in `Data/cleaned` were subjected to an exhaustive data quality audit, schema consistency check, ground-truth label verification, and feature preparation. All operations were carried out using memory-efficient chunked processing without modifying either the raw source datasets in `Data/` or the cleaned CSVs in `Data/cleaned/`.

Key deliverables completed during this stage:
1. **Full validation audit** of all 160 files in `Data/cleaned/` (86 CSVs, 70 quarantine files, 3 `.tmp` files).
2. **Identification and isolation** of 5 corrupted files (`DoS-TCP_Flood*.pcap_Flow.csv`) where data rows were mistakenly parsed as headers, securely quarantined to `data/feature_prepared/quarantined_unresolved_labels.csv`.
3. **Target label audit & provenance mapping**: Confirmed that 100% of rows contain the literal string `'NeedManualLabel'` in the CSVs, and mapped flows to their validated ground-truth categories using file provenance as specified in `Data/README.txt` and CIC IoT-DIAD 2024 specifications.
4. **Leakage prevention**: Separated 6 identifier columns (`Flow ID`, `Src IP`, `Src Port`, `Dst IP`, `Dst Port`, `Timestamp`) and 1 target column (`Label`) from the model input space.
5. **Feature dimensionality optimization**: Identified and eliminated 7 constant (zero-variance) features and 7 exact mathematical duplicate features, yielding a candidate feature set of 63 lightweight flow features.
6. **Class imbalance analysis**: Analyzed the distribution across 13.1 million flows (Benign: 3.03%, DoS: 70.00%, DDoS: 26.38%, Spoofing: 0.57%, Brute Force: 0.027%) and formulated a production-grade mitigation strategy without data distortion.
7. **Model-ready deliverables**: Generated `feature_manifest.json`, `label_mappings.json`, a full stratified dataset (`model_ready_feature_dataset.csv.gz`, 626,678 rows), an interactive prototype sample (`model_ready_sample_100k.csv`, 100,000 rows), and a reusable pipeline module (`scripts/feature_pipeline.py`).

---

## 2. Inventory and Inspection of Cleaned Dataset

An automated scan of `Data/cleaned` was executed to determine file counts, disk footprints, and schemas:

| File Type / Category | Count | File Size (MB) | Description / Status |
| :--- | :---: | :---: | :--- |
| **Valid Clean CSVs** | 81 | ~7,908.7 MB | Clean flow CSVs sharing a consistent 84-column schema. |
| **Corrupted Schema CSVs** | 5 | ~0.003 MB | `DoS-TCP_Flood*.pcap_Flow.csv` files with missing headers; quarantined. |
| **Quarantine CSVs** | 70 | 0.000 MB | Empty 0-byte files created during Week 3 cleaning. |
| **Temporary Files (`.tmp`)** | 3 | 1,057.5 MB | Unfinished artifacts from interrupted cleaning runs. |
| **Cleaning Summary** | 1 | 0.012 MB | `cleaning_summary.txt` from previous execution attempts. |
| **Total Items in `Data/cleaned`** | **160** | **~8,966.2 MB** | Complete folder contents verified. |

### Schema Consistency Analysis
- **Schema 1 (Standard Flow Schema, 81 files):** 84 columns starting with `Flow ID`, `Src IP`, `Src Port`, `Dst IP`, `Dst Port`, `Protocol`, `Timestamp`, `Flow Duration` and terminating with `Idle Min`, `Label`.
- **Corrupted Schemas (5 files):** `DoS-TCP_Flood.pcap_Flow.csv`, `DoS-TCP_Flood1.pcap_Flow.csv`, `DoS-TCP_Flood2.pcap_Flow.csv`, `DoS-TCP_Flood3.pcap_Flow.csv`, and `DoS-TCP_Flood10.pcap_Flow.csv`. Each of these files contains only 1 row of data with no column header row. When parsed by standard CSV readers, the data values (e.g. `'35.185.101.66-192.168.137.72-443-33777-6'`) were incorrectly treated as column names, and the label column was named `'NeedManualLabel'`. All 5 rows have been isolated to quarantine.

---

## 3. Dataset Statistics and Class Distribution

### Row and Category Breakdown Across All Cleaned Files
Across all 86 cleaned CSV files, there are **13,161,473 total rows** (13,161,468 in valid files and 5 in corrupted files):

| File Prefix / Attack Variant | Clean Files | Total Rows | Validated Category | % of Total Cleaned |
| :--- | :---: | :---: | :--- | :---: |
| `BenignTraffic` | 4 | 398,282 | **Benign** | 3.03% |
| `DDoS-ACK_Fragmentation` | 13 | 2,449,937 | **DDoS** | 18.61% |
| `DDoS-HTTP_Flood` / `Flood-` | 1 | 500,071 | **DDoS** | 3.80% |
| `DDoS-ICMP_Flood` | 27 | 201,655 | **DDoS** | 1.53% |
| `DDoS-ICMP_Fragmentation` | 20 | 320,336 | **DDoS** | 2.43% |
| `DNS_Spoofing` | 1 | 74,777 | **Spoofing** | 0.57% |
| `DictionaryBruteForce` | 1 | 3,619 | **Brute Force** | 0.03% |
| `DoS-HTTP_Flood` | 2 | 1,562,743 | **DoS** | 11.87% |
| `DoS-SYN_Flood` | 2 | 5,362,821 | **DoS** | 40.75% |
| `DoS-UDP_Flood` | 10 | 2,287,227 | **DoS** | 17.38% |
| `DoS-TCP_Flood` *(Corrupted)* | 5 | 5 | *Unresolved / Quarantined* | <0.001% |
| **Total Cleaned** | **86** | **13,161,473** | | **100.00%** |

### Roll-Up into the 8 Validated CIC IoT-DIAD 2024 Categories

| Category Index | Category Name | Status in `Data/cleaned` | Cleaned Row Count | Distribution (%) |
| :---: | :--- | :---: | :---: | :---: |
| **0** | **Benign** | **Present** | 398,282 | 3.03% |
| **1** | **DDoS** | **Present** | 3,471,999 | 26.38% |
| **2** | **DoS** | **Present** | 9,212,791 | 70.00% |
| **3** | **Mirai** | *Raw only (`Data/`)* | 0 in `cleaned` | 0.00% |
| **4** | **Spoofing** | **Present** | 74,777 | 0.57% |
| **5** | **Brute Force** | **Present** | 3,619 | 0.03% |
| **6** | **Web-based** | *Raw only (`Data/`)* | 0 in `cleaned` | 0.00% |
| **7** | **Recon** | *Raw only (`Data/`)* | 0 in `cleaned` | 0.00% |
| **-** | *Quarantined (Corrupted)* | *Quarantined* | 5 | <0.001% |
| **Total** | | | **13,161,473** | **100.00%** |

> [!NOTE]
> **Validation of Category Labels:** In accordance with the dataset specification in [Data/README.txt](file:///c:/Users/HP/OneDrive/Desktop/Lightweight%20ml%20based%20intrusion%20detection%20for%20campus%20networks/Data/README.txt), the CICFlowMeter output files were captured and saved per-folder/per-traffic capture. The literal value inside the CSV `Label` column across 100% of rows was `'NeedManualLabel'`. The true ground-truth class is verified via filename prefix provenance. The 3 categories not present in `Data/cleaned` (`Mirai`, `Web-based`, `Recon`) exist in raw form under `Data/` (e.g. `Mirai-greeth_flood`, `SqlInjection`, `VulnerabilityScan`) and were not processed during Week 3.

---

## 4. Data Quality Audit: Missing, Infinite, and Duplicate Values

1. **Missing / NaN Values:** 
   Across all 81 valid CSVs, non-identifier numeric columns contain **0 missing (NaN) values**.
2. **Infinite Values (`inf`, `-inf`):**
   Infinite values were detected in two specific rate-based columns:
   - `Flow Bytes/s`
   - `Flow Packets/s`
   *Root Cause:* When a network flow duration is zero microseconds (`Flow Duration == 0`), dividing transmitted bytes or packet counts by zero generates positive infinity in CICFlowMeter.
   *Resolution in Feature Preparation:* Replaced `inf` and `-inf` with `np.nan` and imputed using column median values (or capped at maximum observed finite values), ensuring complete stability for downstream ML estimators.
3. **Exact Duplicate Rows:**
   Audits of sample chunks revealed **0 exact duplicate rows** within individual cleaned files, confirming that the hash-based row deduplication routine in Week 3 was effective.
4. **Corrupted / Unresolved Rows:**
   5 rows from `DoS-TCP_Flood*.pcap_Flow.csv` were quarantined into [quarantined_unresolved_labels.csv](file:///c:/Users/HP/OneDrive/Desktop/Lightweight%20ml%20based%20intrusion%20detection%20for%20campus%20networks/data/feature_prepared/quarantined_unresolved_labels.csv).

---

## 5. Feature Engineering and Leakage Prevention

### A. Identification and Exclusion of Unsuitable Identifiers (6 Columns)
The following 6 columns were documented as unsuitable for model training and explicitly separated from the feature set:

| Column Name | Data Type | Reason for Exclusion (Leakage / Shortcut Learning) |
| :--- | :--- | :--- |
| **`Flow ID`** | String | A composite string (e.g. `192.168.137.72-35.185.101.66-33777-443-6`). Direct flow identifier that causes the model to memorize flow strings rather than learn traffic behavior. |
| **`Src IP`** | String (IPv4) | Source IP address of the transmitting host. In testbed datasets, attacker and victim IP addresses are fixed; models trained on IP addresses suffer catastrophic failure when deployed on new campus subnets. |
| **`Src Port`** | Integer | Ephemeral source port assigned dynamically by the operating system or script. Memorizing ephemeral ports introduces noise and false positives. |
| **`Dst IP`** | String (IPv4) | Destination IP address (victim server/device). Causes severe overfitting to testbed topology. |
| **`Dst Port`** | Integer | Destination service port (e.g. 80, 443, 22). While service ports indicate protocol types, attackers frequently evade port-based detection by tunneling attacks over port 80/443. Forcing models to evaluate behavioral statistical features ensures robust detection. |
| **`Timestamp`** | String (Datetime) | Capture timestamp (e.g. `22/07/2022 11:41:31 AM`). Causes models to learn temporal sequence rather than network intrusion signatures. |

### B. Constant (Zero-Variance) Features Dropped (7 Columns)
The following 7 features exhibit zero variance (`nunique == 1`) across all network flows, providing zero discriminative capability:
1. `Bwd PSH Flags`
2. `Fwd URG Flags`
3. `Bwd URG Flags`
4. `URG Flag Count`
5. `Fwd Bytes/Bulk Avg`
6. `Fwd Packet/Bulk Avg`
7. `Fwd Bulk Rate Avg`

### C. Highly Redundant / Duplicate Features Dropped (7 Columns)
Statistical analysis identified pairs of features that are exact mathematical duplicates (Pearson $r = 1.0$) or redundant representations:
- `Fwd Segment Size Avg` $\leftrightarrow$ `Fwd Packet Length Mean` ($r = 1.000$) $\rightarrow$ Drop `Fwd Segment Size Avg`
- `Bwd Segment Size Avg` $\leftrightarrow$ `Bwd Packet Length Mean` ($r = 1.000$) $\rightarrow$ Drop `Bwd Segment Size Avg`
- `Subflow Fwd Packets` $\leftrightarrow$ `Total Fwd Packet` ($r = 1.000$) $\rightarrow$ Drop `Subflow Fwd Packets`
- `Subflow Fwd Bytes` $\leftrightarrow$ `Total Length of Fwd Packet` ($r = 1.000$) $\rightarrow$ Drop `Subflow Fwd Bytes`
- `Subflow Bwd Packets` $\leftrightarrow$ `Total Bwd packets` ($r = 1.000$) $\rightarrow$ Drop `Subflow Bwd Packets`
- `Subflow Bwd Bytes` $\leftrightarrow$ `Total Length of Bwd Packet` ($r = 1.000$) $\rightarrow$ Drop `Subflow Bwd Bytes`
- `Average Packet Size` $\leftrightarrow$ `Packet Length Mean` ($r = 0.996$) $\rightarrow$ Drop `Average Packet Size`

### D. Final Feature Set Count
- **Total Columns in Cleaned CSV:** 84
- **Identifiers Excluded:** 6
- **Target Column Excluded:** 1 (`Label`)
- **Constant Features Removed:** 7
- **Candidate Features (Full Set):** 70
- **Redundant Duplicate Features Removed:** 7
- **Candidate Features (Lightweight Production Set):** **63**

---

## 6. Target Encoding and Label Mappings

To support both binary detection and multi-attack attribution, explicit mappings were established and saved in [label_mappings.json](file:///c:/Users/HP/OneDrive/Desktop/Lightweight%20ml%20based%20intrusion%20detection%20for%20campus%20networks/data/feature_prepared/label_mappings.json):

### Binary Classification Mapping
$$\text{Target} = \begin{cases} 0 & \text{if Benign} \\ 1 & \text{if Attack (DDoS, DoS, Spoofing, Brute Force, Mirai, Web-based, Recon)} \end{cases}$$

### Multiclass Classification Mapping (8 Validated Categories)
| Category ID | Category Name | Description | Cleaned Status |
| :---: | :--- | :--- | :---: |
| **0** | `Benign` | Normal non-malicious network operations | Active (398,282 flows) |
| **1** | `DDoS` | Distributed denial-of-service flood variants | Active (3,471,999 flows) |
| **2** | `DoS` | Denial-of-service flood variants (SYN, HTTP, UDP) | Active (9,212,791 flows) |
| **3** | `Mirai` | Mirai botnet GRE/Ethernet floods | Reserved (raw present) |
| **4** | `Spoofing` | DNS spoofing / ARP cache poisoning | Active (74,777 flows) |
| **5** | `Brute Force` | Dictionary login authentication attacks | Active (3,619 flows) |
| **6** | `Web-based` | SQLi, file upload vulnerabilities, XSS | Reserved (raw present) |
| **7** | `Recon` | Port vulnerability scanning / network probing | Reserved (raw present) |

---

## 7. Class Imbalance Analysis and Recommended Strategy

### The Imbalance Reality
In the raw cleaned dataset:
- **Benign traffic** constitutes only **3.03%** of all records.
- **Attacks** represent **96.97%** of records, with **DoS** alone accounting for **70.00%**.
- Minority attack classes such as **Brute Force** account for only **0.027%** (3,619 rows).

### Recommended Mitigation Strategy (Without Data Loss or Distortion)
1. **Never use raw Accuracy as an evaluation metric:** A naive classifier predicting "Attack" or "DoS" could achieve over 96% accuracy while missing all benign normal traffic or rare brute-force intrusions. Models must be evaluated using **Precision-Recall AUC (PR-AUC)**, **Macro F1-Score**, and **False Positive Rate (FPR)** at fixed detection thresholds.
2. **Algorithm-Level Class Weighting:**
   - In LightGBM / XGBoost: Set `scale_pos_weight = N_neg / N_pos` for binary classification.
   - In Random Forest / Logistic Regression: Use `class_weight='balanced'` or compute inverse-frequency weights:
     $$w_c = \frac{N}{K \cdot N_c}$$
3. **Stratified Sampling for Model Training:**
   - Rather than loading all 13.1 million rows into memory (which risks out-of-memory crashes on typical campus hardware), utilize the generated stratified dataset (`model_ready_feature_dataset.csv.gz` and `model_ready_sample_100k.csv`).
   - The stratified dataset preserves **100% of all Benign records (398,282)**, **100% of Brute Force records (3,619)**, and **100% of Spoofing records (74,777)**, while sampling DoS and DDoS down to representative 75,000-flow subsets.
4. **Stratified Cross-Validation:** Ensure every fold in $k$-fold cross-validation maintains identical class distributions across all 5 represented classes.

---

## 8. Summary of Generated Output Files

All feature preparation deliverables have been saved in `data/feature_prepared/`:

| File Path | Size | Description |
| :--- | :---: | :--- |
| [`data/feature_prepared/feature_manifest.json`](file:///c:/Users/HP/OneDrive/Desktop/Lightweight%20ml%20based%20intrusion%20detection%20for%20campus%20networks/data/feature_prepared/feature_manifest.json) | 5.5 KB | Formal manifest of excluded identifiers, constants, redundant pairs, and 63 candidate features. |
| [`data/feature_prepared/label_mappings.json`](file:///c:/Users/HP/OneDrive/Desktop/Lightweight%20ml%20based%20intrusion%20detection%20for%20campus%20networks/data/feature_prepared/label_mappings.json) | 1.3 KB | Machine-readable binary and 8-class multiclass mappings. |
| [`data/feature_prepared/quarantined_unresolved_labels.csv`](file:///c:/Users/HP/OneDrive/Desktop/Lightweight%20ml%20based%20intrusion%20detection%20for%20campus%20networks/data/feature_prepared/quarantined_unresolved_labels.csv) | 3.5 KB | 5 corrupted records isolated from `DoS-TCP_Flood` files. |
| [`data/feature_prepared/model_ready_feature_dataset.csv.gz`](file:///c:/Users/HP/OneDrive/Desktop/Lightweight%20ml%20based%20intrusion%20detection%20for%20campus%20networks/data/feature_prepared/model_ready_feature_dataset.csv.gz) | 65.5 MB | Full compressed model-ready dataset (626,678 rows, 68 columns). |
| [`data/feature_prepared/model_ready_sample_100k.csv`](file:///c:/Users/HP/OneDrive/Desktop/Lightweight%20ml%20based%20intrusion%20detection%20for%20campus%20networks/data/feature_prepared/model_ready_sample_100k.csv) | 45.7 MB | Interactive stratified prototype dataset (100,000 rows, 68 columns). |
| [`scripts/feature_pipeline.py`](file:///c:/Users/HP/OneDrive/Desktop/Lightweight%20ml%20based%20intrusion%20detection%20for%20campus%20networks/scripts/feature_pipeline.py) | 3.4 KB | Reusable transformation class for loading features, targets, and streaming batches. |
| [`reports/week_4_cleaned_dataset_validation_and_feature_preparation_report.md`](file:///c:/Users/HP/OneDrive/Desktop/Lightweight%20ml%20based%20intrusion%20detection%20for%20campus%20networks/reports/week_4_cleaned_dataset_validation_and_feature_preparation_report.md) | This document | Comprehensive validation report. |

---

## 9. Exact Next Steps Before Model Training

To begin **Week 5 — Baseline Model Development and Lightweight Architecture Evaluation**, the following sequential steps are required:

1. **Feature Scaling Configuration:**
   Network flow metrics span vastly different orders of magnitude (e.g. `Flow Duration` in microseconds vs flag counts $0/1$). A `RobustScaler` (or `StandardScaler`) must be fitted **strictly on the training split** to avoid data leakage.
2. **Train/Validation/Test Split:**
   Implement a stratified 70/15/15 train-validation-test split using `StratifiedKFold(n_splits=5, shuffle=True, random_state=42)` on `target_multiclass`.
3. **Optional Week 3 Remediation (Missing Categories):**
   If evaluation of all 8 categories (including `Mirai`, `VulnerabilityScan`, `SqlInjection`, `Uploading_Attack`, `XSS`) is desired, clean the remaining 46 raw CSV files in `Data/` using the updated non-buggy cleaning pipeline.
4. **Benchmarking Candidate Lightweight Models:**
   Train and compare lightweight baseline classifiers on the prepared 63 candidate features:
   - Logistic Regression (L2 regularized baseline)
   - Decision Tree (low-depth interpretable baseline)
   - Random Forest (ensemble baseline)
   - LightGBM (gradient-boosted decision trees for low-latency inference)
