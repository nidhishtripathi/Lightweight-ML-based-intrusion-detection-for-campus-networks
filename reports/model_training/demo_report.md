# Demo Model Training Report

**Date:** 2026-10-30

## Dataset Snapshot
- Rows used: 10000
- Feature columns: 63

## Model Comparison (Binary Classification)
| Model | Accuracy | Precision | Recall | Macro F1 | False Positive Rate | Inference Time (ms) |
|------|----------|-----------|--------|----------|--------------------|---------------------|
| LogisticRegression | 0.8560 | 0.9500 | 0.7741 | 0.8531 | 0.0478 | 2.4 |
| LinearSVM | 0.8565 | 0.9573 | 0.7685 | 0.8526 | 0.0402 | 1.9 |
| RandomForest | 0.8985 | 0.9188 | 0.8907 | 0.9046 | 0.0924 | 16.5 |

---
*Models saved in `models/demo/`.*
