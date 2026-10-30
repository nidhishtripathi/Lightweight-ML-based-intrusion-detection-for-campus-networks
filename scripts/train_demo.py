# scripts/train_demo.py
"""
Demo training pipeline for the B.Tech project.
- Loads a subset (~10k rows) from the prepared sample CSV.
- Performs binary classification (Benign vs Attack).
- Trains three lightweight models: Logistic Regression, Linear SVM, Random Forest.
- Evaluates on a held‑out test set and prints a comparison table.
- Saves each trained pipeline under `models/demo/`.
- Generates a markdown report `reports/model_training/demo_report.md`.
"""

import time
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
import joblib

# ---- Paths ----
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_PATH = BASE_DIR / "Data" / "feature_prepared" / "model_ready_sample_100k.csv"
MODEL_DIR = BASE_DIR / "models" / "demo"
REPORT_PATH = BASE_DIR / "reports" / "model_training" / "demo_report.md"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

# ---- Load a small subset (10k rows) ----
# Using nrows ensures we do not load the full 100k if unnecessary.
SUBSET_SIZE = 10000
print(f"Loading up to {SUBSET_SIZE} rows from {DATA_PATH} ...")
df = pd.read_csv(DATA_PATH, nrows=SUBSET_SIZE)
print(f"Loaded {df.shape[0]} rows, {df.shape[1]} columns.")

# ---- Identify features / target ----
identifier_cols = ["category_label", "original_label", "source_file"]
TARGET = "target_binary"
meta_cols = identifier_cols + [TARGET, "target_multiclass", "category_label", "original_label", "source_file"]
feature_cols = [c for c in df.columns if c not in meta_cols]

X = df[feature_cols]
y = df[TARGET]

# ---- Train‑test split (stratified) ----
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Train size: {X_train.shape[0]}, Test size: {X_test.shape[0]}")

# ---- Helper to evaluate a model ----
def evaluate_model(name, model, X_test, y_test):
    start = time.time()
    y_pred = model.predict(X_test)
    duration = time.time() - start
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "Model": name,
        "Accuracy": acc,
        "Precision": prec,
        "Recall": rec,
        "F1": f1,
        "FPR": fpr,
        "InferenceTime(ms)": duration * 1000,
    }

results = []

# ---- 1. Logistic Regression ----
logreg_pipe = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", LogisticRegression(max_iter=300, n_jobs=-1, random_state=42))
])
print("Training Logistic Regression ...")
logreg_pipe.fit(X_train, y_train)
joblib.dump(logreg_pipe, MODEL_DIR / "logistic_regression.joblib")
results.append(evaluate_model("LogisticRegression", logreg_pipe, X_test, y_test))

# ---- 2. Linear SVM (LinearSVC) ----
svm_pipe = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", LinearSVC(max_iter=2000, random_state=42))
])
print("Training Linear SVM ...")
svm_pipe.fit(X_train, y_train)
joblib.dump(svm_pipe, MODEL_DIR / "linear_svm.joblib")
results.append(evaluate_model("LinearSVM", svm_pipe, X_test, y_test))

# ---- 3. Random Forest ----
rf_pipe = Pipeline([
    ("clf", RandomForestClassifier(n_estimators=40, max_depth=None, random_state=42, n_jobs=-1))
])
print("Training Random Forest ...")
rf_pipe.fit(X_train, y_train)
joblib.dump(rf_pipe, MODEL_DIR / "random_forest.joblib")
results.append(evaluate_model("RandomForest", rf_pipe, X_test, y_test))

# ---- Create markdown report ----
with open(REPORT_PATH, "w", encoding="utf-8") as f:
    f.write("# Demo Model Training Report\n\n")
    f.write(f"**Date:** {pd.Timestamp.now().date()}\n\n")
    f.write("## Dataset Snapshot\n")
    f.write(f"- Rows used: {df.shape[0]}\n")
    f.write(f"- Feature columns: {len(feature_cols)}\n\n")
    f.write("## Model Comparison (Binary Classification)\n")
    f.write("| Model | Accuracy | Precision | Recall | Macro F1 | False Positive Rate | Inference Time (ms) |\n")
    f.write("|------|----------|-----------|--------|----------|--------------------|---------------------|\n")
    for r in results:
        f.write(
            f"| {r['Model']} | {r['Accuracy']:.4f} | {r['Precision']:.4f} | {r['Recall']:.4f} | {r['F1']:.4f} | {r['FPR']:.4f} | {r['InferenceTime(ms)']:.1f} |\n"
        )
    f.write("\n")
    f.write("---\n")
    f.write("*Models saved in `models/demo/`.*\n")

print("Demo training complete. Report written to", REPORT_PATH)
