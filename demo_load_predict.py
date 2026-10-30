# demo_load_predict.py
"""Utility script to load the three demo models and make a quick prediction.
It reads a few rows from the prepared sample CSV, extracts the feature columns,
loads each saved pipeline (LogisticRegression, LinearSVM, RandomForest) and
prints the predicted binary labels (0 = Benign, 1 = Attack).
"""

import pandas as pd
from pathlib import Path
import joblib

# ----- Paths -----
BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "Data" / "feature_prepared" / "model_ready_sample_100k.csv"
MODEL_DIR = BASE_DIR / "models" / "demo"

# ----- Load a tiny preview (5 rows) -----
NUM_ROWS = 5
print(f"Loading {NUM_ROWS} rows from {DATA_PATH} ...")
df = pd.read_csv(DATA_PATH, nrows=NUM_ROWS)

# Identify feature columns (same logic as train_demo.py)
identifier_cols = ["category_label", "original_label", "source_file"]
TARGET = "target_binary"
meta_cols = identifier_cols + [TARGET, "target_multiclass", "category_label", "original_label", "source_file"]
feature_cols = [c for c in df.columns if c not in meta_cols]
X_demo = df[feature_cols]

# Helper to load a model and predict
def load_and_predict(name: str, X):
    model_path = MODEL_DIR / f"{name}.joblib"
    pipeline = joblib.load(model_path)
    preds = pipeline.predict(X)
    return preds

# Run predictions for each saved model
for model_name in ["logistic_regression", "linear_svm", "random_forest"]:
    preds = load_and_predict(model_name, X_demo)
    print(f"{model_name}: predictions -> {preds}")
