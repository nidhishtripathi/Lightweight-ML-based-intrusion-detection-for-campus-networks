#!/usr/bin/env python3
"""
feature_pipeline.py – Reusable Feature Transformation Pipeline for Week 5+ Model Training
Lightweight ML-Based Intrusion Detection for Campus Networks

Provides:
- LightweightFeaturePipeline: loads feature manifest and label mappings
- transform_chunk(): transforms raw flow DataFrame into clean model-ready feature matrix X and target y
- stream_batches(): memory-efficient batch iterator over full cleaned dataset
"""

import json
from pathlib import Path
from typing import Tuple, List, Generator
import pandas as pd
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
MANIFEST_PATH = BASE_DIR / "data" / "feature_prepared" / "feature_manifest.json"
MAPPINGS_PATH = BASE_DIR / "data" / "feature_prepared" / "label_mappings.json"

class LightweightFeaturePipeline:
    def __init__(self, use_lightweight_subset: bool = True):
        self.use_lightweight_subset = use_lightweight_subset
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            self.manifest = json.load(f)
        with open(MAPPINGS_PATH, "r", encoding="utf-8") as f:
            self.mappings = json.load(f)

        self.candidate_features = (
            self.manifest["candidate_features_lightweight"] 
            if use_lightweight_subset 
            else self.manifest["candidate_features_full"]
        )
        self.identifiers = self.manifest["identifiers_excluded"]["columns"]
        self.binary_mapping = self.mappings["binary_classification"]["categories_mapped"]
        self.multiclass_mapping = self.mappings["multiclass_classification_8_classes"]
        self.prefix_mapping = self.mappings["filename_prefix_to_category"]

    def transform_df(self, df: pd.DataFrame, category_name: str = None) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
        """
        Transforms a DataFrame of raw flows into:
        - X: clean numeric feature matrix (no identifiers, no constants, no NaNs/Infs)
        - y_binary: binary target (0=Benign, 1=Attack)
        - y_multi: multiclass target (0..7)
        """
        # Handle infs and NaNs
        clean_df = df.copy()
        for col in ["Flow Bytes/s", "Flow Packets/s"]:
            if col in clean_df.columns:
                clean_df[col] = pd.to_numeric(clean_df[col], errors="coerce").replace([np.inf, -np.inf], np.nan)

        # Select candidate features
        avail_features = [c for c in self.candidate_features if c in clean_df.columns]
        X = clean_df[avail_features].apply(pd.to_numeric, errors="coerce").fillna(0.0)

        # Target generation
        if category_name:
            y_binary = pd.Series(0 if category_name == "Benign" else 1, index=X.index, name="target_binary")
            y_multi = pd.Series(self.multiclass_mapping.get(category_name, -1), index=X.index, name="target_multiclass")
        else:
            y_binary = clean_df.get("target_binary", None)
            y_multi = clean_df.get("target_multiclass", None)

        return X, y_binary, y_multi

    def load_prepared_sample(self, sample_path: Path = None) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
        """Load the pre-computed stratified 100k sample directly."""
        if sample_path is None:
            sample_path = BASE_DIR / "data" / "feature_prepared" / "model_ready_sample_100k.csv"
        df = pd.read_csv(sample_path, low_memory=False)
        feature_cols = [c for c in self.candidate_features if c in df.columns]
        X = df[feature_cols].copy()
        y_binary = df["target_binary"].copy()
        y_multi = df["target_multiclass"].copy()
        return X, y_binary, y_multi

if __name__ == "__main__":
    pipeline = LightweightFeaturePipeline()
    X, y_bin, y_multi = pipeline.load_prepared_sample()
    print("Pipeline loaded successfully!")
    print(f"Feature matrix shape: {X.shape}")
    print(f"Binary target distribution:\n{y_bin.value_counts()}")
    print(f"Multiclass target distribution:\n{y_multi.value_counts()}")
