"""
Baseline Model Training Pipeline for ZeroSentinel.

Responsibilities:
1. Build a TF-IDF vectorizer over code tokens (using detector.tokenizer).
2. Train a class-weighted LogisticRegression binary classifier (vulnerable vs. benign).
3. Train a second class-weighted LogisticRegression classifier for the 7 CWE types.
4. Evaluate on validation split (Precision, Recall, F1, ROC-AUC), automatically select
   the probability threshold maximizing F1, and update `ml/artifacts/thresholds.json`.
5. Save trained models and vectorizer to `ml/artifacts/` using joblib.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report
)

from detector.tokenizer import tokenize_code

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

PROCESSED_DIR = Path(__file__).resolve().parent / "data" / "processed"
ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"
LABEL_MAP_FILE = ARTIFACTS_DIR / "label_map.json"
THRESHOLDS_FILE = ARTIFACTS_DIR / "thresholds.json"

def load_data() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    train_path = PROCESSED_DIR / "train.parquet"
    val_path = PROCESSED_DIR / "val.parquet"
    test_path = PROCESSED_DIR / "test.parquet"

    if not (train_path.exists() and val_path.exists()):
        raise FileNotFoundError(f"Missing parquet files in {PROCESSED_DIR}. Run prepare.py first.")

    train_df = pd.read_parquet(train_path)
    val_df = pd.read_parquet(val_path)
    test_df = pd.read_parquet(test_path) if test_path.exists() else pd.DataFrame()

    return train_df, val_df, test_df

def find_optimal_threshold(
    y_true: np.ndarray,
    y_probs: np.ndarray
) -> Tuple[float, Dict[str, float]]:
    """
    Sweeps probability thresholds from 0.10 to 0.90 to find the threshold
    that maximizes the F1 score on the validation set.
    """
    best_threshold = 0.50
    best_f1 = -1.0
    best_metrics = {}

    for t in np.linspace(0.10, 0.90, 81):
        t = round(float(t), 2)
        preds = (y_probs >= t).astype(int)

        # Avoid zero division warnings if all negative
        prec = precision_score(y_true, preds, zero_division=0)
        rec = recall_score(y_true, preds, zero_division=0)
        f1 = f1_score(y_true, preds, zero_division=0)

        if f1 > best_f1 or (f1 == best_f1 and abs(t - 0.50) < abs(best_threshold - 0.50)):
            best_f1 = f1
            best_threshold = t
            best_metrics = {
                "threshold": best_threshold,
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
                "f1": round(float(f1), 4)
            }

    return best_threshold, best_metrics

def main():
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Loading processed dataset splits...")
    train_df, val_df, test_df = load_data()

    logger.info(f"Loaded {len(train_df)} train, {len(val_df)} val, {len(test_df)} test examples.")

    # 1. Fit TF-IDF Vectorizer
    logger.info("Fitting TF-IDF vectorizer over code tokens...")
    vectorizer = TfidfVectorizer(
        tokenizer=tokenize_code,
        token_pattern=None,
        ngram_range=(1, 2),
        max_features=15000,
        sublinear_tf=True
    )
    X_train = vectorizer.fit_transform(train_df["code"])
    y_train_binary = train_df["label"].values

    logger.info(f"TF-IDF vocabulary size: {len(vectorizer.vocabulary_)} features.")

    # 2. Train Binary Classifier (Vulnerable vs. Benign)
    logger.info("Training class-weighted LogisticRegression binary classifier...")
    binary_model = LogisticRegression(
        class_weight="balanced",
        max_iter=1000,
        random_state=42
    )
    binary_model.fit(X_train, y_train_binary)

    # 3. Train Multiclass CWE Classifier
    vuln_train = train_df[train_df["label"] == 1].copy()
    logger.info(f"Training multiclass CWE classifier on {len(vuln_train)} vulnerable functions...")

    X_train_vuln = vectorizer.transform(vuln_train["code"])
    y_train_cwe = vuln_train["cwe_id"].values

    cwe_model = LogisticRegression(
        class_weight="balanced",
        max_iter=1000,
        random_state=42
    )
    cwe_model.fit(X_train_vuln, y_train_cwe)
    logger.info(f"CWE classes learned: {list(cwe_model.classes_)}")

    # 4. Evaluate on Validation Set
    logger.info("Evaluating baseline models on validation split...")
    X_val = vectorizer.transform(val_df["code"])
    y_val_binary = val_df["label"].values

    val_probs = binary_model.predict_proba(X_val)[:, 1]
    roc_auc = roc_auc_score(y_val_binary, val_probs)

    best_thresh, best_metrics = find_optimal_threshold(y_val_binary, val_probs)
    best_metrics["roc_auc"] = round(float(roc_auc), 4)

    # Metrics at default 0.50 threshold for comparison
    val_preds_50 = (val_probs >= 0.50).astype(int)
    p_50 = precision_score(y_val_binary, val_preds_50, zero_division=0)
    r_50 = recall_score(y_val_binary, val_preds_50, zero_division=0)
    f1_50 = f1_score(y_val_binary, val_preds_50, zero_division=0)

    print("\n================ VALIDATION EVALUATION ================")
    print(f"ROC-AUC:               {roc_auc:.4f}")
    print(f"At default (0.50):     Precision={p_50:.4f}, Recall={r_50:.4f}, F1={f1_50:.4f}")
    print(f"At optimal ({best_thresh:.2f}):     Precision={best_metrics['precision']:.4f}, Recall={best_metrics['recall']:.4f}, F1={best_metrics['f1']:.4f}")
    print("\nClassification Report (at optimal threshold):")
    optimal_val_preds = (val_probs >= best_thresh).astype(int)
    print(classification_report(y_val_binary, optimal_val_preds, target_names=["Benign", "Vulnerable"]))

    # Test evaluation
    if not test_df.empty:
        X_test = vectorizer.transform(test_df["code"])
        y_test_binary = test_df["label"].values
        test_probs = binary_model.predict_proba(X_test)[:, 1]
        test_roc_auc = roc_auc_score(y_test_binary, test_probs)
        test_preds = (test_probs >= best_thresh).astype(int)
        test_p = precision_score(y_test_binary, test_preds, zero_division=0)
        test_r = recall_score(y_test_binary, test_preds, zero_division=0)
        test_f1 = f1_score(y_test_binary, test_preds, zero_division=0)

        print("\n================ TEST SET EVALUATION ================")
        print(f"ROC-AUC:               {test_roc_auc:.4f}")
        print(f"At threshold ({best_thresh:.2f}):  Precision={test_p:.4f}, Recall={test_r:.4f}, F1={test_f1:.4f}")

    # 5. Update thresholds.json
    threshold_payload = {
        "default_threshold": best_thresh,
        "validation_metrics": best_metrics
    }
    with open(THRESHOLDS_FILE, "w", encoding="utf-8") as f:
        json.dump(threshold_payload, f, indent=2)
    logger.info(f"Updated thresholds file: {THRESHOLDS_FILE}")

    # 6. Save trained model artifacts using joblib
    vectorizer_path = ARTIFACTS_DIR / "tfidf_vectorizer.joblib"
    binary_model_path = ARTIFACTS_DIR / "binary_model.joblib"
    cwe_model_path = ARTIFACTS_DIR / "cwe_model.joblib"

    joblib.dump(vectorizer, vectorizer_path)
    joblib.dump(binary_model, binary_model_path)
    joblib.dump(cwe_model, cwe_model_path)

    logger.info("Successfully saved model artifacts:")
    logger.info(f"  - Vectorizer:   {vectorizer_path}")
    logger.info(f"  - Binary Model: {binary_model_path}")
    logger.info(f"  - CWE Model:    {cwe_model_path}")

if __name__ == "__main__":
    main()
