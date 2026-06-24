#!/usr/bin/env python3
"""
=============================================================
  train_model.py — Retrain AI False-Alarm Classifier (A4)
  Author: Angga Firmansyah — AI Model Lead (A4), FP-SOC-K3
=============================================================

Versi .py runnable dari notebook SOC_training.ipynb.
Tujuan: model reproducible TANPA Jupyter (bukti A4).

Algoritma: Random Forest (model utama) + Logistic Regression (baseline).
> Per implementation plan: JANGAN ganti algoritma. RF cukup & cepat.

USAGE:
    python train_model.py                       # pakai labeled_alerts.csv default
    python train_model.py --data foo.csv        # dataset kustom
    python train_model.py --out ../model        # folder output kustom

OUTPUT (di folder --out, default: folder ini):
    model.pkl              Random Forest terlatih
    scaler.pkl             StandardScaler (dipakai LR)
    feature_columns.json   urutan 6 fitur
    metrics.json           precision/recall/F1/AUC + confusion matrix
"""
from __future__ import annotations

import argparse
import json
import os
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (classification_report, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")
os.environ.setdefault("PYTHONWARNINGS", "ignore")

FEATURES = ["rule_id", "rule_level", "freq_per_minute", "hour_of_day",
            "src_port", "dst_port"]
TARGET = "label"

HERE = os.path.dirname(os.path.abspath(__file__))


def load_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [c for c in FEATURES + [TARGET] if c not in df.columns]
    if missing:
        raise SystemExit(f"[ERROR] Kolom hilang di {path}: {missing}")
    # coerce numerik
    for c in FEATURES + [TARGET]:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.dropna(subset=FEATURES + [TARGET]).astype(int)
    return df


def train_random_forest(X_train, y_train):
    """Random Forest — parameter sama dengan notebook cell 10."""
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    return rf


def train_logistic(X_train_sc, y_train):
    lr = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
    lr.fit(X_train_sc, y_train)
    return lr


def cross_validate(rf, X, y):
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    rec = cross_val_score(rf, X, y, cv=cv, scoring="recall")
    prec = cross_val_score(rf, X, y, cv=cv, scoring="precision")
    f1 = cross_val_score(rf, X, y, cv=cv, scoring="f1")
    return {
        "recall_mean": float(rec.mean()), "recall_std": float(rec.std()),
        "precision_mean": float(prec.mean()), "f1_mean": float(f1.mean()),
        "folds_recall": rec.tolist(),
    }


def main():
    ap = argparse.ArgumentParser(description="Train RF false-alarm classifier (A4)")
    ap.add_argument("--data", default=os.path.join(HERE, "..", "data", "labeled_alerts.csv"))
    ap.add_argument("--out", default=HERE)
    args = ap.parse_args()

    data_path = os.path.abspath(args.data)
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 60)
    print("TRAINING AI FALSE-ALARM CLASSIFIER (Random Forest)")
    print("=" * 60)
    print(f"Dataset : {data_path}")
    print(f"Output  : {out_dir}")

    df = load_dataset(data_path)
    print(f"Loaded  : {len(df)} baris | Kolom: {list(df.columns)}")

    tp = int((df[TARGET] == 1).sum())
    fp = int((df[TARGET] == 0).sum())
    print(f"Distribusi: TP(1)={tp} ({tp/len(df)*100:.1f}%) | "
          f"FP(0)={fp} ({fp/len(df)*100:.1f}%)")

    X = df[FEATURES]
    y = df[TARGET]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"Split   : train={len(X_train)} test={len(X_test)}")

    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc = scaler.transform(X_test)

    # --- Random Forest (utama) ---
    print("\nTraining Random Forest...")
    rf = train_random_forest(X_train, y_train)
    rf_pred = rf.predict(X_test)
    rf_proba = rf.predict_proba(X_test)[:, 1]
    p, r, f1, _ = precision_recall_fscore_support(y_test, rf_pred, average="binary")
    try:
        auc = float(roc_auc_score(y_test, rf_proba))
    except ValueError:
        auc = 0.0
    print(f"  RF -> Precision={p:.3f} | Recall={r:.3f} | F1={f1:.3f} | AUC={auc:.3f}")

    # --- Logistic Regression (baseline) ---
    print("Training Logistic Regression (baseline)...")
    lr = train_logistic(X_train_sc, y_train)
    lr_pred = lr.predict(X_test_sc)
    lr_proba = lr.predict_proba(X_test_sc)[:, 1]
    lp, lr_r, lr_f1, _ = precision_recall_fscore_support(
        y_test, lr_pred, average="binary", zero_division=0)
    print(f"  LR -> Precision={lp:.3f} | Recall={lr_r:.3f} | F1={lr_f1:.3f}")

    # --- Cross-validation RF ---
    print("\nCross-validation 5-fold (RF)...")
    cv = cross_validate(RandomForestClassifier(
        n_estimators=200, max_depth=12, min_samples_split=5,
        class_weight="balanced", random_state=42, n_jobs=-1), X, y)
    print(f"  RF CV -> Recall={cv['recall_mean']:.3f}±{cv['recall_std']:.3f} "
          f"| Precision={cv['precision_mean']:.3f} | F1={cv['f1_mean']:.3f}")

    cm = confusion_matrix(y_test, rf_pred).tolist()
    report = classification_report(y_test, rf_pred, output_dict=True, zero_division=0)

    # --- Export ---
    print("\nExport artifacts...")
    joblib.dump(rf, os.path.join(out_dir, "model.pkl"))
    joblib.dump(scaler, os.path.join(out_dir, "scaler.pkl"))
    with open(os.path.join(out_dir, "feature_columns.json"), "w") as f:
        json.dump(FEATURES, f)

    metrics = {
        "model": "RandomForestClassifier",
        "features": FEATURES,
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "random_forest": {
            "precision": float(p), "recall": float(r), "f1": float(f1), "auc": auc,
        },
        "logistic_regression": {
            "precision": float(lp), "recall": float(lr_r), "f1": float(lr_f1),
        },
        "cv_5fold": cv,
        "confusion_matrix_test": cm,
        "classification_report": report,
        "thresholds_note": "confidence=P(FP)=predict_proba[:,0]; "
                           "FILTERED_FP>=0.85, NEEDS_REVIEW 0.60-0.84, FORWARD<0.60",
    }
    with open(os.path.join(out_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print("\n" + "=" * 60)
    print("DONE — artifacts tersimpan:")
    for fn in ("model.pkl", "scaler.pkl", "feature_columns.json", "metrics.json"):
        p2 = os.path.join(out_dir, fn)
        print(f"  {fn:24s} ({os.path.getsize(p2)} bytes)")
    print("=" * 60)
    print("\nConfusion matrix (test, [[TN,FP],[FN,TP]]):")
    print(np.array(cm))


if __name__ == "__main__":
    main()
