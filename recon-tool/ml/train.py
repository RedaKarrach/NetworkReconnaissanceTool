"""
ml/train.py
-----------
Train the SOC classifier on CIC-IDS2017 using classic ML only
(RandomForest / GradientBoosting / optional XGBoost) and fit an IsolationForest
for novelty detection. No deep learning.

Usage
-----
    python ml/train.py --data ml/datasets --model rf --out ml/artifacts

The dataset is NOT committed (see ml/datasets/README.md for the download). The
produced artifacts (ml/artifacts/*.joblib) are also not committed to git; ship
them with scripts/download_artifacts.py or Git LFS.

Outputs
-------
    ml/artifacts/classifier.joblib        {model, scaler, classes, model_version, feature_names}
    ml/artifacts/isolation_forest.joblib  {model, scaler, threshold}
    ml/artifacts/metrics.json             accuracy / precision / recall / F1 / ROC-AUC / confusion matrix
"""
import argparse
import glob
import json
import os
import time

from features import FEATURE_NAMES, cic_row_to_features  # run as a script from ml/


def _load_dataset(data_dir):
    import pandas as pd

    csvs = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not csvs:
        raise SystemExit(
            f"No CSV files in {data_dir}. Download CIC-IDS2017 first "
            f"(see ml/datasets/README.md)."
        )

    frames = []
    for path in csvs:
        print(f"[train] reading {os.path.basename(path)}")
        df = pd.read_csv(path, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        frames.append(df)
    data = pd.concat(frames, ignore_index=True)
    print(f"[train] {len(data):,} rows, {len(data.columns)} columns")
    return data


def _build_xy(df):
    import numpy as np
    import pandas as pd

    label_col = None
    for cand in ("Label", "label", " Label"):
        if cand in df.columns:
            label_col = cand
            break
    if label_col is None:
        raise SystemExit("No 'Label' column found in dataset.")

    df = df.replace([float("inf"), float("-inf")], 0.0)
    df = df.fillna(0.0)

    rows = df.to_dict(orient="records")
    X = np.asarray([cic_row_to_features(r) for r in rows], dtype=float)
    y = df[label_col].astype(str).str.strip().str.upper().values
    # Normalize benign label spelling.
    y = np.array(["BENIGN" if v in ("BENIGN", "NORMAL") else v for v in y])
    return X, y


def _make_model(kind):
    kind = kind.lower()
    if kind in ("rf", "randomforest"):
        from sklearn.ensemble import RandomForestClassifier
        return RandomForestClassifier(
            n_estimators=200, max_depth=None, n_jobs=-1,
            class_weight="balanced", random_state=42,
        )
    if kind in ("gb", "gradientboosting"):
        from sklearn.ensemble import GradientBoostingClassifier
        return GradientBoostingClassifier(random_state=42)
    if kind in ("xgb", "xgboost"):
        try:
            from xgboost import XGBClassifier
        except Exception as exc:
            raise SystemExit(f"xgboost not installed: {exc}")
        return XGBClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.1,
            subsample=0.9, tree_method="hist", n_jobs=-1, random_state=42,
        )
    raise SystemExit(f"Unknown model '{kind}' (use rf | gb | xgb)")


def main():
    parser = argparse.ArgumentParser(description="Train SOC classifier (classic ML)")
    parser.add_argument("--data", default="datasets", help="dir of CIC-IDS2017 CSVs")
    parser.add_argument("--model", default="rf", help="rf | gb | xgb")
    parser.add_argument("--out", default="artifacts", help="artifact output dir")
    parser.add_argument("--test-size", type=float, default=0.25)
    args = parser.parse_args()

    import numpy as np
    import joblib
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report, roc_auc_score,
    )
    from anomaly import train_isolation_forest  # run from ml/

    os.makedirs(args.out, exist_ok=True)

    df = _load_dataset(args.data)
    X, y = _build_xy(df)
    print(f"[train] classes: {sorted(set(y))}")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_te_s = scaler.transform(X_te)

    model = _make_model(args.model)
    print(f"[train] fitting {args.model} ...")
    model.fit(X_tr_s, y_tr)

    y_pred = model.predict(X_te_s)
    metrics = {
        "model": args.model,
        "accuracy": float(accuracy_score(y_te, y_pred)),
        "precision_macro": float(precision_score(y_te, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_te, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_te, y_pred, average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(y_te, y_pred).tolist(),
        "labels": sorted(set(y.tolist())),
        "feature_names": FEATURE_NAMES,
    }
    try:
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X_te_s)
            metrics["roc_auc_ovr"] = float(
                roc_auc_score(y_te, proba, multi_class="ovr", average="macro")
            )
    except Exception as exc:
        metrics["roc_auc_ovr"] = None
        print(f"[train] roc_auc skipped: {exc}")

    print("\n[train] classification report:\n")
    print(classification_report(y_te, y_pred, zero_division=0))
    print(f"[train] accuracy={metrics['accuracy']:.4f} f1_macro={metrics['f1_macro']:.4f} "
          f"roc_auc_ovr={metrics.get('roc_auc_ovr')}")

    # IsolationForest on benign-leaning rows (scaled).
    benign_mask = np.array([str(v).upper() == "BENIGN" for v in y_tr])
    iforest_X = X_tr_s[benign_mask] if benign_mask.any() else X_tr_s
    iforest = train_isolation_forest(iforest_X)

    version = time.strftime("%Y%m%d-%H%M%S")
    joblib.dump(
        {"model": model, "scaler": scaler, "classes": list(getattr(model, "classes_", [])),
         "model_version": f"{args.model}-{version}", "feature_names": FEATURE_NAMES},
        os.path.join(args.out, "classifier.joblib"),
    )
    joblib.dump(
        {"model": iforest, "scaler": scaler, "threshold": 0.0},
        os.path.join(args.out, "isolation_forest.joblib"),
    )
    with open(os.path.join(args.out, "metrics.json"), "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)

    print(f"\n[train] saved artifacts to {args.out}/ (version {args.model}-{version})")


if __name__ == "__main__":
    main()
