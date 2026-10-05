import os
import time
import json
import joblib
import pandas as pd
import numpy as np
from typing import Dict, Any, Optional

from sklearn.ensemble import RandomForestClassifier, IsolationForest

from src.data_loader import find_dataset_files, load_dataset
from src.preprocessing import prepare_features_and_labels, fit_and_split_data
from src.metrics import calculate_metrics, measure_inference_latency
from src.rules import RuleBasedEngine

MODEL_DIR = "models"
BINARY_MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_binary.joblib")
MULTICLASS_MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_multiclass.joblib")
ISOLATION_FOREST_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
METRICS_SUMMARY_PATH = os.path.join(MODEL_DIR, "metrics_summary.json")


def train_nids_models(
    file_path: Optional[str] = None,
    sample_size: Optional[int] = None,
    n_estimators: int = 100,
    max_depth: int = 20,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Main training function for Hybrid NIDS machine learning models.
    """
    if file_path is None:
        files = find_dataset_files()
        if not files:
            raise FileNotFoundError("No dataset files found in data/ or workspace directory.")
        file_path = files[0]
        
    print(f"[*] Loading dataset from: {file_path}")
    df, load_meta = load_dataset(file_path, sample_size=sample_size, random_state=random_state)
    print(f"[*] Dataset loaded: {load_meta['retained_rows']:,} rows, {load_meta['total_columns']} columns.")

    # Prepare features X, binary label y_binary, attack label y_attack
    X, y_binary, y_attack, feature_list = prepare_features_and_labels(df)
    
    print(f"[*] Feature matrix shape: {X.shape}")
    print(f"[*] Binary class counts:\n{y_binary.value_counts().to_dict()}")

    # Split data and fit scaler on training set
    print("[*] Splitting data into Train (70%), Val (15%), Test (15%) and scaling features...")
    split_data = fit_and_split_data(X, y_binary, y_attack=y_attack, test_size=0.15, val_size=0.15, random_state=random_state)

    X_train = split_data["X_train"]
    X_val = split_data["X_val"]
    X_test = split_data["X_test"]
    y_bin_train = split_data["y_bin_train"]
    y_bin_val = split_data["y_bin_val"]
    y_bin_test = split_data["y_bin_test"]
    y_att_train = split_data["y_att_train"]
    y_att_test = split_data["y_att_test"]

    os.makedirs(MODEL_DIR, exist_ok=True)

    # 1. Train Primary Model: Binary Random Forest Classifier
    print(f"[*] Training Primary Binary Random Forest (n_estimators={n_estimators}, max_depth={max_depth})...")
    start_time = time.time()
    rf_binary = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight='balanced',
        n_jobs=-1,
        random_state=random_state
    )
    rf_binary.fit(X_train, y_bin_train)
    train_time_sec = round(time.time() - start_time, 2)
    print(f"[+] Binary Random Forest trained in {train_time_sec} seconds.")

    # Evaluate on held-out test set
    y_bin_pred = rf_binary.predict(X_test)
    y_bin_proba = rf_binary.predict_proba(X_test)
    binary_metrics = calculate_metrics(y_bin_test, y_bin_pred, y_proba=y_bin_proba, is_multiclass=False)

    # Feature importances
    importances = rf_binary.feature_importances_
    feat_imp = sorted(zip(feature_list, importances), key=lambda x: x[1], reverse=True)
    top_features = [{"feature": f, "importance": float(imp)} for f, imp in feat_imp]

    # Measure latency
    sample_eval = X_test[: min(1000, len(X_test))]
    latency_ms = measure_inference_latency(rf_binary, sample_eval)

    # Save Binary RF Model
    joblib.dump(rf_binary, BINARY_MODEL_PATH)
    print(f"[+] Binary model saved to {BINARY_MODEL_PATH}")

    # 2. Train Multiclass Random Forest Classifier
    multiclass_metrics = None
    if y_att_train is not None and len(set(y_att_train)) > 1:
        print(f"[*] Training Multiclass Random Forest for Attack Categories ({len(set(y_att_train))} classes)...")
        rf_multi = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            class_weight='balanced_subsample',
            n_jobs=-1,
            random_state=random_state
        )
        rf_multi.fit(X_train, y_att_train)
        
        y_att_pred = rf_multi.predict(X_test)
        try:
            y_att_proba = rf_multi.predict_proba(X_test)
        except Exception:
            y_att_proba = None
            
        classes_list = rf_multi.classes_.tolist()
        multiclass_metrics = calculate_metrics(
            y_att_test, y_att_pred, y_proba=y_att_proba, classes=classes_list, is_multiclass=True
        )
        joblib.dump(rf_multi, MULTICLASS_MODEL_PATH)
        print(f"[+] Multiclass model saved to {MULTICLASS_MODEL_PATH}")

    # 3. Train Isolation Forest (Anomaly Detector on Benign samples)
    print("[*] Training Isolation Forest on benign samples for unsupervised anomaly detection...")
    benign_indices = (y_bin_train == 0).to_numpy()
    X_benign_train = X_train[benign_indices]
    
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=random_state,
        n_jobs=-1
    )
    iso_forest.fit(X_benign_train)
    joblib.dump(iso_forest, ISOLATION_FOREST_PATH)
    print(f"[+] Isolation Forest model saved to {ISOLATION_FOREST_PATH}")

    # 4. Evaluate the Rule Engine and the combined Hybrid decision on the same held-out test set
    print("[*] Evaluating rule engine and hybrid (ML OR Rules) decision on the test set...")
    rule_alerts = RuleBasedEngine().analyze_dataframe(split_data["X_test_df"])
    y_rule_pred = np.array([1 if alerts else 0 for alerts in rule_alerts])
    y_hybrid_pred = np.maximum(np.asarray(y_bin_pred), y_rule_pred)
    rules_metrics = calculate_metrics(y_bin_test, y_rule_pred, is_multiclass=False)
    hybrid_metrics = calculate_metrics(y_bin_test, y_hybrid_pred, is_multiclass=False)
    for m in (rules_metrics, hybrid_metrics):
        m.pop("classification_report", None)

    # Isolation Forest: how often does it flag benign vs attack test flows?
    iso_flags = iso_forest.predict(X_test) == -1
    iso_metrics = {
        "benign_flag_rate": float(iso_flags[(y_bin_test == 0).to_numpy()].mean()),
        "attack_flag_rate": float(iso_flags[(y_bin_test == 1).to_numpy()].mean()),
    }

    # Combine Summary
    summary = {
        "dataset_file": file_path,
        "total_samples": len(X),
        "class_distribution": {
            "benign": int((y_binary == 0).sum()),
            "malicious": int((y_binary == 1).sum())
        },
        "attack_distribution": {str(k): int(v) for k, v in y_attack[y_binary == 1].value_counts().items()},
        "train_samples": len(X_train),
        "val_samples": len(X_val),
        "test_samples": len(X_test),
        "feature_count": len(feature_list),
        "features": feature_list,
        "training_time_sec": train_time_sec,
        "prediction_latency_ms": latency_ms,
        "binary": binary_metrics,
        "multiclass": multiclass_metrics,
        "isolation_forest": iso_metrics,
        "rules": rules_metrics,
        "hybrid": hybrid_metrics,
        "top_features": top_features[:20]
    }

    with open(METRICS_SUMMARY_PATH, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[+] Training complete! Summary saved to {METRICS_SUMMARY_PATH}")
    print(f"    - Accuracy: {binary_metrics['accuracy']*100:.2f}%")
    print(f"    - Precision: {binary_metrics['precision']*100:.2f}%")
    print(f"    - Recall: {binary_metrics['recall']*100:.2f}%")
    print(f"    - F1-Score: {binary_metrics['f1_score']*100:.2f}%")
    print(f"    - FPR: {binary_metrics['false_positive_rate']*100:.2f}%")
    if multiclass_metrics:
        print(f"    - Multiclass accuracy: {multiclass_metrics['accuracy']*100:.2f}% (macro F1 {multiclass_metrics['f1_macro']*100:.2f}%)")
    print(f"    - Isolation Forest flags: {iso_metrics['benign_flag_rate']*100:.2f}% of benign, {iso_metrics['attack_flag_rate']*100:.2f}% of attacks")
    print(f"    - Rules only: recall {rules_metrics['recall']*100:.2f}%, FPR {rules_metrics['false_positive_rate']*100:.2f}%")
    print(f"    - Hybrid    : recall {hybrid_metrics['recall']*100:.2f}%, FPR {hybrid_metrics['false_positive_rate']*100:.2f}%")

    return summary


if __name__ == "__main__":
    train_nids_models()
