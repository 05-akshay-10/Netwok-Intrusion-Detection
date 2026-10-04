import time
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    roc_curve
)


def calculate_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: Optional[np.ndarray] = None,
    classes: Optional[List[str]] = None,
    is_multiclass: bool = False
) -> Dict[str, Any]:
    """
    Calculate comprehensive model evaluation metrics.
    """
    acc = accuracy_score(y_true, y_pred)
    
    if not is_multiclass:
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        cm = confusion_matrix(y_true, y_pred)
        # Confusion matrix layout for binary: [[TN, FP], [FN, TP]]
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        else:
            tn, fp, fn, tp = 0, 0, 0, 0
            fpr = 0.0

        roc_auc = None
        roc_data = None
        if y_proba is not None:
            try:
                # Use positive class probabilities
                pos_proba = y_proba[:, 1] if y_proba.ndim > 1 else y_proba
                roc_auc = float(roc_auc_score(y_true, pos_proba))
                fpr_pts, tpr_pts, thresholds = roc_curve(y_true, pos_proba)
                roc_data = {
                    "fpr": fpr_pts.tolist(),
                    "tpr": tpr_pts.tolist(),
                    "thresholds": thresholds.tolist()
                }
            except Exception:
                roc_auc = None

        report_dict = classification_report(y_true, y_pred, output_dict=True, zero_division=0)

        return {
            "is_multiclass": False,
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1_score": float(f1),
            "false_positive_rate": float(fpr),
            "confusion_matrix": cm.tolist(),
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
            "roc_auc": roc_auc,
            "roc_curve": roc_data,
            "classification_report": report_dict
        }
    else:
        # Multiclass evaluation
        prec_macro = precision_score(y_true, y_pred, average='macro', zero_division=0)
        rec_macro = recall_score(y_true, y_pred, average='macro', zero_division=0)
        f1_macro = f1_score(y_true, y_pred, average='macro', zero_division=0)
        
        prec_weighted = precision_score(y_true, y_pred, average='weighted', zero_division=0)
        rec_weighted = recall_score(y_true, y_pred, average='weighted', zero_division=0)
        f1_weighted = f1_score(y_true, y_pred, average='weighted', zero_division=0)

        cm = confusion_matrix(y_true, y_pred)
        report_dict = classification_report(y_true, y_pred, output_dict=True, zero_division=0)

        roc_auc = None
        if y_proba is not None:
            try:
                roc_auc = float(roc_auc_score(y_true, y_proba, multi_class='ovr', average='weighted'))
            except Exception:
                roc_auc = None

        return {
            "is_multiclass": True,
            "accuracy": float(acc),
            "precision_macro": float(prec_macro),
            "recall_macro": float(rec_macro),
            "f1_macro": float(f1_macro),
            "precision_weighted": float(prec_weighted),
            "recall_weighted": float(rec_weighted),
            "f1_weighted": float(f1_weighted),
            "confusion_matrix": cm.tolist(),
            "classes": classes or sorted(list(set(y_true))),
            "roc_auc": roc_auc,
            "classification_report": report_dict
        }


def measure_inference_latency(model, X_sample: np.ndarray, n_runs: int = 5) -> float:
    """
    Measure average prediction latency in milliseconds per 1,000 samples.
    """
    times = []
    for _ in range(n_runs):
        start = time.perf_counter()
        _ = model.predict(X_sample)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
        
    avg_sec = np.mean(times)
    ms_per_1k = (avg_sec / len(X_sample)) * 1000.0 * 1000.0
    return float(ms_per_1k)


def generate_evaluation_report_text(metrics_summary: Dict[str, Any]) -> str:
    """
    Generate clean, downloadable plain-text summary report of model performance.
    """
    bin_m = metrics_summary.get("binary", {})
    multi_m = metrics_summary.get("multiclass", {})
    
    report = []
    report.append("=======================================================================")
    report.append(" HYBRID NIDS - MACHINE LEARNING MODEL EVALUATION REPORT")
    report.append("=======================================================================\n")
    
    report.append("1. BINARY CLASSIFICATION (BENIGN vs MALICIOUS)")
    report.append("-----------------------------------------------------------------------")
    report.append(f" Accuracy           : {bin_m.get('accuracy', 0.0)*100:.2f}%")
    report.append(f" Precision          : {bin_m.get('precision', 0.0)*100:.2f}%")
    report.append(f" Recall (TPR)       : {bin_m.get('recall', 0.0)*100:.2f}%")
    report.append(f" F1-Score           : {bin_m.get('f1_score', 0.0)*100:.2f}%")
    report.append(f" False Positive Rate: {bin_m.get('false_positive_rate', 0.0)*100:.2f}%")
    if bin_m.get('roc_auc'):
        report.append(f" ROC-AUC Score      : {bin_m.get('roc_auc'):.4f}")
    report.append(f" Training Time      : {metrics_summary.get('training_time_sec', 0.0):.2f} seconds")
    report.append(f" Prediction Latency : {metrics_summary.get('prediction_latency_ms', 0.0):.4f} ms per 1k samples")
    
    report.append("\nConfusion Matrix [ [TN, FP], [FN, TP] ]:")
    cm = bin_m.get("confusion_matrix", [[0, 0], [0, 0]])
    report.append(f"  True Negatives (TN)  : {cm[0][0]:,}")
    report.append(f"  False Positives (FP) : {cm[0][1]:,}")
    report.append(f"  False Negatives (FN) : {cm[1][0]:,}")
    report.append(f"  True Positives (TP)  : {cm[1][1]:,}")
    
    if multi_m:
        report.append("\n2. MULTICLASS ATTACK CATEGORY CLASSIFICATION")
        report.append("-----------------------------------------------------------------------")
        report.append(f" Accuracy           : {multi_m.get('accuracy', 0.0)*100:.2f}%")
        report.append(f" Macro Precision    : {multi_m.get('precision_macro', 0.0)*100:.2f}%")
        report.append(f" Macro Recall       : {multi_m.get('recall_macro', 0.0)*100:.2f}%")
        report.append(f" Macro F1-Score     : {multi_m.get('f1_macro', 0.0)*100:.2f}%")
        report.append(f" Weighted F1-Score  : {multi_m.get('f1_weighted', 0.0)*100:.2f}%")
        
    report.append("\n3. METRIC DEFINITIONS FOR EXAMINATION / VIVA")
    report.append("-----------------------------------------------------------------------")
    report.append(" * Accuracy: Percentage of total network flows correctly classified.")
    report.append(" * Precision: Out of all flows flagged as attacks, what % were actually attacks.")
    report.append(" * Recall: Out of all actual attacks, what % were correctly detected by the model.")
    report.append(" * F1-Score: Harmonic mean of precision and recall, ideal for imbalanced network data.")
    report.append(" * False Positive Rate (FPR): % of benign network traffic incorrectly flagged as malicious.")
    report.append(" * ROC-AUC: Area under the Receiver Operating Characteristic curve measuring trade-off between TPR and FPR.")
    report.append("=======================================================================")

    return "\n".join(report)
