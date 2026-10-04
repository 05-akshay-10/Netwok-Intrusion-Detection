import pytest
import numpy as np
from src.metrics import calculate_metrics


def test_calculate_binary_metrics():
    y_true = np.array([0, 0, 1, 1, 0, 1, 0, 1])
    y_pred = np.array([0, 0, 1, 1, 0, 0, 0, 1])  # 1 false negative (index 5)
    y_proba = np.array([
        [0.9, 0.1], [0.8, 0.2], [0.1, 0.9], [0.2, 0.8],
        [0.95, 0.05], [0.6, 0.4], [0.85, 0.15], [0.05, 0.95]
    ])

    m = calculate_metrics(y_true, y_pred, y_proba=y_proba, is_multiclass=False)

    assert m['accuracy'] == 7.0 / 8.0
    assert m['precision'] == 1.0  # 3 TP out of 3 positive predictions
    assert m['recall'] == 0.75    # 3 TP out of 4 actual positives
    assert m['false_positive_rate'] == 0.0  # 0 FP out of 4 actual negatives
    assert m['roc_auc'] is not None
    assert 'confusion_matrix' in m
