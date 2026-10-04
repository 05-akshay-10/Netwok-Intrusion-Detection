import os
import joblib
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, List, Optional

from src.preprocessing import transform_new_data

MODEL_DIR = "models"
BINARY_MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_binary.joblib")
MULTICLASS_MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_multiclass.joblib")
ISOLATION_FOREST_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")


class NIDSPredictor:
    def __init__(self):
        self.binary_model = None
        self.multiclass_model = None
        self.isolation_forest = None
        self._load_models()

    def _load_models(self):
        if os.path.exists(BINARY_MODEL_PATH):
            self.binary_model = joblib.load(BINARY_MODEL_PATH)
        if os.path.exists(MULTICLASS_MODEL_PATH):
            self.multiclass_model = joblib.load(MULTICLASS_MODEL_PATH)
        if os.path.exists(ISOLATION_FOREST_PATH):
            self.isolation_forest = joblib.load(ISOLATION_FOREST_PATH)

    def is_ready(self) -> bool:
        return self.binary_model is not None

    def predict_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Run ML inference on a DataFrame of flow features.
        Returns copy of DataFrame augmented with ML prediction columns.
        """
        if not self.is_ready():
            raise RuntimeError("NIDS models are not loaded or trained yet.")

        # Transform and scale raw features
        X_scaled, aligned_df, feature_names = transform_new_data(df)

        # 1. Binary prediction & probabilities
        binary_preds = self.binary_model.predict(X_scaled)
        try:
            binary_probas = self.binary_model.predict_proba(X_scaled)[:, 1]
        except Exception:
            binary_probas = binary_preds.astype(float)

        # 2. Multiclass prediction (Attack category)
        if self.multiclass_model is not None:
            try:
                attack_preds = self.multiclass_model.predict(X_scaled)
            except Exception:
                attack_preds = np.where(binary_preds == 1, 'Malicious', 'Benign')
        else:
            attack_preds = np.where(binary_preds == 1, 'Malicious', 'Benign')

        # 3. Isolation Forest Anomaly Detection
        if self.isolation_forest is not None:
            # IsolationForest outputs 1 for inliers (normal), -1 for outliers (anomalous)
            iso_preds = self.isolation_forest.predict(X_scaled)
            iso_scores = self.isolation_forest.score_samples(X_scaled)
            anomaly_flag = np.where(iso_preds == -1, True, False)
        else:
            anomaly_flag = np.zeros(len(df), dtype=bool)
            iso_scores = np.zeros(len(df), dtype=float)

        # Build output dataframe
        result_df = df.copy()
        result_df['ml_binary_pred'] = binary_preds
        result_df['ml_confidence'] = binary_probas
        result_df['ml_attack_category'] = attack_preds
        result_df['ml_is_anomaly'] = anomaly_flag
        result_df['ml_anomaly_score'] = iso_scores

        return result_df
