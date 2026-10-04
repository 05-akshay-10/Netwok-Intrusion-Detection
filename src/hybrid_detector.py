import datetime
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional, Tuple

from src.predict import NIDSPredictor
from src.rules import RuleBasedEngine


class HybridDetector:
    def __init__(self, predictor: Optional[NIDSPredictor] = None, rule_engine: Optional[RuleBasedEngine] = None):
        self.predictor = predictor if predictor is not None else NIDSPredictor()
        self.rule_engine = rule_engine if rule_engine is not None else RuleBasedEngine()

    def analyze(self, df: pd.DataFrame, ml_threshold: float = 0.5) -> pd.DataFrame:
        """
        Run combined Machine Learning and Rule-based analysis on network flows.
        """
        if len(df) == 0:
            return pd.DataFrame()

        # 1. Run ML Predictor
        ml_results_df = self.predictor.predict_dataframe(df)

        # 2. Run Rule Engine
        rule_alerts_list = self.rule_engine.analyze_dataframe(df)

        # 3. Combine results row by row
        combined_rows = []
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for idx in range(len(ml_results_df)):
            row_ml = ml_results_df.iloc[idx]
            rule_alerts = rule_alerts_list[idx]

            ml_conf = float(row_ml.get('ml_confidence', 0.0))
            ml_pred = int(row_ml.get('ml_binary_pred', 0))
            ml_attack = str(row_ml.get('ml_attack_category', 'Benign'))
            is_anomaly = bool(row_ml.get('ml_is_anomaly', False))

            ml_flagged = (ml_conf >= ml_threshold) or (ml_pred == 1)
            rules_flagged = len(rule_alerts) > 0

            # Determine Detection Method
            if ml_flagged and rules_flagged:
                method = "Both ML & Rules"
                final_class = "Malicious"
            elif ml_flagged:
                method = "ML Only"
                final_class = "Malicious"
            elif rules_flagged:
                method = "Rules Only"
                final_class = "Malicious"
            else:
                method = "Neither (Benign)"
                final_class = "Benign"

            # Determine Severity
            rule_severities = [a['severity'] for a in rule_alerts]
            if "High" in rule_severities or (ml_flagged and rules_flagged) or ml_conf >= 0.85:
                severity = "High"
            elif "Medium" in rule_severities or ml_conf >= 0.5:
                severity = "Medium"
            elif "Low" in rule_severities or is_anomaly:
                severity = "Low"
            else:
                severity = "None"

            # Attack category refinement
            if final_class == "Benign":
                attack_category = "Benign"
            elif ml_attack != "Benign":
                attack_category = ml_attack
            elif rules_flagged:
                attack_category = rule_alerts[0]['rule_name']
            else:
                attack_category = "Malicious (Unspecified)"

            # Construct Explanation
            exp_parts = []
            if ml_flagged:
                exp_parts.append(f"ML Random Forest predicted malicious intent with {ml_conf*100:.1f}% confidence ({attack_category}).")
            if rules_flagged:
                rule_names = [a['rule_name'] for a in rule_alerts]
                exp_parts.append(f"Rule engine triggered {len(rule_alerts)} alert(s): {', '.join(rule_names)}.")
                for a in rule_alerts:
                    exp_parts.append(f"  • [{a['rule_name']}]: {a['explanation']}")
            if is_anomaly and not ml_flagged and not rules_flagged:
                exp_parts.append("Isolation Forest detected an unusual statistical flow pattern (Anomaly).")
            if not exp_parts:
                exp_parts.append("Flow patterns match standard benign network traffic parameters.")

            explanation = " ".join(exp_parts)
            rule_names_str = ", ".join([a['rule_name'] for a in rule_alerts]) if rule_alerts else "None"

            row_dict = row_ml.to_dict()
            row_dict.update({
                "timestamp": now_str,
                "final_prediction": final_class,
                "attack_category": attack_category,
                "detection_method": method,
                "severity": severity,
                "ml_confidence_pct": round(ml_conf * 100, 1),
                "triggered_rules": rule_names_str,
                "explanation": explanation,
                "rule_alert_count": len(rule_alerts)
            })

            combined_rows.append(row_dict)

        return pd.DataFrame(combined_rows)
