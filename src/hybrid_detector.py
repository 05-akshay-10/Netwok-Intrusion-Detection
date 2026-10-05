import datetime
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional, Tuple

from src.data_loader import normalize_column_names
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

        # Map raw CIC-IDS2017 headers (e.g. " Destination Port") to the training schema
        df = normalize_column_names(df).reset_index(drop=True)

        # 1. Run ML Predictor
        ml_results_df = self.predictor.predict_dataframe(df)

        # 2. Run Rule Engine
        rule_alerts_list = self.rule_engine.analyze_dataframe(df)

        # 3. Combine results row by row
        combined_rows = []
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for row_dict, rule_alerts in zip(ml_results_df.to_dict("records"), rule_alerts_list):
            ml_conf = float(row_dict.get('ml_confidence', 0.0))
            ml_attack = str(row_dict.get('ml_attack_category', 'Benign'))
            is_anomaly = bool(row_dict.get('ml_is_anomaly', False))

            # The sensitivity threshold alone decides the ML verdict
            ml_flagged = ml_conf >= ml_threshold
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

            # Determine Severity (benign flows carry no severity)
            rule_severities = [a['severity'] for a in rule_alerts]
            if final_class == "Benign":
                severity = "None"
            elif "High" in rule_severities or (ml_flagged and rules_flagged) or (ml_flagged and ml_conf >= 0.85):
                severity = "High"
            elif "Medium" in rule_severities or ml_flagged:
                severity = "Medium"
            else:
                severity = "Low"

            # Attack category refinement
            if final_class == "Benign":
                attack_category = "Benign"
            elif ml_flagged and ml_attack.upper() != "BENIGN":
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
            if is_anomaly:
                exp_parts.append("Isolation Forest also scored this flow as statistically unusual (Anomaly).")
            if not ml_flagged and not rules_flagged:
                exp_parts.insert(0, "Flow patterns match standard benign network traffic parameters.")

            explanation = " ".join(exp_parts)
            rule_names_str = ", ".join([a['rule_name'] for a in rule_alerts]) if rule_alerts else "None"

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
