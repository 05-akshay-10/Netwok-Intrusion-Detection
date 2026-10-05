import os
import pytest
import numpy as np
import pandas as pd
from src.rules import RuleBasedEngine
from src.hybrid_detector import HybridDetector
from src.predict import BINARY_MODEL_PATH


def test_rule_based_engine_triggers():
    engine = RuleBasedEngine()

    # Normal benign flow
    benign_flow = pd.Series({
        'DESTINATION_PORT': 80,
        'FLOW_DURATION': 50000,
        'FLOW_PACKETS_S': 10.0,
        'TOTAL_FWD_PACKETS': 5,
        'PACKET_LENGTH_MEAN': 200,
        'PSH_FLAG_COUNT': 0,
        'URG_FLAG_COUNT': 0
    })
    alerts_benign = engine.analyze_flow(benign_flow)
    assert len(alerts_benign) == 0

    # Controlled PortScan flow example: empty probe answered by a zero-window reset
    portscan_flow = pd.Series({
        'DESTINATION_PORT': 445,
        'FLOW_DURATION': 50,
        'FLOW_PACKETS_S': 40000.0,
        'TOTAL_FWD_PACKETS': 1,
        'TOTAL_BACKWARD_PACKETS': 1,
        'TOTAL_LENGTH_OF_FWD_PACKETS': 0,
        'INIT_WIN_BYTES_BACKWARD': 0,
        'PACKET_LENGTH_MEAN': 2,
        'PSH_FLAG_COUNT': 0,
        'URG_FLAG_COUNT': 0
    })
    alerts_ps = engine.analyze_flow(portscan_flow)
    assert len(alerts_ps) >= 1
    assert any(a['rule_name'] == 'Possible Port Scan' for a in alerts_ps)

    # Controlled DoS flood example
    dos_flow = pd.Series({
        'DESTINATION_PORT': 80,
        'FLOW_DURATION': 10000,
        'FLOW_PACKETS_S': 250000.0,
        'TOTAL_FWD_PACKETS': 500,
        'PACKET_LENGTH_MEAN': 1000,
        'PSH_FLAG_COUNT': 1,
        'URG_FLAG_COUNT': 0
    })
    alerts_dos = engine.analyze_flow(dos_flow)
    assert len(alerts_dos) >= 1
    assert any('DoS' in a['rule_name'] for a in alerts_dos)


def test_short_benign_flow_is_not_a_flood():
    # A 2-packet DNS-style exchange has a huge packets/s value but is not a flood or a scan
    engine = RuleBasedEngine()
    tiny_flow = {
        'DESTINATION_PORT': 53,
        'FLOW_DURATION': 4,
        'FLOW_PACKETS_S': 500000.0,
        'TOTAL_FWD_PACKETS': 2,
        'TOTAL_BACKWARD_PACKETS': 0,
        'TOTAL_LENGTH_OF_FWD_PACKETS': 37,
        'INIT_WIN_BYTES_BACKWARD': -1,
        'PACKET_LENGTH_MEAN': 22.6,
    }
    assert engine.analyze_flow(tiny_flow) == []


def test_brute_force_and_slow_dos_rules():
    engine = RuleBasedEngine()
    ssh_flow = {'DESTINATION_PORT': 22, 'FLOW_DURATION': 12_000_000, 'TOTAL_FWD_PACKETS': 21, 'PACKET_LENGTH_MEAN': 88}
    assert any(a['rule_name'] == 'Possible Brute Force Attack' for a in engine.analyze_flow(ssh_flow))

    slow_flow = {'DESTINATION_PORT': 80, 'FLOW_DURATION': 99_000_000, 'TOTAL_FWD_PACKETS': 3,
                 'TOTAL_LENGTH_OF_BWD_PACKETS': 0, 'PACKET_LENGTH_MEAN': 4.8}
    assert any('Slow-Rate' in a['rule_name'] for a in engine.analyze_flow(slow_flow))


class _StubPredictor:
    """Returns a fixed ML confidence for every row."""

    def __init__(self, confidence: float):
        self.confidence = confidence

    def predict_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        out = df.copy()
        out['ml_binary_pred'] = int(self.confidence >= 0.5)
        out['ml_confidence'] = self.confidence
        out['ml_attack_category'] = 'DoS Hulk' if self.confidence >= 0.5 else 'Benign'
        out['ml_is_anomaly'] = False
        out['ml_anomaly_score'] = 0.0
        return out


def test_hybrid_threshold_and_detection_method():
    quiet = pd.DataFrame([{'DESTINATION_PORT': 443, 'FLOW_DURATION': 50000, 'FLOW_PACKETS_S': 10.0, 'TOTAL_FWD_PACKETS': 5}])
    ssh = pd.DataFrame([{'DESTINATION_PORT': 22, 'FLOW_DURATION': 12_000_000, 'TOTAL_FWD_PACKETS': 21, 'PACKET_LENGTH_MEAN': 88}])

    # ML confidence 0.6: flagged at the default threshold, not at a stricter one
    detector = HybridDetector(predictor=_StubPredictor(0.6))
    assert detector.analyze(quiet, ml_threshold=0.5).iloc[0]['detection_method'] == 'ML Only'
    strict = detector.analyze(quiet, ml_threshold=0.9).iloc[0]
    assert strict['final_prediction'] == 'Benign'
    assert strict['severity'] == 'None'

    assert detector.analyze(ssh, ml_threshold=0.5).iloc[0]['detection_method'] == 'Both ML & Rules'

    rules_only = HybridDetector(predictor=_StubPredictor(0.05)).analyze(ssh).iloc[0]
    assert rules_only['detection_method'] == 'Rules Only'
    assert rules_only['attack_category'] == 'Possible Brute Force Attack'


@pytest.mark.skipif(not os.path.exists(BINARY_MODEL_PATH), reason="trained model not available")
def test_hybrid_end_to_end_keeps_rows_aligned():
    # Raw CIC-IDS2017 style headers plus duplicate rows: every input row must get one result
    row = {' Destination Port': 80, ' Flow Duration': 99_000_000, ' Total Fwd Packets': 3,
           'Total Length of Bwd Packets': 0, ' Flow Packets/s': np.inf}
    df = pd.DataFrame([row, row, row])
    results = HybridDetector().analyze(df)
    assert len(results) == 3
    assert (results['triggered_rules'].str.contains('Slow-Rate')).all()
