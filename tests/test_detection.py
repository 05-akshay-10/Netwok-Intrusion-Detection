import pytest
import pandas as pd
from src.rules import RuleBasedEngine
from src.hybrid_detector import HybridDetector


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

    # Controlled PortScan flow example
    portscan_flow = pd.Series({
        'DESTINATION_PORT': 445,
        'FLOW_DURATION': 50,
        'FLOW_PACKETS_S': 100000.0,
        'TOTAL_FWD_PACKETS': 2,
        'PACKET_LENGTH_MEAN': 60,
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
