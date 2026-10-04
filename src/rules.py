import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional

DEFAULT_RULE_CONFIG = {
    # Port Scan rule thresholds
    "port_scan_packets_s": 50000.0,
    "port_scan_duration_max": 1000.0,
    
    # DoS / DDoS rule thresholds
    "dos_flow_packets_s": 100000.0,
    "dos_fwd_packets_min": 100,
    "dos_packet_len_mean_max": 500.0,
    
    # Brute Force rule thresholds
    "brute_force_ports": [21, 22, 23, 3389],  # FTP, SSH, Telnet, RDP
    "brute_force_packets_min": 20,
    "brute_force_duration_max": 50000.0,
    
    # Suspicious Flag / Traffic Pattern rule thresholds
    "urg_flag_threshold": 1,
    "psh_flag_threshold": 1,
    "zero_window_threshold": -1, # Flag if INIT_WIN_BYTES_FORWARD == 0
    
    # Rule toggles
    "enable_port_scan": True,
    "enable_dos": True,
    "enable_brute_force": True,
    "enable_suspicious_flags": True,
}


class RuleBasedEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = DEFAULT_RULE_CONFIG.copy()
        if config:
            self.config.update(config)

    def analyze_flow(self, flow: pd.Series) -> List[Dict[str, Any]]:
        """
        Evaluate a single network flow against active heuristic rules.
        Returns a list of triggered alert dictionaries.
        """
        alerts = []
        
        # Helper to get flow value safely
        def get_val(key: str, default: float = 0.0) -> float:
            return float(flow.get(key, default)) if not pd.isna(flow.get(key, default)) else default

        dest_port = int(get_val('DESTINATION_PORT', 0))
        flow_duration = get_val('FLOW_DURATION', 0)
        flow_packets_s = get_val('FLOW_PACKETS_S', 0)
        fwd_packets = get_val('TOTAL_FWD_PACKETS', 0)
        packet_len_mean = get_val('PACKET_LENGTH_MEAN', 0)
        psh_flags = get_val('PSH_FLAG_COUNT', 0)
        urg_flags = get_val('URG_FLAG_COUNT', 0)
        init_win_fwd = get_val('INIT_WIN_BYTES_FORWARD', -1)

        # 1. Port Scan Rule
        if self.config.get("enable_port_scan", True):
            ps_rate = self.config["port_scan_packets_s"]
            ps_dur = self.config["port_scan_duration_max"]
            if flow_packets_s > ps_rate and flow_duration < ps_dur:
                alerts.append({
                    "rule_name": "Possible Port Scan",
                    "severity": "Medium",
                    "triggering_features": f"Flow Packets/s ({flow_packets_s:,.0f}) > {ps_rate:,.0f}, Duration ({flow_duration:.0f}µs)",
                    "explanation": f"High burst rate ({flow_packets_s:,.0f} pkts/s) over short duration ({flow_duration:.0f}µs) on port {dest_port} matches port scanning signature."
                })

        # 2. DoS / DDoS Rule
        if self.config.get("enable_dos", True):
            dos_rate = self.config["dos_flow_packets_s"]
            dos_pkts = self.config["dos_fwd_packets_min"]
            if flow_packets_s > dos_rate or (fwd_packets > dos_pkts and flow_packets_s > 20000):
                alerts.append({
                    "rule_name": "Possible Denial of Service (DoS/DDoS)",
                    "severity": "High",
                    "triggering_features": f"Flow Packets/s ({flow_packets_s:,.0f}) > {dos_rate:,.0f} OR Total Fwd Packets ({fwd_packets}) > {dos_pkts}",
                    "explanation": f"Abnormally massive packet rate ({flow_packets_s:,.0f} pkts/s) directed at port {dest_port} indicating potential DoS flood attack."
                })

        # 3. Repeated Connection / Brute Force Rule
        if self.config.get("enable_brute_force", True):
            bf_ports = self.config["brute_force_ports"]
            bf_pkts = self.config["brute_force_packets_min"]
            bf_dur = self.config["brute_force_duration_max"]
            if dest_port in bf_ports and fwd_packets > bf_pkts and flow_duration < bf_dur:
                alerts.append({
                    "rule_name": "Possible Brute Force Attack",
                    "severity": "High",
                    "triggering_features": f"Target Port {dest_port}, Fwd Packets ({fwd_packets}) > {bf_pkts}, Duration ({flow_duration:.0f}µs)",
                    "explanation": f"Multiple rapid connection packets targeted at authentication service on port {dest_port} (FTP/SSH/RDP)."
                })

        # 4. Suspicious Flags / Anomalous Traffic Pattern Rule
        if self.config.get("enable_suspicious_flags", True):
            if urg_flags >= self.config["urg_flag_threshold"] and psh_flags >= self.config["psh_flag_threshold"]:
                alerts.append({
                    "rule_name": "Suspicious TCP Flags (URG+PSH)",
                    "severity": "Medium",
                    "triggering_features": f"URG Flag ({urg_flags}), PSH Flag ({psh_flags})",
                    "explanation": f"Unusual TCP control flag combination (URGent + PSH push flags set simultaneously)."
                })
            elif init_win_fwd == 0 and fwd_packets > 5:
                alerts.append({
                    "rule_name": "Zero Window Size Traffic",
                    "severity": "Low",
                    "triggering_features": f"Init Window Bytes Fwd = 0, Fwd Packets = {fwd_packets}",
                    "explanation": "Client attempting data transmission with 0 TCP window buffer size."
                })

        return alerts

    def analyze_dataframe(self, df: pd.DataFrame) -> List[List[Dict[str, Any]]]:
        """
        Evaluate all rows in a pandas DataFrame against active rules.
        """
        results = []
        for idx in range(len(df)):
            row = df.iloc[idx]
            alerts = self.analyze_flow(row)
            results.append(alerts)
        return results
