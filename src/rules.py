import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional

# Thresholds are per-flow heuristics. CIC-IDS2017 durations are in microseconds.
DEFAULT_RULE_CONFIG = {
    # Port Scan rule: tiny probe flow answered by a reset (closed port)
    "port_scan_max_fwd_packets": 2,
    "port_scan_max_bwd_packets": 1,
    "port_scan_max_fwd_bytes": 6,
    "port_scan_duration_max": 1000.0,

    # DoS / DDoS flood rule: sustained high packet rate.
    # A minimum packet count is required because the rate of a 2-packet flow is meaningless.
    "dos_flow_packets_s": 20000.0,
    "dos_fwd_packets_min": 100,

    # Slow-rate DoS rule (Slowloris / Slow HTTP): connection held open with no server data
    "slow_dos_ports": [80, 443, 8080],
    "slow_dos_duration_min": 60_000_000.0,
    "slow_dos_fwd_packets_min": 2,
    "slow_dos_bwd_bytes_max": 0,

    # Brute Force rule: many small packets exchanged with an authentication service
    "brute_force_ports": [21, 22, 23, 3389],  # FTP, SSH, Telnet, RDP
    "brute_force_packets_min": 8,
    "brute_force_packet_len_mean_max": 100.0,

    # Suspicious Flag / Traffic Pattern rule thresholds
    "urg_flag_threshold": 1,
    "psh_flag_threshold": 1,
    "zero_window_fwd_packets_min": 5,  # Flag if INIT_WIN_BYTES_FORWARD == 0 with more packets than this

    # Rule toggles
    "enable_port_scan": True,
    "enable_dos": True,
    "enable_slow_dos": True,
    "enable_brute_force": True,
    "enable_suspicious_flags": True,
}


class RuleBasedEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = DEFAULT_RULE_CONFIG.copy()
        if config:
            self.config.update(config)

    def analyze_flow(self, flow) -> List[Dict[str, Any]]:
        """
        Evaluate a single network flow (pd.Series or dict) against active heuristic rules.
        Returns a list of triggered alert dictionaries.
        """
        alerts = []

        # Helper to get flow value safely (missing / NaN / non-numeric -> default)
        def get_val(key: str, default: float = 0.0) -> float:
            try:
                val = float(flow.get(key, default))
            except (TypeError, ValueError):
                return default
            return default if np.isnan(val) else val

        dest_port = int(get_val('DESTINATION_PORT', 0))
        flow_duration = get_val('FLOW_DURATION', 0)
        flow_packets_s = get_val('FLOW_PACKETS_S', 0)
        fwd_packets = get_val('TOTAL_FWD_PACKETS', 0)
        bwd_packets = get_val('TOTAL_BACKWARD_PACKETS', 0)
        fwd_bytes = get_val('TOTAL_LENGTH_OF_FWD_PACKETS', 0)
        # -1 = unknown, so rules needing the reverse direction stay silent when it is absent
        bwd_bytes = get_val('TOTAL_LENGTH_OF_BWD_PACKETS', -1)
        packet_len_mean = get_val('PACKET_LENGTH_MEAN', 0)
        psh_flags = get_val('PSH_FLAG_COUNT', 0)
        urg_flags = get_val('URG_FLAG_COUNT', 0)
        init_win_fwd = get_val('INIT_WIN_BYTES_FORWARD', -1)
        init_win_bwd = get_val('INIT_WIN_BYTES_BACKWARD', -1)

        # 1. Port Scan Rule
        if self.config.get("enable_port_scan", True):
            ps_dur = self.config["port_scan_duration_max"]
            if (
                1 <= fwd_packets <= self.config["port_scan_max_fwd_packets"]
                and bwd_packets <= self.config["port_scan_max_bwd_packets"]
                and fwd_bytes <= self.config["port_scan_max_fwd_bytes"]
                and init_win_bwd == 0
                and flow_duration < ps_dur
            ):
                alerts.append({
                    "rule_name": "Possible Port Scan",
                    "severity": "Medium",
                    "triggering_features": f"Fwd Packets ({fwd_packets:.0f}), Fwd Bytes ({fwd_bytes:.0f}), Init Win Bytes Bwd = 0, Duration ({flow_duration:.0f}µs) < {ps_dur:.0f}µs",
                    "explanation": f"Tiny payload-less probe ({fwd_packets:.0f} packet(s), {flow_duration:.0f}µs) to port {dest_port} answered with a zero-window reset, matching a port scanning signature."
                })

        # 2. DoS / DDoS Flood Rule
        if self.config.get("enable_dos", True):
            dos_rate = self.config["dos_flow_packets_s"]
            dos_pkts = self.config["dos_fwd_packets_min"]
            if flow_packets_s > dos_rate and fwd_packets >= dos_pkts:
                alerts.append({
                    "rule_name": "Possible Denial of Service (DoS/DDoS)",
                    "severity": "High",
                    "triggering_features": f"Flow Packets/s ({flow_packets_s:,.0f}) > {dos_rate:,.0f} AND Total Fwd Packets ({fwd_packets:.0f}) >= {dos_pkts}",
                    "explanation": f"Abnormally massive packet rate ({flow_packets_s:,.0f} pkts/s over {fwd_packets:.0f} packets) directed at port {dest_port} indicating potential DoS flood attack."
                })

        # 3. Slow-Rate DoS Rule
        if self.config.get("enable_slow_dos", True):
            slow_dur = self.config["slow_dos_duration_min"]
            if (
                dest_port in self.config["slow_dos_ports"]
                and flow_duration > slow_dur
                and fwd_packets >= self.config["slow_dos_fwd_packets_min"]
                and 0 <= bwd_bytes <= self.config["slow_dos_bwd_bytes_max"]
            ):
                alerts.append({
                    "rule_name": "Possible Slow-Rate DoS (Slowloris-style)",
                    "severity": "Medium",
                    "triggering_features": f"Target Port {dest_port}, Duration ({flow_duration/1e6:.0f}s) > {slow_dur/1e6:.0f}s, Bwd Bytes ({bwd_bytes:.0f})",
                    "explanation": f"Connection to web port {dest_port} held open for {flow_duration/1e6:.0f}s without the server sending any data, matching slow-rate DoS behaviour."
                })

        # 4. Repeated Connection / Brute Force Rule
        if self.config.get("enable_brute_force", True):
            bf_ports = self.config["brute_force_ports"]
            bf_pkts = self.config["brute_force_packets_min"]
            bf_len = self.config["brute_force_packet_len_mean_max"]
            if dest_port in bf_ports and fwd_packets >= bf_pkts and packet_len_mean < bf_len:
                alerts.append({
                    "rule_name": "Possible Brute Force Attack",
                    "severity": "High",
                    "triggering_features": f"Target Port {dest_port}, Fwd Packets ({fwd_packets:.0f}) >= {bf_pkts}, Mean Packet Length ({packet_len_mean:.0f}) < {bf_len:.0f}",
                    "explanation": f"Many small packets exchanged with authentication service on port {dest_port} (FTP/SSH/Telnet/RDP), consistent with repeated login attempts."
                })

        # 5. Suspicious Flags / Anomalous Traffic Pattern Rules
        if self.config.get("enable_suspicious_flags", True):
            if urg_flags >= self.config["urg_flag_threshold"] and psh_flags >= self.config["psh_flag_threshold"]:
                alerts.append({
                    "rule_name": "Suspicious TCP Flags (URG+PSH)",
                    "severity": "Medium",
                    "triggering_features": f"URG Flag ({urg_flags:.0f}), PSH Flag ({psh_flags:.0f})",
                    "explanation": "Unusual TCP control flag combination (URGent + PSH push flags set simultaneously)."
                })
            if init_win_fwd == 0 and fwd_packets > self.config["zero_window_fwd_packets_min"]:
                alerts.append({
                    "rule_name": "Zero Window Size Traffic",
                    "severity": "Low",
                    "triggering_features": f"Init Window Bytes Fwd = 0, Fwd Packets = {fwd_packets:.0f}",
                    "explanation": "Client attempting data transmission with 0 TCP window buffer size."
                })

        return alerts

    def analyze_dataframe(self, df: pd.DataFrame) -> List[List[Dict[str, Any]]]:
        """
        Evaluate all rows in a pandas DataFrame against active rules.
        """
        return [self.analyze_flow(row) for row in df.to_dict("records")]
