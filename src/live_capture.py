import time
import threading
import pandas as pd
from typing import Dict, Any, List, Optional
from collections import defaultdict

try:
    from scapy.all import sniff, get_if_list, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

from src.rules import RuleBasedEngine


class LivePacketCapturer:
    def __init__(self, rule_engine: Optional[RuleBasedEngine] = None):
        self.rule_engine = rule_engine if rule_engine is not None else RuleBasedEngine()
        self.is_capturing = False
        self.capture_thread = None
        self.packet_count = 0
        self.flows = defaultdict(lambda: {
            "start_time": time.time(),
            "last_time": time.time(),
            "fwd_packets": 0,
            "bwd_packets": 0,
            "fwd_bytes": 0,
            "bwd_bytes": 0,
            "dest_port": 0,
            "protocol": "TCP",
            "psh_flags": 0,
            "urg_flags": 0,
            "source_ip": "",
            "dest_ip": ""
        })
        self.alerts = []

    def get_interfaces(self) -> List[str]:
        if not SCAPY_AVAILABLE:
            return ["Default Adapter (Scapy Not Installed)"]
        try:
            interfaces = get_if_list()
            return interfaces if interfaces else ["Default Adapter"]
        except Exception:
            return ["Default Adapter"]

    def _packet_callback(self, pkt):
        if not pkt.haslayer(IP):
            return

        self.packet_count += 1
        now = time.time()
        ip_layer = pkt.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "OTHER")
        sport = 0
        dport = 0
        flags = ""

        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        flow_key = (src_ip, dst_ip, dport, proto)
        flow_data = self.flows[flow_key]
        
        flow_data["last_time"] = now
        flow_data["fwd_packets"] += 1
        flow_data["fwd_bytes"] += len(pkt)
        flow_data["dest_port"] = dport
        flow_data["protocol"] = proto
        flow_data["source_ip"] = src_ip
        flow_data["dest_ip"] = dst_ip

        if 'P' in flags:
            flow_data["psh_flags"] += 1
        if 'U' in flags:
            flow_data["urg_flags"] += 1

        # Periodic check per 10 packets for live rule alert
        if self.packet_count % 10 == 0:
            duration_us = (now - flow_data["start_time"]) * 1_000_000.0
            pkts_per_s = (flow_data["fwd_packets"] / (duration_us / 1_000_000.0)) if duration_us > 0 else 0

            flow_series = pd.Series({
                "DESTINATION_PORT": dport,
                "FLOW_DURATION": duration_us,
                "FLOW_PACKETS_S": pkts_per_s,
                "TOTAL_FWD_PACKETS": flow_data["fwd_packets"],
                "PACKET_LENGTH_MEAN": flow_data["fwd_bytes"] / max(1, flow_data["fwd_packets"]),
                "PSH_FLAG_COUNT": flow_data["psh_flags"],
                "URG_FLAG_COUNT": flow_data["urg_flags"]
            })

            rule_alerts = self.rule_engine.analyze_flow(flow_series)
            for alert in rule_alerts:
                alert_entry = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "dest_port": dport,
                    "protocol": proto,
                    "rule_name": alert["rule_name"],
                    "severity": alert["severity"],
                    "explanation": alert["explanation"]
                }
                # Prevent duplicates
                if alert_entry not in self.alerts:
                    self.alerts.append(alert_entry)

    def start_capture(self, interface: Optional[str] = None):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy library is not installed or unavailable.")

        if self.is_capturing:
            return

        self.is_capturing = True
        self.packet_count = 0
        self.flows.clear()
        self.alerts.clear()

        def _sniff_target():
            try:
                kwargs = {"prn": self._packet_callback, "store": False}
                if interface and interface != "Default Adapter":
                    kwargs["iface"] = interface
                sniff(**kwargs)
            except Exception as e:
                print(f"[!] Live capture error: {e}")
            finally:
                self.is_capturing = False

        self.capture_thread = threading.Thread(target=_sniff_target, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        self.is_capturing = False

    def get_stats(self) -> Dict[str, Any]:
        """Return live capture stats."""
        return {
            "is_capturing": self.is_capturing,
            "total_packets": self.packet_count,
            "active_flows": len(self.flows),
            "alert_count": len(self.alerts),
            "alerts": self.alerts[-20:]  # Last 20 live alerts
        }

