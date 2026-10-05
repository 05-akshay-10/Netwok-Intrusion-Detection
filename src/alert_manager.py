import os
import sqlite3
import pandas as pd
from typing import Dict, Any, List, Optional

DB_PATH = os.path.join("data", "alerts.db")


class AlertManager:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS intrusion_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    protocol TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    attack_category TEXT,
                    detection_method TEXT,
                    severity TEXT,
                    ml_confidence REAL,
                    triggered_rules TEXT,
                    explanation TEXT
                )
            """)
            conn.commit()

    def save_alerts_from_df(self, df: pd.DataFrame) -> int:
        """
        Extract malicious rows from hybrid detection results and save to SQLite.
        """
        if df.empty or 'final_prediction' not in df.columns:
            return 0

        malicious_df = df[df['final_prediction'] == 'Malicious'].copy()
        if malicious_df.empty:
            return 0

        def _first(row, keys, default):
            for key in keys:
                val = row.get(key)
                if val is not None and not pd.isna(val):
                    return val
            return default

        def _port(row, keys) -> int:
            try:
                return int(float(_first(row, keys, 0)))
            except (TypeError, ValueError):
                return 0

        # Flow CSVs such as CIC-IDS2017 often carry no IP/protocol columns; record that honestly
        records_to_insert = []
        for row in malicious_df.to_dict("records"):
            records_to_insert.append((
                str(row.get('timestamp', '')),
                str(_first(row, ['SOURCE_IP', 'SRC_IP', 'source_ip'], 'N/A')),
                str(_first(row, ['DESTINATION_IP', 'DST_IP', 'dest_ip'], 'N/A')),
                str(_first(row, ['PROTOCOL', 'protocol'], 'N/A')),
                _port(row, ['SOURCE_PORT', 'source_port']),
                _port(row, ['DESTINATION_PORT', 'destination_port']),
                str(row.get('attack_category', 'Malicious')),
                str(row.get('detection_method', 'Hybrid')),
                str(row.get('severity', 'Medium')),
                float(row.get('ml_confidence_pct', 0.0)),
                str(row.get('triggered_rules', 'None')),
                str(row.get('explanation', 'Flagged intrusion alert.'))
            ))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT INTO intrusion_alerts (
                    timestamp, source_ip, destination_ip, protocol, source_port, destination_port,
                    attack_category, detection_method, severity, ml_confidence, triggered_rules, explanation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records_to_insert)
            conn.commit()

        return len(records_to_insert)

    def get_all_alerts(self, severity_filter: Optional[str] = None, method_filter: Optional[str] = None) -> pd.DataFrame:
        """
        Fetch alerts from database with optional filters.
        """
        query = "SELECT * FROM intrusion_alerts WHERE 1=1"
        params = []

        if severity_filter and severity_filter != "All":
            query += " AND severity = ?"
            params.append(severity_filter)

        if method_filter and method_filter != "All":
            query += " AND detection_method = ?"
            params.append(method_filter)

        query += " ORDER BY id DESC"

        with self._get_connection() as conn:
            df = pd.read_sql_query(query, conn, params=params)

        return df

    def clear_alert_history(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM intrusion_alerts")
            conn.commit()
