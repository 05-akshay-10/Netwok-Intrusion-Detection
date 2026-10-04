import os
import glob
import pandas as pd
import numpy as np
from typing import Tuple, Dict, Any, Optional

# Standard column mapping dictionary to normalize variations in CIC-IDS2017 column names
COLUMN_MAPPING = {
    'destination port': 'DESTINATION_PORT',
    'dest port': 'DESTINATION_PORT',
    'destination_port': 'DESTINATION_PORT',
    'flow duration': 'FLOW_DURATION',
    'total fwd packets': 'TOTAL_FWD_PACKETS',
    'total backward packets': 'TOTAL_BACKWARD_PACKETS',
    'total length of fwd packets': 'TOTAL_LENGTH_OF_FWD_PACKETS',
    'total length of bwd packets': 'TOTAL_LENGTH_OF_BWD_PACKETS',
    'fwd packet length max': 'FWD_PACKET_LENGTH_MAX',
    'fwd packet length min': 'FWD_PACKET_LENGTH_MIN',
    'fwd packet length mean': 'FWD_PACKET_LENGTH_MEAN',
    'fwd packet length std': 'FWD_PACKET_LENGTH_STD',
    'bwd packet length max': 'BWD_PACKET_LENGTH_MAX',
    'bwd packet length min': 'BWD_PACKET_LENGTH_MIN',
    'bwd packet length mean': 'BWD_PACKET_LENGTH_MEAN',
    'bwd packet length std': 'BWD_PACKET_LENGTH_STD',
    'flow bytes/s': 'FLOW_BYTES_S',
    'flow packets/s': 'FLOW_PACKETS_S',
    'flow iat mean': 'FLOW_IAT_MEAN',
    'flow iat std': 'FLOW_IAT_STD',
    'flow iat max': 'FLOW_IAT_MAX',
    'flow iat min': 'FLOW_IAT_MIN',
    'fwd iat total': 'FWD_IAT_TOTAL',
    'fwd iat mean': 'FWD_IAT_MEAN',
    'fwd iat std': 'FWD_IAT_STD',
    'fwd iat max': 'FWD_IAT_MAX',
    'fwd iat min': 'FWD_IAT_MIN',
    'bwd iat total': 'BWD_IAT_TOTAL',
    'bwd iat mean': 'BWD_IAT_MEAN',
    'bwd iat std': 'BWD_IAT_STD',
    'bwd iat max': 'BWD_IAT_MAX',
    'bwd iat min': 'BWD_IAT_MIN',
    'fwd psh flags': 'FWD_PSH_FLAGS',
    'fwd urg flags': 'FWD_URG_FLAGS',
    'fwd header length': 'FWD_HEADER_LENGTH',
    'bwd header length': 'BWD_HEADER_LENGTH',
    'fwd packets/s': 'FWD_PACKETS_S',
    'bwd packets/s': 'BWD_PACKETS_S',
    'min packet length': 'MIN_PACKET_LENGTH',
    'max packet length': 'MAX_PACKET_LENGTH',
    'packet length mean': 'PACKET_LENGTH_MEAN',
    'packet length std': 'PACKET_LENGTH_STD',
    'packet length variance': 'PACKET_LENGTH_VARIANCE',
    'fin flag count': 'FIN_FLAG_COUNT',
    'rst flag count': 'RST_FLAG_COUNT',
    'psh flag count': 'PSH_FLAG_COUNT',
    'ack flag count': 'ACK_FLAG_COUNT',
    'urg flag count': 'URG_FLAG_COUNT',
    'ece flag count': 'ECE_FLAG_COUNT',
    'down/up ratio': 'DOWN_UP_RATIO',
    'average packet size': 'AVERAGE_PACKET_SIZE',
    'avg fwd segment size': 'AVG_FWD_SEGMENT_SIZE',
    'avg bwd segment size': 'AVG_BWD_SEGMENT_SIZE',
    'subflow fwd bytes': 'SUBFLOW_FWD_BYTES',
    'subflow bwd bytes': 'SUBFLOW_BWD_BYTES',
    'init_win_bytes_forward': 'INIT_WIN_BYTES_FORWARD',
    'init win bytes forward': 'INIT_WIN_BYTES_FORWARD',
    'init_win_bytes_backward': 'INIT_WIN_BYTES_BACKWARD',
    'init win bytes backward': 'INIT_WIN_BYTES_BACKWARD',
    'act_data_pkt_fwd': 'ACT_DATA_PKT_FWD',
    'act data pkt fwd': 'ACT_DATA_PKT_FWD',
    'min_seg_size_forward': 'MIN_SEG_SIZE_FORWARD',
    'min seg size forward': 'MIN_SEG_SIZE_FORWARD',
    'active mean': 'ACTIVE_MEAN',
    'active std': 'ACTIVE_STD',
    'active max': 'ACTIVE_MAX',
    'active min': 'ACTIVE_MIN',
    'idle mean': 'IDLE_MEAN',
    'idle std': 'IDLE_STD',
    'idle max': 'IDLE_MAX',
    'idle min': 'IDLE_MIN',
    'label': 'Label',
    'attack': 'Attack',
    'class': 'Label'
}

def find_dataset_files(base_dir: str = ".") -> list[str]:
    """Search for dataset files (.csv, .txt) in common dataset locations."""
    search_patterns = [
        os.path.join(base_dir, "data", "*.txt"),
        os.path.join(base_dir, "data", "*.csv"),
        os.path.join(base_dir, "data", "raw", "*.txt"),
        os.path.join(base_dir, "data", "raw", "*.csv"),
        os.path.join(base_dir, "*.csv"),
        os.path.join(base_dir, "*.txt"),
    ]
    found_files = []
    for pattern in search_patterns:
        found_files.extend(glob.glob(pattern))
    return sorted(list(set(found_files)))


def normalize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip spaces and map column names to a standardized UPPERCASE schema."""
    cleaned_cols = {}
    for col in df.columns:
        col_clean = str(col).strip()
        col_lower = col_clean.lower()
        if col_lower in COLUMN_MAPPING:
            cleaned_cols[col] = COLUMN_MAPPING[col_lower]
        else:
            # Fallback to uppercase snake_case
            col_norm = col_clean.upper().replace(' ', '_').replace('/', '_').replace('-', '_')
            cleaned_cols[col] = col_norm
    
    return df.rename(columns=cleaned_cols)


def load_dataset(
    file_path: str,
    sample_size: Optional[int] = None,
    random_state: int = 42
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Load a dataset CSV or TXT file with error handling and column normalization.
    
    Returns:
        (df, summary_metadata)
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset file not found at path: {file_path}")

    # Determine sep (comma vs tab vs whitespace)
    try:
        df = pd.read_csv(file_path, low_memory=False)
    except Exception:
        df = pd.read_csv(file_path, sep=r'\s+', low_memory=False)

    initial_rows = len(df)
    
    # Normalize column names
    df = normalize_column_names(df)
    
    # Strip string values if any object columns exist
    for col in df.select_dtypes(include=['object']).columns:
        df[col] = df[col].astype(str).str.strip()

    if sample_size and sample_size < len(df):
        df = df.sample(n=sample_size, random_state=random_state).reset_index(drop=True)

    metadata = {
        "file_path": file_path,
        "initial_rows": initial_rows,
        "retained_rows": len(df),
        "total_columns": len(df.columns),
        "columns": df.columns.tolist(),
        "memory_mb": round(df.memory_usage(deep=True).sum() / (1024 * 1024), 2)
    }

    return df, metadata
