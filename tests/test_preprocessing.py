import pytest
import pandas as pd
import numpy as np
from src.data_loader import normalize_column_names
from src.preprocessing import clean_dataframe, prepare_features_and_labels


def test_normalize_column_names():
    df = pd.DataFrame(columns=[' Destination Port', ' Flow Duration', 'LABEL', ' Attack '])
    norm_df = normalize_column_names(df)
    assert 'DESTINATION_PORT' in norm_df.columns
    assert 'FLOW_DURATION' in norm_df.columns
    assert 'Label' in norm_df.columns
    assert 'Attack' in norm_df.columns


def test_clean_dataframe_inf_and_nan():
    data = {
        'DESTINATION_PORT': [80, 443, 22, 80, 80],
        'FLOW_DURATION': [100, np.inf, -np.inf, np.nan, 100],
        'TOTAL_FWD_PACKETS': [10, 20, 30, 40, 10],
        'Label': ['BENIGN', 'BENIGN', 'BENIGN', 'BENIGN', 'BENIGN']
    }
    df = pd.DataFrame(data)
    cleaned, stats = clean_dataframe(df)

    # Inf and NaN replaced and filled with median
    assert not np.isinf(cleaned['FLOW_DURATION']).any()
    assert not cleaned['FLOW_DURATION'].isna().any()
    # Duplicate row (index 0 and 4) removed
    assert stats['duplicates_removed'] >= 1


def test_prepare_features_and_labels():
    data = {
        'DESTINATION_PORT': [80, 22, 443],
        'FLOW_DURATION': [100, 200, 300],
        'Label': ['BENIGN', 'DoS Hulk', 'BENIGN'],
        'Attack': ['Benign', 'DoS Hulk', 'Benign']
    }
    df = pd.DataFrame(data)
    X, y_bin, y_att, feats = prepare_features_and_labels(df)

    assert 'Label' not in X.columns
    assert 'Attack' not in X.columns
    assert list(y_bin) == [0, 1, 0]
    assert len(feats) == 2
