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


def test_split_keeps_features_and_both_labels_aligned(tmp_path, monkeypatch):
    from src import preprocessing
    monkeypatch.setattr(preprocessing, "SCALER_PATH", str(tmp_path / "scaler.joblib"))
    monkeypatch.setattr(preprocessing, "FEATURE_NAMES_PATH", str(tmp_path / "features.joblib"))
    monkeypatch.chdir(tmp_path)

    # Feature value encodes the row's labels, so any misalignment is detectable
    n = 400
    attack = pd.Series(['Benign'] * 280 + ['DoS Hulk'] * 80 + ['PortScan'] * 40)
    y_binary = (attack != 'Benign').astype(int)
    code = attack.map({'Benign': 0, 'DoS Hulk': 1, 'PortScan': 2})
    X = pd.DataFrame({'CODE': code, 'ROW': np.arange(n)})

    split = preprocessing.fit_and_split_data(X, y_binary, y_attack=attack)
    for part in ('train', 'val', 'test'):
        X_part = split[f'X_{part}_df']
        y_att = split[f'y_att_{part}']
        y_bin = split[f'y_bin_{part}']
        assert list(X_part['CODE']) == list(y_att.map({'Benign': 0, 'DoS Hulk': 1, 'PortScan': 2}))
        assert list((X_part['CODE'] > 0).astype(int)) == list(y_bin)
    assert len(split['X_train_df']) + len(split['X_val_df']) + len(split['X_test_df']) == n


def test_clean_dataframe_can_keep_duplicates():
    df = pd.DataFrame({'DESTINATION_PORT': [80, 80, 80], 'FLOW_DURATION': [1.0, 1.0, np.inf]})
    cleaned, stats = clean_dataframe(df, drop_duplicates=False)
    assert len(cleaned) == 3
    assert stats['duplicates_removed'] == 0


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
