import os
import joblib
import pandas as pd
import numpy as np
from typing import Tuple, Dict, Any, List, Optional
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

SCALER_PATH = os.path.join("models", "feature_scaler.joblib")
FEATURE_NAMES_PATH = os.path.join("models", "feature_names.joblib")


def clean_dataframe(df: pd.DataFrame, drop_duplicates: bool = True) -> Tuple[pd.DataFrame, Dict[str, int]]:
    """
    Clean dataset by handling infinite values, NaNs, and duplicates.
    Pass drop_duplicates=False at inference time so output rows stay aligned with input rows.
    """
    initial_count = len(df)
    
    # Copy to avoid mutating original df
    cleaned = df.copy()
    
    # Identify non-target columns
    target_cols = [c for c in ['LABEL', 'ATTACK', 'CLASS', 'TARGET'] if c in [col.upper() for col in cleaned.columns]]
    
    # Find actual matching column names for targets
    actual_target_cols = [col for col in cleaned.columns if col.upper() in target_cols]
    feature_cols = [col for col in cleaned.columns if col not in actual_target_cols]
    
    # Replace infinite values with NaN in numeric columns
    numeric_cols = cleaned[feature_cols].select_dtypes(include=[np.number]).columns
    cleaned[numeric_cols] = cleaned[numeric_cols].replace([np.inf, -np.inf], np.nan)
    
    # Count rows with NaNs
    nan_rows = cleaned[numeric_cols].isna().any(axis=1).sum()
    
    # Impute NaNs with column median (or 0 if all median is NaN)
    for col in numeric_cols:
        if cleaned[col].isna().any():
            median_val = cleaned[col].median()
            cleaned[col] = cleaned[col].fillna(median_val if not np.isnan(median_val) else 0.0)
            
    # Remove duplicate rows
    dupes_count = 0
    if drop_duplicates:
        dupes_count = cleaned.duplicated().sum()
        cleaned = cleaned.drop_duplicates().reset_index(drop=True)
    
    retained_count = len(cleaned)
    
    stats = {
        "initial_rows": initial_count,
        "nan_rows_handled": int(nan_rows),
        "duplicates_removed": int(dupes_count),
        "retained_rows": retained_count,
        "removed_rows": initial_count - retained_count
    }
    
    return cleaned, stats


def prepare_features_and_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, Optional[pd.Series], List[str]]:
    """
    Extract feature matrix X, binary label y_binary, and multiclass attack label y_attack if present.
    Ensures target labels are excluded from X.
    """
    df_clean, _ = clean_dataframe(df)
    
    # Identify binary label column
    binary_col = None
    for candidate in ['Label', 'LABEL', 'Class', 'CLASS', 'Target', 'TARGET']:
        if candidate in df_clean.columns:
            binary_col = candidate
            break
            
    # Identify attack category column
    attack_col = None
    for candidate in ['Attack', 'ATTACK', 'Attack_Category', 'ATTACK_CATEGORY']:
        if candidate in df_clean.columns:
            attack_col = candidate
            break

    if binary_col is None and attack_col is None:
        raise ValueError("Could not find a valid Label or Attack column in dataset.")

    # Exclude targets from features
    target_names = [c for c in [binary_col, attack_col] if c is not None]
    feature_cols = [col for col in df_clean.columns if col not in target_names]
    
    # Retain numeric features only
    X = df_clean[feature_cols].select_dtypes(include=[np.number]).copy()
    feature_list = X.columns.tolist()

    # Binary label mapping
    if binary_col is not None:
        y_raw = df_clean[binary_col]
        # If numeric (0 or 1)
        if pd.api.types.is_numeric_dtype(y_raw):
            y_binary = y_raw.astype(int)
        else:
            # Map 'BENIGN' / 'Benign' to 0, anything else to 1
            y_binary = y_raw.astype(str).str.strip().str.upper().apply(lambda x: 0 if x in ['BENIGN', '0'] else 1)
    else:
        # Fallback to attack column for binary label
        y_binary = df_clean[attack_col].astype(str).str.strip().str.upper().apply(lambda x: 0 if x in ['BENIGN', '0'] else 1)

    # Multiclass attack label
    if attack_col is not None:
        y_attack = df_clean[attack_col].astype(str).str.strip()
    elif binary_col is not None and not pd.api.types.is_numeric_dtype(df_clean[binary_col]):
        y_attack = df_clean[binary_col].astype(str).str.strip()
    else:
        y_attack = y_binary.apply(lambda x: 'Benign' if x == 0 else 'Malicious')

    return X, y_binary, y_attack, feature_list


def fit_and_split_data(
    X: pd.DataFrame,
    y_binary: pd.Series,
    y_attack: Optional[pd.Series] = None,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Split data into Train, Validation, and Test sets.
    Fits StandardScaler ONLY on training data to prevent data leakage.
    Saves scaler and feature list to models/.
    """
    # Split row positions ONCE so X, y_binary and y_attack always refer to the same rows.
    # Stratify on attack category when every class is large enough, else on the binary label.
    def _split(idx: np.ndarray, size: float) -> Tuple[np.ndarray, np.ndarray]:
        if y_attack is not None:
            try:
                return train_test_split(
                    idx, test_size=size, random_state=random_state, stratify=y_attack.iloc[idx]
                )
            except ValueError:
                pass
        return train_test_split(
            idx, test_size=size, random_state=random_state, stratify=y_binary.iloc[idx]
        )

    # 1. First split out test set
    train_val_idx, test_idx = _split(np.arange(len(X)), test_size)

    # 2. Split train_val into train and validation sets
    relative_val_size = val_size / (1.0 - test_size)
    train_idx, val_idx = _split(train_val_idx, relative_val_size)

    X_train, X_val, X_test = X.iloc[train_idx], X.iloc[val_idx], X.iloc[test_idx]
    y_bin_train, y_bin_val, y_bin_test = y_binary.iloc[train_idx], y_binary.iloc[val_idx], y_binary.iloc[test_idx]

    y_att_train, y_att_val, y_att_test = None, None, None
    if y_attack is not None:
        y_att_train, y_att_val, y_att_test = y_attack.iloc[train_idx], y_attack.iloc[val_idx], y_attack.iloc[test_idx]

    # 3. Fit scaler ONLY on X_train
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    feature_names = X.columns.tolist()

    # Save fitted scaler & feature list
    os.makedirs("models", exist_ok=True)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(feature_names, FEATURE_NAMES_PATH)

    return {
        "X_train": X_train_scaled,
        "X_val": X_val_scaled,
        "X_test": X_test_scaled,
        "X_train_df": X_train,
        "X_val_df": X_val,
        "X_test_df": X_test,
        "y_bin_train": y_bin_train,
        "y_bin_val": y_bin_val,
        "y_bin_test": y_bin_test,
        "y_att_train": y_att_train,
        "y_att_val": y_att_val,
        "y_att_test": y_att_test,
        "scaler": scaler,
        "feature_names": feature_names
    }


def transform_new_data(df: pd.DataFrame) -> Tuple[np.ndarray, pd.DataFrame, List[str]]:
    """
    Transform unseen user CSV data using the saved scaler and exact training features.
    Aligns columns, handles missing/extra features gracefully.
    """
    if not os.path.exists(SCALER_PATH) or not os.path.exists(FEATURE_NAMES_PATH):
        raise FileNotFoundError("Scaler or feature list not found in models/. Please train the model first.")

    scaler: StandardScaler = joblib.load(SCALER_PATH)
    feature_names: List[str] = joblib.load(FEATURE_NAMES_PATH)

    # Clean input df (keep duplicates: every input flow must get exactly one prediction)
    df_clean, _ = clean_dataframe(df, drop_duplicates=False)

    # Align columns to match training features exactly
    aligned_df = pd.DataFrame(index=df_clean.index)
    for col in feature_names:
        if col in df_clean.columns:
            aligned_df[col] = pd.to_numeric(df_clean[col], errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0.0)
        else:
            aligned_df[col] = 0.0

    # Scale aligned features (column names match those the scaler was fitted with)
    X_scaled = scaler.transform(aligned_df)

    return X_scaled, aligned_df, feature_names
