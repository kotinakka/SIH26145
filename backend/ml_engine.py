"""
Phase 4 — Hybrid ML inference wrapper for detector.py.
Loads trained Random Forest & Isolation Forest artifacts from ../ml/.
"""

import os
import warnings
import joblib
import numpy as np

warnings.filterwarnings("ignore", category=UserWarning)

ML_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml"))

_CLF = None
_ISO = None
_SCALER = None
_COLS = None


def _load_models():
    global _CLF, _ISO, _SCALER, _COLS
    if _CLF is not None:
        return True
    rf_path = os.path.join(ML_DIR, "rf_threat_model.joblib")
    if not os.path.exists(rf_path):
        return False
    try:
        _CLF = joblib.load(rf_path)
        _ISO = joblib.load(os.path.join(ML_DIR, "isolation_forest.joblib"))
        _SCALER = joblib.load(os.path.join(ML_DIR, "scaler.joblib"))
        _COLS = joblib.load(os.path.join(ML_DIR, "feature_columns.joblib"))
        return True
    except Exception:
        return False


def predict_flow_ml(flow):
    """
    Returns (predicted_class, ml_probability, is_anomaly) or None if models aren't trained yet.
    """
    if not _load_models():
        return None

    vec = []
    for col in _COLS:
        val = flow.get(col, 0.0)
        if val is None:
            val = 0.0
        elif isinstance(val, bool):
            val = 1.0 if val else 0.0
        vec.append(float(val))

    X_scaled = _SCALER.transform(np.array([vec], dtype=float))
    probs = _CLF.predict_proba(X_scaled)[0]
    best_idx = int(np.argmax(probs))
    pred_class = str(_CLF.classes_[best_idx])
    ml_conf = float(probs[best_idx])
    is_anomaly = int(_ISO.predict(X_scaled)[0]) == -1

    return pred_class, ml_conf, is_anomaly