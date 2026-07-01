"""Run the trained Keras phishing model on a single URL."""

from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import joblib
import numpy as np
import tensorflow as tf

from feature_extractor import FEATURE_NAMES, extract_features

BACKEND_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BACKEND_DIR / "phishing_dl_model.h5"
SCALER_PATH = BACKEND_DIR / "scaler.pkl"
FEATURES_PATH = BACKEND_DIR / "important_features.pkl"

_model = None
_scaler = None
_feature_order = None


def _load_artifacts() -> None:
    global _model, _scaler, _feature_order

    if _model is not None:
        return

    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Missing model file: {MODEL_PATH}")
    if not SCALER_PATH.exists():
        raise FileNotFoundError(f"Missing scaler file: {SCALER_PATH}")
    if not FEATURES_PATH.exists():
        raise FileNotFoundError(f"Missing features file: {FEATURES_PATH}")

    with FEATURES_PATH.open("rb") as handle:
        _feature_order = pickle.load(handle)

    if list(_feature_order) != FEATURE_NAMES:
        _feature_order = FEATURE_NAMES

    _scaler = joblib.load(SCALER_PATH)
    _model = tf.keras.models.load_model(MODEL_PATH)


def probability_to_risk_score(probability: float) -> int:
    return int(round(max(0.0, min(1.0, probability)) * 100))


def probability_to_classification(probability: float) -> str:
    score = probability_to_risk_score(probability)
    if score <= 30:
        return "Low Risk"
    if score <= 60:
        return "Medium Risk"
    return "High Risk"


def predict_url(url: str) -> dict:
    _load_artifacts()
    features = extract_features(url)
    vector = np.array([[features[name] for name in _feature_order]], dtype=np.float32)
    scaled = _scaler.transform(vector)
    probability = float(_model.predict(scaled, verbose=0)[0][0])
    risk_score = probability_to_risk_score(probability)

    return {
        "success": True,
        "url": url,
        "phishingProbability": round(probability, 4),
        "isPhishing": probability >= 0.5,
        "riskScore": risk_score,
        "classification": probability_to_classification(probability),
        "confidence": int(round(abs(probability - 0.5) * 200)),
        "model": "phishing_dl_model",
        "featureCount": len(_feature_order),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Predict phishing probability for a URL")
    parser.add_argument("url", help="URL to analyze")
    args = parser.parse_args()

    try:
        result = predict_url(args.url)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as error:
        print(json.dumps({"success": False, "error": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
