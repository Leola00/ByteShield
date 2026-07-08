"""Predictive financial risk forecast using the trained financial fraud model."""

from __future__ import annotations

import json
import math
import os
import pickle
import sys
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import joblib
import numpy as np
import tensorflow as tf

BACKEND_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BACKEND_DIR / "financial_fraud_model.h5"
SCALER_PATH = BACKEND_DIR / "financial_scaler.pkl"
FEATURES_PATH = BACKEND_DIR / "important_financial_features.pkl"

BREAKDOWN_KEYS = [
    "senderAuthenticity",
    "languageAnalysis",
    "linkSafety",
    "financialFraudIndicators",
    "socialEngineeringIndicators",
    "urgencyDetection",
]

_model = None
_scaler = None
_feature_order = None
_scaler_mean = None


def _load_artifacts() -> None:
    global _model, _scaler, _feature_order, _scaler_mean

    if _model is not None:
        return

    for path in (MODEL_PATH, SCALER_PATH, FEATURES_PATH):
        if not path.exists():
            raise FileNotFoundError(f"Missing model artifact: {path}")

    with FEATURES_PATH.open("rb") as handle:
        _feature_order = pickle.load(handle)

    _scaler = joblib.load(SCALER_PATH)
    _scaler_mean = np.array(_scaler.mean_, dtype=np.float32)
    _model = tf.keras.models.load_model(MODEL_PATH)


def _estimate_loss_sar(classification: str, text: str, risk_score: float) -> float:
    cls = str(classification or "")
    lower = str(text or "").lower()
    risk = float(risk_score or 0)

    if cls.startswith("High") or risk >= 61:
        if any(word in lower for word in ("ceo", "manager", "مدير", "رئيس")):
            return 50000.0
        return 5000.0
    if cls.startswith("Medium") or cls.startswith("Suspicious") or 31 <= risk <= 60:
        return 1500.0
    return 0.0


def _build_feature_vector(payload: dict) -> np.ndarray:
    risk_score = float(payload.get("riskScore") or 0)
    risk_norm = max(0.0, min(1.0, risk_score / 100.0))
    breakdown = payload.get("riskBreakdown") or {}
    text = str(payload.get("text") or "")
    classification = str(payload.get("classification") or "")

    estimated_loss = payload.get("estimatedLossSAR")
    if estimated_loss is None:
        estimated_loss = _estimate_loss_sar(classification, text, risk_score)
    amount = float(estimated_loss or 0)
    if amount <= 0:
        amount = 12.0 + risk_norm * 4800.0

    vec = _scaler_mean.copy()
    vec[_feature_order.index("Amount")] = min(max(amount, 1.0), 50000.0)
    vec[_feature_order.index("Time")] = float(
        payload.get("timeSeconds")
        or (datetime.now(timezone.utc).hour * 3600 + datetime.now(timezone.utc).minute * 60)
    )

    for index in range(1, 29):
        key = BREAKDOWN_KEYS[(index - 1) % len(BREAKDOWN_KEYS)]
        signal = float(breakdown.get(key, risk_score) or risk_score) / 100.0
        feature_name = f"V{index}"
        feature_idx = _feature_order.index(feature_name)
        baseline = float(_scaler_mean[feature_idx])
        vec[feature_idx] = baseline * (1.0 - signal) + math.sin(index * 0.65) * 0.04 * signal

    return vec


def _forecast_level(combined_score: float) -> str:
    if combined_score >= 75:
        return "Critical"
    if combined_score >= 55:
        return "High"
    if combined_score >= 30:
        return "Medium"
    return "Low"


def predict_financial_risk(payload: dict) -> dict:
    _load_artifacts()

    risk_score = float(payload.get("riskScore") or 0)
    classification = str(payload.get("classification") or "")
    text = str(payload.get("text") or "")
    estimated_loss = payload.get("estimatedLossSAR")
    if estimated_loss is None:
        estimated_loss = _estimate_loss_sar(classification, text, risk_score)

    vector = _build_feature_vector(payload)
    scaled = _scaler.transform(vector.reshape(1, -1))
    model_probability = float(_model.predict(scaled, verbose=0)[0][0])
    model_probability = max(0.0, min(1.0, model_probability))

    combined_score = round((risk_score * 0.65) + (model_probability * 100 * 0.35))
    combined_score = int(max(0, min(100, combined_score)))
    predicted_loss_sar = round(float(estimated_loss or 0) * (1.0 + model_probability))

    return {
        "success": True,
        "model": "financial_fraud_model",
        "featureCount": len(_feature_order),
        "riskScore": risk_score,
        "classification": classification,
        "baselineLossSAR": round(float(estimated_loss or 0)),
        "fraudProbability": round(model_probability, 4),
        "financialRiskScore": combined_score,
        "forecastLevel": _forecast_level(combined_score),
        "predictedLossSAR": predicted_loss_sar,
        "forecastSummaryAr": (
            f"توقع نموذج المخاطر المالية: {combined_score}/100 — "
            f"خسارة محتملة {predicted_loss_sar:,.0f} ر.س."
        ),
        "forecastSummaryEn": (
            f"Financial risk forecast: {combined_score}/100 — "
            f"projected exposure {predicted_loss_sar:,.0f} SAR."
        ),
    }


def main() -> int:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")

        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        result = predict_financial_risk(payload)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
