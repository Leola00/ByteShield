"""Compare extracted features vs scaler expectations for sample URLs."""

import pickle
import sys
from pathlib import Path

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
from feature_extractor import extract_features
from predict_url import predict_url

BACKEND = Path(__file__).resolve().parent.parent
FEATURES = pickle.load(open(BACKEND / "important_features.pkl", "rb"))
SCALER = joblib.load(BACKEND / "scaler.pkl")

URLS = [
    "https://www.google.com",
    "https://www.alinma.com",
    "https://www.sama.gov.sa",
    "http://secure-bank-verify.xyz/login",
    "https://paypal.com.secure-login.xyz",
]

print("=== Predictions ===")
for url in URLS:
    r = predict_url(url)
    print(f"{r['phishingProbability']:.4f} score={r['riskScore']:3d}  {url}")

print("\n=== Feature drift (google.com vs scaler mean) ===")
feats = extract_features("https://www.google.com")
vec = np.array([feats[n] for n in FEATURES])
scaled = SCALER.transform([vec])[0]
z = np.abs((vec - SCALER.mean_) / np.where(SCALER.scale_ == 0, 1, SCALER.scale_))
worst = np.argsort(z)[-10:][::-1]
for i in worst:
    print(f"  {FEATURES[i]:30s} raw={vec[i]:12.4f} mean={SCALER.mean_[i]:10.4f} z={z[i]:8.2f}")
