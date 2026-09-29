"""Model loading + prediction helpers (lazy singleton)."""
from __future__ import annotations

import json
import os
from typing import Optional

import numpy as np

MODEL_DIR = os.environ.get("IPSEC_XRAY_MODELS", os.path.join(os.path.dirname(__file__), "..", "..", "models"))


class Models:
    _inst: Optional["Models"] = None

    def __init__(self, model_dir: str = MODEL_DIR):
        import joblib
        self.dir = model_dir
        self.available = False
        self.meta = {}
        self.traffic = self.cipher = self.mode = None
        try:
            self.traffic = joblib.load(os.path.join(model_dir, "traffic_rf.joblib"))
            self.cipher = joblib.load(os.path.join(model_dir, "cipher_rf.joblib"))
            self.mode = joblib.load(os.path.join(model_dir, "mode_rf.joblib"))
            with open(os.path.join(model_dir, "meta.json")) as f:
                self.meta = json.load(f)
            for clf in (self.traffic, self.cipher, self.mode):
                self._single_thread(clf)
            self.available = True
        except Exception as e:  # models not trained yet
            self.error = str(e)

    @classmethod
    def get(cls) -> "Models":
        if cls._inst is None:
            cls._inst = Models()
        return cls._inst

    @staticmethod
    def _single_thread(clf) -> None:
        """We predict one flow at a time: joblib's thread pool costs far more than the trees themselves."""
        for est in [clf] + [getattr(c, "estimator", None) for c in getattr(clf, "calibrated_classifiers_", [])]:
            if est is not None and hasattr(est, "n_jobs"):
                try:
                    est.n_jobs = 1
                except Exception:
                    pass

    @staticmethod
    def _probs(clf, x: np.ndarray) -> dict:
        p = clf.predict_proba(x.reshape(1, -1))[0]
        return {str(c): float(v) for c, v in zip(clf.classes_, p)}

    def predict_traffic(self, feats: np.ndarray) -> dict:
        return self._probs(self.traffic, feats) if self.available else {}

    def predict_cipher(self, feats: np.ndarray) -> dict:
        return self._probs(self.cipher, feats) if self.available else {}

    def predict_mode(self, feats: np.ndarray) -> dict:
        return self._probs(self.mode, feats) if self.available else {}
