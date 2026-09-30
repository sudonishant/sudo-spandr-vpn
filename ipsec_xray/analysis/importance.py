"""Feature importance extractor for Random Forest inference models.

Provides MDI (Mean Decrease in Impurity) feature importances for cipher,
mode, and traffic classification models (including CalibratedClassifierCV ensembles).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from ..ml.models import MODEL_DIR
from .features import CIPHER_FEATURE_NAMES, TRAFFIC_FEATURE_NAMES


def get_feature_importances(model_type: str = "cipher") -> list[dict[str, Any]]:
    """Retrieve ranked feature importances for a trained model.

    Args:
        model_type: One of 'cipher', 'traffic', or 'mode'.

    Returns:
        List of dicts: [{'feature': name, 'importance': float, 'rank': int}, ...]
    """
    model_file = Path(MODEL_DIR) / f"{model_type}_rf.joblib"
    if not model_file.exists():
        return []

    bundle = joblib.load(model_file)
    clf = bundle.get("clf") if isinstance(bundle, dict) else bundle

    # Extract feature importances whether direct RandomForest or CalibratedClassifierCV
    if hasattr(clf, "feature_importances_"):
        importances = clf.feature_importances_
    elif hasattr(clf, "calibrated_classifiers_"):
        estimators = []
        for cc in clf.calibrated_classifiers_:
            estimator = getattr(cc, "estimator", getattr(cc, "base_estimator", None))
            if estimator and hasattr(estimator, "feature_importances_"):
                estimators.append(estimator.feature_importances_)
        if estimators:
            importances = np.mean(estimators, axis=0)
        else:
            return []
    else:
        return []

    if model_type in ("cipher", "mode"):
        names = CIPHER_FEATURE_NAMES
    else:
        names = TRAFFIC_FEATURE_NAMES

    # Match up names with importances
    results = []
    for i, imp in enumerate(importances):
        name = names[i] if i < len(names) else f"feature_{i}"
        results.append({
            "feature": name,
            "importance": round(float(imp), 5),
        })

    results.sort(key=lambda x: x["importance"], reverse=True)
    for rank, item in enumerate(results, 1):
        item["rank"] = rank

    return results


def export_all_importances() -> dict[str, list[dict[str, Any]]]:
    """Export feature importance summaries for all trained models."""
    return {
        "cipher": get_feature_importances("cipher"),
        "traffic": get_feature_importances("traffic"),
        "mode": get_feature_importances("mode"),
    }


if __name__ == "__main__":
    out = export_all_importances()
    print(json.dumps(out, indent=2))
