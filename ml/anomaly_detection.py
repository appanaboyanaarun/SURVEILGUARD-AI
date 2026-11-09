import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from typing import Dict, Any, Tuple, Optional, List
from .preprocessing import events_to_feature_matrix
from .sample_training_data import generate_baseline_normal_events


class AnomalyDetector:
    """Manages training, persistence, and inference for surveillance anomaly detection."""

    def __init__(self, model_dir: str, algorithm: str = "isolation_forest", contamination: float = 0.08):
        self.model_dir = model_dir
        os.makedirs(self.model_dir, exist_ok=True)
        self.algorithm = algorithm
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.model = None
        self.is_fitted = False
        self.model_path = os.path.join(self.model_dir, "anomaly_detector.joblib")

        # Try to load existing model, otherwise train baseline
        if os.path.exists(self.model_path):
            self.load()
        else:
            self.train_baseline()

    def _init_model(self):
        if self.algorithm == "one_class_svm":
            self.model = OneClassSVM(kernel="rbf", gamma="scale", nu=self.contamination)
        else:
            self.model = IsolationForest(
                n_estimators=150,
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1
            )

    def train(self, events: List[Dict[str, Any]]):
        """Trains scaler and model on provided surveillance event records."""
        X = events_to_feature_matrix(events)
        if len(X) < 10:
            raise ValueError("Need at least 10 event samples to train anomaly detection model.")

        self._init_model()
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True
        self.save()

    def train_baseline(self):
        """Generates synthetic baseline data and trains default model."""
        baseline_events = generate_baseline_normal_events(600)
        self.train(baseline_events)

    def save(self):
        """Saves scaler, model, and metadata to disk."""
        data = {
            "scaler": self.scaler,
            "model": self.model,
            "algorithm": self.algorithm,
            "contamination": self.contamination,
        }
        joblib.dump(data, self.model_path)

    def load(self):
        """Loads trained scaler and model from disk."""
        try:
            data = joblib.load(self.model_path)
            self.scaler = data["scaler"]
            self.model = data["model"]
            self.algorithm = data.get("algorithm", "isolation_forest")
            self.contamination = data.get("contamination", 0.08)
            self.is_fitted = True
        except Exception:
            self.train_baseline()

    def score_single(self, event_data: Dict[str, Any]) -> float:
        """
        Computes a normalized anomaly score between 0.0 (very normal) and 1.0 (highly suspicious).
        """
        if not self.is_fitted or self.model is None:
            self.train_baseline()

        X = events_to_feature_matrix([event_data])
        X_scaled = self.scaler.transform(X)

        if self.algorithm == "one_class_svm":
            raw_score = self.model.decision_function(X_scaled)[0]
            # One-Class SVM: negative values = outlier, positive = inlier
            # Map [-1.0, 1.0] -> [1.0, 0.0]
            norm_score = 1.0 / (1.0 + np.exp(raw_score * 2.5))
        else:
            # IsolationForest score_samples: typically in range [-0.7, -0.3]
            raw_score = self.model.score_samples(X_scaled)[0]
            # Higher negative value means more anomalous
            # Normalize to 0.0 - 1.0 range
            norm_score = 1.0 / (1.0 + np.exp((raw_score + 0.48) * 12.0))

        # Add sensible baseline domain heuristic weighting for restricted areas and extreme times
        heuristic_boost = 0.0
        if event_data.get("restricted_area", 0) == 1:
            heuristic_boost += 0.25
        
        ts = event_data.get("timestamp")
        if isinstance(ts, str):
            try:
                import datetime
                ts = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                pass
        
        if hasattr(ts, "hour") and (ts.hour < 5 or ts.hour >= 22):
            heuristic_boost += 0.15
            
        if event_data.get("person_count", 1) >= 3:
            heuristic_boost += 0.10
            
        if event_data.get("event_duration", 0) > 180:
            heuristic_boost += 0.10

        final_score = float(np.clip(norm_score * 0.7 + heuristic_boost, 0.05, 0.98))
        return round(final_score, 3)
