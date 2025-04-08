# utils/anomaly_detector.py
import numpy as np
from sklearn.ensemble import IsolationForest
import logging
from datetime import datetime

class AnomalyDetector:
    """
    Uses Isolation Forest for unsupervised anomaly detection on BGP updates.
    """
    def __init__(self, contamination='auto', random_state=42):
        """
        Initializes the Isolation Forest model.

        Args:
            contamination (float or 'auto'): The expected proportion of outliers
                                             in the data set.
            random_state (int): Controls the randomness of the estimator.
        """
        self.model = IsolationForest(contamination=contamination,
                                     random_state=random_state,
                                     n_estimators=100) # Default n_estimators
        self.is_fitted = False
        # Simple state for features requiring history (can be expanded)
        self.prefix_last_seen = {}
        self.prefix_origin_history = {}
        logging.info("AnomalyDetector initialized.")

    def extract_features(self, update_data: dict) -> np.ndarray | None:
        """
        Extracts numerical features from a BGP update dictionary.

        Args:
            update_data (dict): Dictionary containing BGP update details like
                                'timestamp', 'prefix', 'as_path', 'update_type'.

        Returns:
            np.ndarray: A numpy array of numerical features, or None if
                        essential data is missing.
        """
        try:
            as_path_str = update_data.get('as_path', '')
            path_ases = [int(asn) for asn in as_path_str.split(',') if asn.isdigit()]
            path_length = len(path_ases)
            unique_asns = len(set(path_ases))
            prefix = update_data.get('prefix', '')
            timestamp = update_data.get('timestamp') # Expecting datetime object

            if not prefix or not timestamp or path_length == 0:
                 logging.debug("Missing essential data for feature extraction.")
                 return None

            # Feature: Prefix length (numeric part after '/')
            prefix_len = int(prefix.split('/')[-1]) if '/' in prefix else 32 # Default for host routes?

            # Feature: Time since last update for this prefix (requires state)
            time_since_last = 0
            if prefix in self.prefix_last_seen:
                time_since_last = (timestamp - self.prefix_last_seen[prefix]).total_seconds()
            self.prefix_last_seen[prefix] = timestamp # Update last seen time

            # Feature: Origin AS change (requires state)
            origin_asn = path_ases[-1] if path_ases else 0
            origin_changed = 0
            if prefix in self.prefix_origin_history:
                last_origin = self.prefix_origin_history[prefix]
                if last_origin != origin_asn:
                    origin_changed = 1
            self.prefix_origin_history[prefix] = origin_asn # Update origin history

            # Basic features: path length, unique ASNs, prefix length, time diff, origin change
            # More features can be added (e.g., specific ASN presence, community analysis)
            features = np.array([
                path_length,
                unique_asns,
                prefix_len,
                time_since_last,
                origin_changed
            ])
            # Ensure features are finite (handle potential NaNs or Infs if calculations change)
            if not np.all(np.isfinite(features)):
                 logging.warning(f"Non-finite features generated for prefix {prefix}: {features}")
                 return None

            return features.reshape(1, -1) # Reshape for single sample prediction

        except Exception as e:
            logging.error(f"Error extracting features for update {update_data}: {e}")
            return None

    def fit(self, features_list: list[np.ndarray]):
        """
        Fits the Isolation Forest model to the provided features.
        This is typically done offline with a representative dataset.

        Args:
            features_list (list[np.ndarray]): A list of feature arrays.
        """
        if not features_list:
            logging.warning("No features provided for fitting the model.")
            return

        X = np.vstack(features_list) # Combine list of (1, n_features) arrays into (n_samples, n_features)
        if X.shape[0] > 0:
            logging.info(f"Fitting IsolationForest model with {X.shape[0]} samples.")
            self.model.fit(X)
            self.is_fitted = True
            logging.info("IsolationForest model fitted.")
        else:
             logging.warning("Feature extraction resulted in zero samples for fitting.")


    def predict(self, features: np.ndarray) -> int | None:
        """
        Predicts whether a sample is an anomaly using the fitted model.

        Args:
            features (np.ndarray): A numpy array of features for a single sample.

        Returns:
            int | None: Prediction result (-1 for anomaly, 1 for normal),
                        or None if the model is not fitted or prediction fails.
        """
        if not self.is_fitted:
            # In a real scenario, you might load a pre-trained model here
            # For now, we'll just warn and return normal
            logging.warning("Anomaly model not fitted. Cannot predict.")
            # Or potentially fit online if desired, though less robust
            # self.model.fit(features) # Basic online fitting (use with caution)
            # self.is_fitted = True
            return 1 # Default to normal if not fitted

        try:
            # Predict returns 1 for inliers, -1 for outliers
            prediction = self.model.predict(features)
            return int(prediction[0])
        except Exception as e:
            logging.error(f"Error during anomaly prediction: {e}")
            return None
