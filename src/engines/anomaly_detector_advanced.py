#!/usr/bin/env python3
"""
Advanced Anomaly Detection Engine for LogSentinel Pro v4.0
Multiple algorithms for sophisticated log anomaly analysis
"""

import json
import math
import statistics
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib


class StatisticalAnomalyDetector:
    """Statistical methods for anomaly detection."""
    
    def __init__(self, sample_size: int = 100):
        self.sample_size = sample_size
        self.baseline_data = defaultdict(list)
        self.z_score_threshold = 3.0
        self.iqr_multiplier = 1.5
    
    def z_score_detection(self, metric_name: str, value: float, values_history: List[float]) -> Dict:
        """Z-score anomaly detection."""
        if len(values_history) < 2:
            return {"anomaly": False, "z_score": 0, "method": "z_score"}
        
        mean = statistics.mean(values_history)
        stdev = statistics.stdev(values_history)
        
        if stdev == 0:
            return {"anomaly": False, "z_score": 0, "method": "z_score"}
        
        z_score = abs((value - mean) / stdev)
        is_anomaly = z_score > self.z_score_threshold
        
        return {
            "anomaly": is_anomaly,
            "z_score": z_score,
            "threshold": self.z_score_threshold,
            "mean": mean,
            "value": value,
            "method": "z_score",
            "confidence": min(z_score / self.z_score_threshold, 1.0)
        }
    
    def iqr_detection(self, values_history: List[float]) -> Dict:
        """Interquartile Range (IQR) anomaly detection."""
        if len(values_history) < 4:
            return {"anomaly": False, "method": "iqr"}
        
        sorted_vals = sorted(values_history)
        q1 = sorted_vals[len(sorted_vals) // 4]
        q3 = sorted_vals[3 * len(sorted_vals) // 4]
        iqr = q3 - q1
        
        lower_bound = q1 - (self.iqr_multiplier * iqr)
        upper_bound = q3 + (self.iqr_multiplier * iqr)
        
        if values_history:
            latest = values_history[-1]
            is_anomaly = latest < lower_bound or latest > upper_bound
            
            return {
                "anomaly": is_anomaly,
                "q1": q1,
                "q3": q3,
                "iqr": iqr,
                "lower_bound": lower_bound,
                "upper_bound": upper_bound,
                "value": latest,
                "method": "iqr",
                "confidence": min(abs(latest - lower_bound if latest < lower_bound else latest - upper_bound) / max(iqr, 1), 1.0)
            }
        
        return {"anomaly": False, "method": "iqr"}
    
    def mad_detection(self, values_history: List[float], threshold: float = 2.5) -> Dict:
        """Median Absolute Deviation (MAD) detection."""
        if len(values_history) < 2:
            return {"anomaly": False, "method": "mad"}
        
        median = statistics.median(values_history)
        mad = statistics.median([abs(x - median) for x in values_history])
        
        if mad == 0:
            return {"anomaly": False, "method": "mad"}
        
        if values_history:
            latest = values_history[-1]
            modified_z_score = 0.6745 * (latest - median) / mad
            is_anomaly = abs(modified_z_score) > threshold
            
            return {
                "anomaly": is_anomaly,
                "median": median,
                "mad": mad,
                "modified_z_score": modified_z_score,
                "threshold": threshold,
                "value": latest,
                "method": "mad",
                "confidence": min(abs(modified_z_score) / threshold, 1.0)
            }
        
        return {"anomaly": False, "method": "mad"}
    
    def grubbs_test(self, values_history: List[float], alpha: float = 0.05) -> Dict:
        """Grubbs' test for outliers."""
        if len(values_history) < 3:
            return {"anomaly": False, "method": "grubbs"}
        
        mean = statistics.mean(values_history)
        stdev = statistics.stdev(values_history)
        
        if stdev == 0:
            return {"anomaly": False, "method": "grubbs"}
        
        # Calculate G statistic
        max_deviation = max(abs(x - mean) for x in values_history)
        g_score = max_deviation / stdev
        
        # Critical threshold (simplified)
        n = len(values_history)
        t_dist_critical = 3.0  # Simplified threshold
        critical_value = ((n - 1) * t_dist_critical) / math.sqrt(n * (n - 2 + t_dist_critical ** 2))
        
        is_anomaly = g_score > critical_value
        
        return {
            "anomaly": is_anomaly,
            "g_score": g_score,
            "critical_value": critical_value,
            "method": "grubbs",
            "confidence": min(g_score / critical_value, 1.0)
        }


class TimeSeriesAnomalyDetector:
    """Time-series based anomaly detection."""
    
    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.time_series_data = []
    
    def exponential_smoothing(self, values: List[float], alpha: float = 0.3) -> Tuple[float, float]:
        """Exponential smoothing for trend detection."""
        if not values:
            return 0.0, 0.0
        
        s = values[0]
        for val in values[1:]:
            s = alpha * val + (1 - alpha) * s
        
        trend = values[-1] - s if len(values) > 1 else 0
        return s, trend
    
    def seasonal_decomposition(self, values: List[float], period: int = 7) -> Dict:
        """Decompose time series into trend and seasonal components."""
        if len(values) < period * 2:
            return {"anomaly": False, "method": "seasonal"}
        
        # Calculate moving average (trend)
        trend = []
        for i in range(len(values)):
            if i < period // 2 or i >= len(values) - period // 2:
                trend.append(values[i])
            else:
                window = values[i - period // 2:i + period // 2 + 1]
                trend.append(statistics.mean(window))
        
        # Detrend
        detrended = [values[i] - trend[i] for i in range(len(values))]
        
        # Calculate seasonal pattern
        seasonal = [0] * len(values)
        for i in range(period):
            seasonal_values = [detrended[j] for j in range(i, len(values), period)]
            if seasonal_values:
                seasonal_avg = statistics.mean(seasonal_values)
                for j in range(i, len(values), period):
                    seasonal[j] = seasonal_avg
        
        # Residuals
        residuals = [values[i] - trend[i] - seasonal[i] for i in range(len(values))]
        residual_std = statistics.stdev(residuals) if len(set(residuals)) > 1 else 0
        
        # Detect anomaly in latest residual
        if residuals:
            latest_residual = residuals[-1]
            is_anomaly = abs(latest_residual) > 3 * residual_std if residual_std > 0 else False
            
            return {
                "anomaly": is_anomaly,
                "residual": latest_residual,
                "residual_std": residual_std,
                "method": "seasonal",
                "confidence": min(abs(latest_residual) / max(3 * residual_std, 1), 1.0)
            }
        
        return {"anomaly": False, "method": "seasonal"}
    
    def autoregressive_detection(self, values: List[float], lag: int = 2) -> Dict:
        """AR model for anomaly detection."""
        if len(values) < lag + 1:
            return {"anomaly": False, "method": "autoregressive"}
        
        # Fit AR model
        recent_values = values[-lag-1:]
        predicted = statistics.mean(recent_values[:-1])
        actual = recent_values[-1]
        
        error = abs(actual - predicted)
        errors = []
        
        for i in range(lag, len(values)):
            predicted_val = statistics.mean(values[i-lag:i])
            errors.append(abs(values[i] - predicted_val))
        
        error_std = statistics.stdev(errors) if len(set(errors)) > 1 else 0
        
        is_anomaly = error > 3 * error_std if error_std > 0 else False
        
        return {
            "anomaly": is_anomaly,
            "prediction_error": error,
            "error_std": error_std,
            "predicted": predicted,
            "actual": actual,
            "method": "autoregressive",
            "confidence": min(error / max(3 * error_std, 1), 1.0)
        }


class BehavioralAnomalyDetector:
    """Behavioral pattern-based anomaly detection."""
    
    def __init__(self):
        self.user_baselines = defaultdict(dict)
        self.host_baselines = defaultdict(dict)
        self.known_patterns = []
    
    def entropy_analysis(self, log_entries: List[str]) -> Dict:
        """Calculate entropy to detect unusual patterns."""
        if not log_entries:
            return {"anomaly": False, "entropy": 0, "method": "entropy"}
        
        # Count character frequencies
        char_freq = defaultdict(int)
        total_chars = 0
        
        for entry in log_entries:
            for char in entry:
                char_freq[char] += 1
                total_chars += 1
        
        # Calculate entropy
        entropy = 0.0
        for count in char_freq.values():
            if count > 0:
                probability = count / total_chars
                entropy -= probability * math.log2(probability)
        
        # High entropy might indicate injected/obfuscated code
        max_entropy = math.log2(len(set(''.join(log_entries)))) if log_entries else 0
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0
        
        is_anomaly = normalized_entropy > 0.8  # High entropy threshold
        
        return {
            "anomaly": is_anomaly,
            "entropy": entropy,
            "normalized_entropy": normalized_entropy,
            "method": "entropy",
            "confidence": normalized_entropy
        }
    
    def pattern_frequency_deviation(self, current_pattern: str, pattern_history: List[Tuple[str, int]]) -> Dict:
        """Detect deviations from typical pattern frequencies."""
        if not pattern_history:
            return {"anomaly": False, "method": "pattern_frequency"}
        
        total_occurrences = sum(count for _, count in pattern_history)
        
        # Get expected frequency
        expected_freq = defaultdict(int)
        for pattern, count in pattern_history:
            expected_freq[pattern] += count
        
        current_freq = expected_freq.get(current_pattern, 0)
        expected_probability = current_freq / total_occurrences if total_occurrences > 0 else 0
        
        # Chi-square like calculation
        chi_square = 0
        for pattern, freq in expected_freq.items():
            expected = (freq / total_occurrences) * total_occurrences
            if expected > 0:
                chi_square += ((freq - expected) ** 2) / expected
        
        # Normalize
        normalized_chi = chi_square / len(expected_freq) if expected_freq else 0
        is_anomaly = normalized_chi > 5.0
        
        return {
            "anomaly": is_anomaly,
            "pattern": current_pattern,
            "expected_probability": expected_probability,
            "chi_square": normalized_chi,
            "method": "pattern_frequency",
            "confidence": min(normalized_chi / 5.0, 1.0)
        }
    
    def user_behavior_deviation(self, user_id: str, current_activity: Dict, baseline: Dict) -> Dict:
        """Detect deviations from typical user behavior."""
        deviations = []
        confidence_scores = []
        
        for key, baseline_value in baseline.items():
            if key in current_activity:
                current_value = current_activity[key]
                
                if isinstance(baseline_value, (int, float)) and isinstance(current_value, (int, float)):
                    if baseline_value > 0:
                        deviation_ratio = current_value / baseline_value
                        
                        # Significant if > 150% or < 50% of baseline
                        if deviation_ratio > 1.5 or deviation_ratio < 0.5:
                            deviations.append({
                                "metric": key,
                                "baseline": baseline_value,
                                "current": current_value,
                                "ratio": deviation_ratio
                            })
                            confidence_scores.append(min(abs(deviation_ratio - 1.0), 1.0))
        
        is_anomaly = len(deviations) > len(baseline) * 0.3
        avg_confidence = statistics.mean(confidence_scores) if confidence_scores else 0
        
        return {
            "anomaly": is_anomaly,
            "user": user_id,
            "deviations": deviations,
            "method": "user_behavior",
            "confidence": avg_confidence
        }


class DensityBasedAnomalyDetector:
    """Density-based anomaly detection."""
    
    def __init__(self, min_samples: int = 5, eps: float = 0.5):
        self.min_samples = min_samples
        self.eps = eps
    
    def local_outlier_factor(self, point: List[float], data_points: List[List[float]]) -> Dict:
        """Local Outlier Factor (LOF) for multivariate anomaly detection."""
        if len(data_points) < self.min_samples:
            return {"anomaly": False, "lof": 1.0, "method": "lof"}
        
        # Calculate k-distance neighbors
        distances = []
        for data_point in data_points:
            dist = math.sqrt(sum((point[i] - data_point[i]) ** 2 for i in range(len(point))))
            distances.append(dist)
        
        distances.sort()
        k_distance = distances[min(self.min_samples, len(distances) - 1)]
        
        # Find points within eps distance
        neighbors = []
        neighbor_distances = []
        
        for i, dist in enumerate(distances):
            if dist <= k_distance and dist > 0:
                neighbors.append(data_points[i])
                neighbor_distances.append(dist)
        
        if len(neighbors) < 2:
            return {"anomaly": False, "lof": 1.0, "method": "lof"}
        
        # Calculate reachability distance
        reachability_distances = []
        for i, neighbor_dist in enumerate(neighbor_distances):
            reachability = max(neighbor_dist, k_distance)
            reachability_distances.append(reachability)
        
        lrd = self.min_samples / sum(reachability_distances) if sum(reachability_distances) > 0 else 0
        
        # Calculate LOF
        neighbor_lrds = []
        for i, neighbor in enumerate(neighbors):
            neighbor_dists = []
            for other_point in data_points:
                dist = math.sqrt(sum((neighbor[j] - other_point[j]) ** 2 for j in range(len(neighbor))))
                neighbor_dists.append(dist)
            
            neighbor_dists.sort()
            neighbor_k_dist = neighbor_dists[min(self.min_samples, len(neighbor_dists) - 1)]
            neighbor_reach_dists = [max(d, neighbor_k_dist) for d in neighbor_dists[:self.min_samples]]
            neighbor_lrd = self.min_samples / sum(neighbor_reach_dists) if sum(neighbor_reach_dists) > 0 else 0
            neighbor_lrds.append(neighbor_lrd)
        
        avg_neighbor_lrd = statistics.mean(neighbor_lrds) if neighbor_lrds else 0
        lof = avg_neighbor_lrd / lrd if lrd > 0 else 1.0
        
        is_anomaly = lof > 1.5
        
        return {
            "anomaly": is_anomaly,
            "lof": lof,
            "threshold": 1.5,
            "method": "lof",
            "confidence": min((lof - 1.0) / 0.5, 1.0) if lof > 1.0 else 0.0
        }


class IsolationForestAnomalyDetector:
    """Isolation Forest implementation for anomaly detection."""
    
    def __init__(self, n_trees: int = 100, sample_size: int = 256):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.trees = []
    
    def build_tree(self, data: List[List[float]], depth: int = 0, max_depth: int = None) -> Dict:
        """Build isolation tree recursively."""
        if max_depth is None:
            max_depth = math.ceil(math.log2(len(data)))
        
        if len(data) < 2 or depth >= max_depth:
            return {"leaf": True, "size": len(data)}
        
        # Select random feature and split value
        n_features = len(data[0]) if data else 0
        if n_features == 0:
            return {"leaf": True, "size": len(data)}
        
        feature_idx = hash(str(depth)) % n_features
        min_val = min(d[feature_idx] for d in data)
        max_val = max(d[feature_idx] for d in data)
        
        if min_val == max_val:
            return {"leaf": True, "size": len(data)}
        
        split_value = min_val + (max_val - min_val) * 0.5
        
        # Partition data
        left = [d for d in data if d[feature_idx] < split_value]
        right = [d for d in data if d[feature_idx] >= split_value]
        
        if not left or not right:
            return {"leaf": True, "size": len(data)}
        
        return {
            "leaf": False,
            "feature": feature_idx,
            "split_value": split_value,
            "left": self.build_tree(left, depth + 1, max_depth),
            "right": self.build_tree(right, depth + 1, max_depth)
        }
    
    def anomaly_score(self, point: List[float], num_features: int) -> float:
        """Calculate anomaly score using path length."""
        if not self.trees:
            return 0.0
        
        path_lengths = []
        for tree in self.trees:
            path_lengths.append(self._traverse_tree(point, tree, 0))
        
        avg_path_length = statistics.mean(path_lengths) if path_lengths else 0
        c = 2 * (math.log(self.sample_size - 1) + 0.5772156649) - 2 * (self.sample_size - 1) / self.sample_size
        
        anomaly_score = 2 ** (-avg_path_length / c)
        return anomaly_score
    
    def _traverse_tree(self, point: List[float], node: Dict, depth: int) -> float:
        """Traverse tree and return path length."""
        if node.get("leaf"):
            return depth + math.log(node.get("size", 1))
        
        feature_idx = node.get("feature")
        split_value = node.get("split_value")
        
        if feature_idx is None or split_value is None:
            return depth
        
        if point[feature_idx] < split_value:
            return self._traverse_tree(point, node.get("left", {}), depth + 1)
        else:
            return self._traverse_tree(point, node.get("right", {}), depth + 1)


class AnomalyDetectionOrchestrator:
    """Combine multiple anomaly detection algorithms for consensus."""
    
    def __init__(self):
        self.statistical_detector = StatisticalAnomalyDetector()
        self.timeseries_detector = TimeSeriesAnomalyDetector()
        self.behavioral_detector = BehavioralAnomalyDetector()
        self.density_detector = DensityBasedAnomalyDetector()
        self.isolation_detector = IsolationForestAnomalyDetector()
        self.ensemble_threshold = 0.5  # Majority voting threshold
    
    def analyze_metric(self, metric_name: str, value: float, values_history: List[float]) -> Dict:
        """Run all algorithms and aggregate results."""
        results = {
            "metric": metric_name,
            "value": value,
            "timestamp": datetime.now().isoformat(),
            "algorithms": {},
            "ensemble_anomaly": False,
            "ensemble_confidence": 0.0,
            "consensus": {}
        }
        
        # Z-Score
        results["algorithms"]["z_score"] = self.statistical_detector.z_score_detection(metric_name, value, values_history)
        
        # IQR
        results["algorithms"]["iqr"] = self.statistical_detector.iqr_detection(values_history)
        
        # MAD
        results["algorithms"]["mad"] = self.statistical_detector.mad_detection(values_history)
        
        # Grubbs
        results["algorithms"]["grubbs"] = self.statistical_detector.grubbs_test(values_history)
        
        # Time Series
        if len(values_history) >= 5:
            results["algorithms"]["seasonal"] = self.timeseries_detector.seasonal_decomposition(values_history)
            results["algorithms"]["autoregressive"] = self.timeseries_detector.autoregressive_detection(values_history)
        
        # Calculate consensus
        anomaly_votes = sum(1 for algo_result in results["algorithms"].values() if algo_result.get("anomaly", False))
        total_algorithms = len(results["algorithms"])
        
        confidence_scores = [algo_result.get("confidence", 0) for algo_result in results["algorithms"].values() if algo_result.get("anomaly", False)]
        
        results["ensemble_anomaly"] = anomaly_votes / total_algorithms > self.ensemble_threshold
        results["ensemble_confidence"] = statistics.mean(confidence_scores) if confidence_scores else 0.0
        
        results["consensus"] = {
            "anomaly_votes": anomaly_votes,
            "total_algorithms": total_algorithms,
            "consensus_percentage": (anomaly_votes / total_algorithms) * 100,
            "algorithms_flagged": [name for name, result in results["algorithms"].items() if result.get("anomaly", False)]
        }
        
        return results
    
    def analyze_behavioral(self, log_entries: List[str], pattern_history: List[Tuple[str, int]]) -> Dict:
        """Run behavioral analysis."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "behavioral_analysis": {}
        }
        
        # Entropy
        results["behavioral_analysis"]["entropy"] = self.behavioral_detector.entropy_analysis(log_entries)
        
        # Pattern frequency
        if log_entries and pattern_history:
            current_pattern = log_entries[-1][:50] if log_entries else ""
            results["behavioral_analysis"]["pattern_frequency"] = self.behavioral_detector.pattern_frequency_deviation(current_pattern, pattern_history)
        
        return results
    
    def analyze_multivariate(self, point: List[float], data_points: List[List[float]]) -> Dict:
        """Run multivariate anomaly detection."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "multivariate_analysis": {}
        }
        
        # LOF
        results["multivariate_analysis"]["lof"] = self.density_detector.local_outlier_factor(point, data_points)
        
        # Isolation Forest
        isolation_score = self.isolation_detector.anomaly_score(point, len(point))
        results["multivariate_analysis"]["isolation_forest"] = {
            "anomaly": isolation_score > 0.6,
            "score": isolation_score,
            "method": "isolation_forest",
            "confidence": isolation_score
        }
        
        return results
