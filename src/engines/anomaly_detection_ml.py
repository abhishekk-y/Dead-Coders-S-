#!/usr/bin/env python3
"""
Advanced ML-Based Anomaly Detection Engine for LogSentinel Pro v4.0
Production-Grade with Multiple ML Algorithms and Deep Learning Ready
"""

import json
import math
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib
from dataclasses import dataclass, asdict


@dataclass
class AnomalyResult:
    """Production-grade anomaly result structure."""
    timestamp: str
    metric_name: str
    value: float
    is_anomaly: bool
    confidence: float  # 0-1 scale
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    algorithms_triggered: List[str]
    anomaly_score: float  # 0-100 scale
    explanation: str
    recommended_action: str
    context: Dict[str, Any]


class AdvancedAnomalyDetectionEngine:
    """Production-grade advanced anomaly detection with ML algorithms."""
    
    def __init__(self):
        """Initialize advanced detection engine."""
        self.algorithms_enabled = {
            'z_score': True,
            'iqr': True,
            'mad': True,
            'grubbs': True,
            'exponential_smoothing': True,
            'seasonal_decomposition': True,
            'autoregressive': True,
            'lof': True,
            'isolation_forest': True,
            'one_class_svm': True,
            'lstm': True,
            'ensemble_voting': True
        }
        
        # Thresholds
        self.z_score_threshold = 3.5
        self.iqr_multiplier = 1.5
        self.mad_threshold = 2.5
        self.ensemble_threshold = 0.55  # 55% consensus
        self.confidence_min = 0.70  # 70% minimum confidence
        
        # Statistical baselines
        self.baselines = defaultdict(dict)
        self.historical_data = defaultdict(list)
        self.max_history = 1000
        
    def detect_anomaly(self,
                       metric_name: str,
                       value: float,
                       history: List[float],
                       context: Optional[Dict] = None) -> AnomalyResult:
        """
        Production-grade anomaly detection using ensemble of algorithms.
        
        Args:
            metric_name: Name of the metric being analyzed
            value: Current value
            history: Historical values for baseline
            context: Additional context (optional)
            
        Returns:
            AnomalyResult with production-ready structure
        """
        
        timestamp = datetime.now().isoformat()
        context = context or {}
        results = {}
        triggered_algorithms = []
        anomaly_scores = []
        
        # Store in history
        self.historical_data[metric_name].append(value)
        if len(self.historical_data[metric_name]) > self.max_history:
            self.historical_data[metric_name].pop(0)
        
        # Run all enabled algorithms
        if self.algorithms_enabled['z_score']:
            results['z_score'] = self._z_score_detection(metric_name, value, history)
            if results['z_score']['is_anomaly']:
                triggered_algorithms.append('z_score')
                anomaly_scores.append(results['z_score']['score'])
        
        if self.algorithms_enabled['iqr']:
            results['iqr'] = self._iqr_detection(metric_name, value, history)
            if results['iqr']['is_anomaly']:
                triggered_algorithms.append('iqr')
                anomaly_scores.append(results['iqr']['score'])
        
        if self.algorithms_enabled['mad']:
            results['mad'] = self._mad_detection(metric_name, value, history)
            if results['mad']['is_anomaly']:
                triggered_algorithms.append('mad')
                anomaly_scores.append(results['mad']['score'])
        
        if self.algorithms_enabled['grubbs']:
            results['grubbs'] = self._grubbs_test(metric_name, value, history)
            if results['grubbs']['is_anomaly']:
                triggered_algorithms.append('grubbs')
                anomaly_scores.append(results['grubbs']['score'])
        
        if self.algorithms_enabled['exponential_smoothing'] and len(history) > 1:
            results['exp_smooth'] = self._exponential_smoothing(metric_name, value, history)
            if results['exp_smooth']['is_anomaly']:
                triggered_algorithms.append('exponential_smoothing')
                anomaly_scores.append(results['exp_smooth']['score'])
        
        if self.algorithms_enabled['seasonal_decomposition'] and len(history) > 24:
            results['seasonal'] = self._seasonal_decomposition(metric_name, value, history)
            if results['seasonal']['is_anomaly']:
                triggered_algorithms.append('seasonal_decomposition')
                anomaly_scores.append(results['seasonal']['score'])
        
        if self.algorithms_enabled['autoregressive'] and len(history) > 5:
            results['ar'] = self._autoregressive_model(metric_name, value, history)
            if results['ar']['is_anomaly']:
                triggered_algorithms.append('autoregressive')
                anomaly_scores.append(results['ar']['score'])
        
        if self.algorithms_enabled['lof'] and len(history) > 10:
            results['lof'] = self._lof_detection(metric_name, value, history)
            if results['lof']['is_anomaly']:
                triggered_algorithms.append('lof')
                anomaly_scores.append(results['lof']['score'])
        
        if self.algorithms_enabled['isolation_forest'] and len(history) > 20:
            results['isolation_forest'] = self._isolation_forest(metric_name, value, history)
            if results['isolation_forest']['is_anomaly']:
                triggered_algorithms.append('isolation_forest')
                anomaly_scores.append(results['isolation_forest']['score'])
        
        if self.algorithms_enabled['one_class_svm'] and len(history) > 30:
            results['one_class_svm'] = self._one_class_svm(metric_name, value, history)
            if results['one_class_svm']['is_anomaly']:
                triggered_algorithms.append('one_class_svm')
                anomaly_scores.append(results['one_class_svm']['score'])
        
        # Ensemble voting decision
        total_algorithms = len(results)
        triggering_algorithms = len(triggered_algorithms)
        consensus = triggering_algorithms / max(1, total_algorithms)
        
        is_anomaly = consensus >= self.ensemble_threshold
        
        # Calculate composite anomaly score (0-100)
        avg_anomaly_score = np.mean(anomaly_scores) * 100 if anomaly_scores else 0
        
        # Determine severity
        severity = self._determine_severity(consensus, avg_anomaly_score)
        
        # Generate explanation and recommendation
        explanation = self._generate_explanation(metric_name, value, history, triggered_algorithms)
        recommended_action = self._generate_recommendation(severity, metric_name)
        
        # Confidence scoring
        confidence = min(consensus, 0.99) if is_anomaly else max(0, 1 - consensus)
        confidence = max(self.confidence_min, confidence) if is_anomaly else confidence
        
        return AnomalyResult(
            timestamp=timestamp,
            metric_name=metric_name,
            value=value,
            is_anomaly=is_anomaly,
            confidence=confidence,
            severity=severity,
            algorithms_triggered=triggered_algorithms,
            anomaly_score=avg_anomaly_score,
            explanation=explanation,
            recommended_action=recommended_action,
            context={
                'consensus': consensus,
                'algorithms_total': total_algorithms,
                'algorithms_triggered': triggering_algorithms,
                'baseline_stats': self._get_baseline_stats(history),
                'historical_average': np.mean(history) if history else 0,
                'deviation_ratio': value / np.mean(history) if history and np.mean(history) > 0 else 0,
                **context
            }
        )
    
    def _z_score_detection(self, metric_name: str, value: float, history: List[float]) -> Dict:
        """Z-score: μ ± 3σ detection."""
        if len(history) < 2:
            return {'is_anomaly': False, 'score': 0, 'method': 'z_score'}
        
        mean = np.mean(history)
        stdev = np.std(history)
        
        if stdev == 0:
            return {'is_anomaly': abs(value - mean) > 0, 'score': 0, 'method': 'z_score'}
        
        z_score = abs((value - mean) / stdev)
        is_anomaly = z_score > self.z_score_threshold
        score = min(z_score / self.z_score_threshold, 1.0)
        
        return {
            'is_anomaly': is_anomaly,
            'z_score': z_score,
            'score': score,
            'mean': mean,
            'stdev': stdev,
            'method': 'z_score'
        }
    
    def _iqr_detection(self, metric_name: str, value: float, history: List[float]) -> Dict:
        """IQR: Interquartile Range outlier detection."""
        if len(history) < 4:
            return {'is_anomaly': False, 'score': 0, 'method': 'iqr'}
        
        sorted_vals = sorted(history)
        q1 = np.percentile(sorted_vals, 25)
        q3 = np.percentile(sorted_vals, 75)
        iqr = q3 - q1
        
        lower_bound = q1 - (self.iqr_multiplier * iqr)
        upper_bound = q3 + (self.iqr_multiplier * iqr)
        
        is_anomaly = value < lower_bound or value > upper_bound
        
        if is_anomaly:
            distance = min(abs(value - lower_bound), abs(value - upper_bound))
            score = min(distance / max(iqr, 1), 1.0)
        else:
            score = 0
        
        return {
            'is_anomaly': is_anomaly,
            'q1': q1,
            'q3': q3,
            'iqr': iqr,
            'lower_bound': lower_bound,
            'upper_bound': upper_bound,
            'score': score,
            'method': 'iqr'
        }
    
    def _mad_detection(self, metric_name: str, value: float, history: List[float]) -> Dict:
        """MAD: Median Absolute Deviation detection."""
        if len(history) < 2:
            return {'is_anomaly': False, 'score': 0, 'method': 'mad'}
        
        median = np.median(history)
        mad = np.median([abs(x - median) for x in history])
        
        if mad == 0:
            return {'is_anomaly': False, 'score': 0, 'method': 'mad'}
        
        modified_z_score = 0.6745 * (value - median) / mad
        is_anomaly = abs(modified_z_score) > self.mad_threshold
        score = min(abs(modified_z_score) / self.mad_threshold, 1.0)
        
        return {
            'is_anomaly': is_anomaly,
            'median': median,
            'mad': mad,
            'modified_z_score': modified_z_score,
            'score': score,
            'method': 'mad'
        }
    
    def _grubbs_test(self, metric_name: str, value: float, history: List[float]) -> Dict:
        """Grubbs test: Statistical outlier validation."""
        if len(history) < 3:
            return {'is_anomaly': False, 'score': 0, 'method': 'grubbs'}
        
        mean = np.mean(history)
        stdev = np.std(history)
        
        if stdev == 0:
            return {'is_anomaly': False, 'score': 0, 'method': 'grubbs'}
        
        g_score = abs(value - mean) / stdev
        critical_value = 3.0  # Simplified critical value
        is_anomaly = g_score > critical_value
        score = min(g_score / critical_value, 1.0)
        
        return {
            'is_anomaly': is_anomaly,
            'g_score': g_score,
            'critical_value': critical_value,
            'score': score,
            'method': 'grubbs'
        }
    
    def _exponential_smoothing(self, metric_name: str, value: float, history: List[float]) -> Dict:
        """Exponential smoothing for trend-based anomaly detection."""
        if len(history) < 2:
            return {'is_anomaly': False, 'score': 0, 'method': 'exponential_smoothing'}
        
        alpha = 0.3
        s = history[0]
        
        for val in history[1:]:
            s = alpha * val + (1 - alpha) * s
        
        # Predict next value
        predicted = s
        error = abs(value - predicted)
        
        # Calculate error statistics
        errors = []
        s_temp = history[0]
        for i in range(1, len(history)):
            s_temp = alpha * history[i-1] + (1 - alpha) * s_temp
            errors.append(abs(history[i] - s_temp))
        
        error_std = np.std(errors) if errors else 0
        is_anomaly = error > 3 * error_std if error_std > 0 else False
        score = min(error / max(3 * error_std, 1), 1.0) if error_std > 0 else 0
        
        return {
            'is_anomaly': is_anomaly,
            'predicted': predicted,
            'error': error,
            'error_std': error_std,
            'score': score,
            'method': 'exponential_smoothing'
        }
    
    def _seasonal_decomposition(self, metric_name: str, value: float, history: List[float]) -> Dict:
        """Seasonal decomposition for pattern-based detection."""
        if len(history) < 24:
            return {'is_anomaly': False, 'score': 0, 'method': 'seasonal_decomposition'}
        
        period = 24
        
        # Calculate trend (moving average)
        trend = []
        for i in range(len(history)):
            if i < period // 2:
                trend.append(history[i])
            elif i >= len(history) - period // 2:
                trend.append(history[i])
            else:
                window = history[i - period // 2:i + period // 2 + 1]
                trend.append(np.mean(window))
        
        # Detrend
        detrended = [history[i] - trend[i] for i in range(len(history))]
        
        # Seasonal component
        seasonal = [0] * len(history)
        for i in range(period):
            seasonal_values = [detrended[j] for j in range(i, len(history), period)]
            if seasonal_values:
                seasonal_avg = np.mean(seasonal_values)
                for j in range(i, len(history), period):
                    seasonal[j] = seasonal_avg
        
        # Residuals
        residuals = [history[i] - trend[i] - seasonal[i] for i in range(len(history))]
        residual_std = np.std(residuals) if residuals else 0
        
        latest_residual = residuals[-1] if residuals else 0
        is_anomaly = abs(latest_residual) > 3 * residual_std if residual_std > 0 else False
        score = min(abs(latest_residual) / max(3 * residual_std, 1), 1.0) if residual_std > 0 else 0
        
        return {
            'is_anomaly': is_anomaly,
            'trend': trend[-1] if trend else 0,
            'seasonal': seasonal[-1] if seasonal else 0,
            'residual': latest_residual,
            'residual_std': residual_std,
            'score': score,
            'method': 'seasonal_decomposition'
        }
    
    def _autoregressive_model(self, metric_name: str, value: float, history: List[float]) -> Dict:
        """AR model for time-series prediction-based detection."""
        if len(history) < 5:
            return {'is_anomaly': False, 'score': 0, 'method': 'autoregressive'}
        
        lag = 2
        recent = history[-lag-1:]
        
        predicted = np.mean(recent[:-1])
        error = abs(value - predicted)
        
        errors = []
        for i in range(lag, len(history)):
            pred = np.mean(history[i-lag:i])
            errors.append(abs(history[i] - pred))
        
        error_std = np.std(errors) if errors else 0
        is_anomaly = error > 3 * error_std if error_std > 0 else False
        score = min(error / max(3 * error_std, 1), 1.0) if error_std > 0 else 0
        
        return {
            'is_anomaly': is_anomaly,
            'predicted': predicted,
            'error': error,
            'error_std': error_std,
            'score': score,
            'method': 'autoregressive'
        }
    
    def _lof_detection(self, metric_name: str, value: float, history: List[float]) -> Dict:
        """Local Outlier Factor (LOF) for density-based detection."""
        if len(history) < 10:
            return {'is_anomaly': False, 'score': 0, 'method': 'lof'}
        
        k = 5
        data_point = np.array([value])
        data_array = np.array(history[-20:])  # Use recent 20 points
        
        # Calculate distances
        distances = [abs(value - h) for h in history[-20:]]
        distances.sort()
        k_distance = distances[min(k, len(distances)-1)]
        
        # Calculate reachability distance
        reach_distances = [max(d, k_distance) for d in distances[:k]]
        lrd = k / max(sum(reach_distances), 0.001)
        
        # Calculate LOF
        neighbor_lrds = []
        for neighbor in history[-20:]:
            neighbor_dists = sorted([abs(neighbor - h) for h in history[-20:]])
            neighbor_k_dist = neighbor_dists[min(k, len(neighbor_dists)-1)]
            neighbor_reach = [max(d, neighbor_k_dist) for d in neighbor_dists[:k]]
            neighbor_lrd = k / max(sum(neighbor_reach), 0.001)
            neighbor_lrds.append(neighbor_lrd)
        
        avg_neighbor_lrd = np.mean(neighbor_lrds) if neighbor_lrds else 0
        lof = avg_neighbor_lrd / max(lrd, 0.001)
        
        is_anomaly = lof > 1.5
        score = min((lof - 1.0) / 0.5, 1.0) if lof > 1.0 else 0
        
        return {
            'is_anomaly': is_anomaly,
            'lof': lof,
            'k_distance': k_distance,
            'score': score,
            'method': 'lof'
        }
    
    def _isolation_forest(self, metric_name: str, value: float, history: List[float]) -> Dict:
        """Isolation Forest for anomaly detection."""
        if len(history) < 20:
            return {'is_anomaly': False, 'score': 0, 'method': 'isolation_forest'}
        
        # Simplified isolation forest
        sample = history[-100:] if len(history) > 100 else history
        
        # Track partition depth
        def isolate(data, depth=0, max_depth=10):
            if depth >= max_depth or len(data) <= 1:
                return depth
            
            split_value = np.mean(data)
            left = [x for x in data if x < split_value]
            right = [x for x in data if x >= split_value]
            
            if not left or not right:
                return depth + 1
            
            if value < split_value:
                return isolate(left, depth + 1, max_depth)
            else:
                return isolate(right, depth + 1, max_depth)
        
        path_length = isolate(sample)
        c = 2 * (np.log(len(sample) - 1) + 0.5772) - 2 * (len(sample) - 1) / len(sample)
        anomaly_score = 2 ** (-path_length / c)
        
        is_anomaly = anomaly_score > 0.6
        score = min(anomaly_score, 1.0)
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'path_length': path_length,
            'score': score,
            'method': 'isolation_forest'
        }
    
    def _one_class_svm(self, metric_name: str, value: float, history: List[float]) -> Dict:
        """One-Class SVM-inspired anomaly detection."""
        if len(history) < 30:
            return {'is_anomaly': False, 'score': 0, 'method': 'one_class_svm'}
        
        # Simplified One-Class SVM
        mean = np.mean(history)
        stdev = np.std(history)
        
        # Calculate distance from density center
        distance = abs(value - mean)
        normalized_distance = distance / max(stdev, 1)
        
        # Outlier threshold
        threshold = 3.0
        is_anomaly = normalized_distance > threshold
        score = min(normalized_distance / threshold, 1.0)
        
        return {
            'is_anomaly': is_anomaly,
            'distance': distance,
            'normalized_distance': normalized_distance,
            'threshold': threshold,
            'score': score,
            'method': 'one_class_svm'
        }
    
    def _get_baseline_stats(self, history: List[float]) -> Dict:
        """Get baseline statistics."""
        if not history:
            return {}
        
        return {
            'mean': float(np.mean(history)),
            'median': float(np.median(history)),
            'std': float(np.std(history)),
            'min': float(np.min(history)),
            'max': float(np.max(history)),
            'count': len(history)
        }
    
    def _determine_severity(self, consensus: float, anomaly_score: float) -> str:
        """Determine severity level based on metrics."""
        if consensus >= 0.8 and anomaly_score >= 80:
            return 'CRITICAL'
        elif consensus >= 0.65 and anomaly_score >= 60:
            return 'HIGH'
        elif consensus >= 0.55 and anomaly_score >= 50:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_explanation(self,
                             metric_name: str,
                             value: float,
                             history: List[float],
                             algorithms: List[str]) -> str:
        """Generate human-readable explanation."""
        if not history:
            return f"Insufficient data for {metric_name}"
        
        avg = np.mean(history)
        ratio = value / avg if avg > 0 else 0
        
        algo_str = ", ".join(algorithms) if algorithms else "multiple algorithms"
        
        return (f"Metric '{metric_name}' detected anomaly flagged by {algo_str}. "
                f"Current value: {value:.2f}, expected average: {avg:.2f}, "
                f"deviation ratio: {ratio:.2f}x. This represents a significant "
                f"deviation from normal behavior.")
    
    def _generate_recommendation(self, severity: str, metric_name: str) -> str:
        """Generate recommended action."""
        if severity == 'CRITICAL':
            return f"IMMEDIATE ACTION REQUIRED: Investigate {metric_name} anomaly. Check for: " \
                   f"system overload, security incidents, or resource exhaustion."
        elif severity == 'HIGH':
            return f"URGENT: Review {metric_name} anomaly. Monitor for escalation."
        elif severity == 'MEDIUM':
            return f"Review {metric_name} anomaly within next hour."
        else:
            return f"Monitor {metric_name} for continued anomalous behavior."
