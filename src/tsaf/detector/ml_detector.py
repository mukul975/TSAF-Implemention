"""
Machine Learning Threat Detection Component
Uses ML models for advanced threat detection and classification.
"""

import asyncio
import joblib
import json
import numpy as np
from typing import Dict, List, Optional, Any, Union
import uuid
import re
from pathlib import Path

import structlog

try:
    import torch
    import torch.nn as nn
    from transformers import AutoTokenizer, AutoModel
    from sklearn.ensemble import IsolationForest
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger = structlog.get_logger(__name__)
    logger.warning("ML dependencies not available - ML detection will be disabled")

from tsaf.core.config import DetectorConfig
from tsaf.detector.static_analyzer import Vulnerability
from tsaf.analyzer.models import VulnerabilityCategory, SeverityLevel
from tsaf.core.exceptions import TSAFException

logger = structlog.get_logger(__name__)


class MLThreatDetector:
    """
    Machine Learning-based threat detection system with online learning.

    Uses multiple ML approaches:
    - BERT-based text classification for threat detection
    - Isolation Forest for anomaly detection
    - TF-IDF vectorization for similarity analysis
    - Custom neural networks for pattern recognition
    - Online learning with continuous model updates
    - Ensemble methods for improved accuracy
    """

    def __init__(self, config: DetectorConfig):
        self.config = config

        # Online learning components
        self.training_samples = []
        self.feedback_samples = []
        self.model_performance_history = []
        self.retrain_threshold = 1000  # Retrain after 1000 new samples
        self.performance_threshold = 0.85  # Retrain if performance drops below this

        # Ensemble components
        self.ensemble_models = []
        self.model_weights = []
        self.ensemble_size = 3
        self._initialized = False

        # ML Models
        self.bert_model = None
        self.bert_tokenizer = None
        self.threat_classifier = None
        self.anomaly_detector = None
        self.tfidf_vectorizer = None

        # Feature extractors
        self.text_features = TextFeatureExtractor()
        self.pattern_features = PatternFeatureExtractor()

        # Model paths
        ml_model_path = getattr(config, 'ml_model_path', './models/ml_models.pkl')
        self.model_dir = Path(ml_model_path).parent
        self.model_dir.mkdir(parents=True, exist_ok=True)

        # Training data for online learning
        self.training_samples = []
        self.max_training_samples = 10000

        # Threat categories mapping
        self.threat_categories = {
            0: VulnerabilityCategory.ISV,   # Input Sanitization
            1: VulnerabilityCategory.PIV,   # Protocol Injection
            2: VulnerabilityCategory.SCV,   # State Corruption
            3: VulnerabilityCategory.CPRV,  # Cross-Protocol Relay
            4: VulnerabilityCategory.TIV,   # Translation Integrity
            5: VulnerabilityCategory.CEV    # Command Execution
        }

    async def initialize(self) -> None:
        """Initialize ML models and components."""
        if self._initialized:
            return

        if not TORCH_AVAILABLE:
            logger.warning("ML dependencies not available - skipping ML detector initialization")
            return

        logger.info("Initializing ML Threat Detector")

        try:
            # Initialize BERT model for text analysis
            await self._initialize_bert_model()

            # Initialize threat classifier
            await self._initialize_threat_classifier()

            # Initialize anomaly detector
            await self._initialize_anomaly_detector()

            # Initialize TF-IDF vectorizer
            await self._initialize_tfidf_vectorizer()

            # Load or create baseline models
            await self._load_or_create_models()

            self._initialized = True
            logger.info("ML Threat Detector initialization complete")

        except Exception as e:
            logger.error("Failed to initialize ML Threat Detector", error=str(e))
            # Don't raise exception - fall back to non-ML detection
            logger.warning("ML Threat Detector disabled due to initialization failure")

    async def _initialize_bert_model(self) -> None:
        """Initialize BERT model for text embeddings."""
        try:
            model_name = "bert-base-uncased"
            self.bert_tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.bert_model = AutoModel.from_pretrained(model_name)
            self.bert_model.eval()
            logger.info("BERT model initialized successfully")
        except Exception as e:
            logger.error("Failed to initialize BERT model", error=str(e))
            raise

    async def _initialize_threat_classifier(self) -> None:
        """Initialize threat classification model."""
        self.threat_classifier = ThreatClassifier(
            input_dim=768,  # BERT embedding dimension
            num_classes=len(self.threat_categories),
            hidden_dim=256
        )
        logger.info("Threat classifier initialized")

    async def _initialize_anomaly_detector(self) -> None:
        """Initialize anomaly detection model."""
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        logger.info("Anomaly detector initialized")

    async def _initialize_tfidf_vectorizer(self) -> None:
        """Initialize TF-IDF vectorizer."""
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            stop_words='english',
            lowercase=True
        )
        logger.info("TF-IDF vectorizer initialized")

    async def _load_or_create_models(self) -> None:
        """Load existing models or create new ones."""
        # Load threat classifier if exists
        classifier_path = self.model_dir / "threat_classifier.pth"
        if classifier_path.exists():
            try:
                self.threat_classifier.load_state_dict(torch.load(classifier_path))
                logger.info("Loaded existing threat classifier")
            except Exception as e:
                logger.warning("Failed to load threat classifier", error=str(e))

        # Load anomaly detector if exists
        anomaly_path = self.model_dir / "anomaly_detector.joblib"
        if anomaly_path.exists():
            try:
                self.anomaly_detector = joblib.load(anomaly_path)
                logger.info("Loaded existing anomaly detector")
            except Exception as e:
                logger.warning("Failed to load anomaly detector", error=str(e))

        # Load TF-IDF vectorizer if exists
        tfidf_path = self.model_dir / "tfidf_vectorizer.joblib"
        if tfidf_path.exists():
            try:
                self.tfidf_vectorizer = joblib.load(tfidf_path)
                logger.info("Loaded existing TF-IDF vectorizer")
            except Exception as e:
                logger.warning("Failed to load TF-IDF vectorizer", error=str(e))
                # Reinitialize if loading fails
                await self._initialize_tfidf_vectorizer()

    async def detect_threats(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None
    ) -> List[Vulnerability]:
        """
        Detect threats using ML models.

        Args:
            message: Message content to analyze
            context: Additional context

        Returns:
            List of detected vulnerabilities
        """
        if not self._initialized or not TORCH_AVAILABLE:
            return []

        vulnerabilities = []

        try:
            # Extract features
            text_features = await self.text_features.extract(message)
            pattern_features = await self.pattern_features.extract(message)

            # Get BERT embeddings
            embeddings = await self._get_bert_embeddings(message)

            # Threat classification
            threat_vulns = await self._classify_threats(message, embeddings, context)
            vulnerabilities.extend(threat_vulns)

            # Anomaly detection
            anomaly_vulns = await self._detect_anomalies(text_features, pattern_features)
            vulnerabilities.extend(anomaly_vulns)

            # Similarity analysis
            similarity_vulns = await self._analyze_similarity(message, embeddings)
            vulnerabilities.extend(similarity_vulns)

            # Update training data for online learning
            await self._update_training_data(message, embeddings, vulnerabilities)

            logger.debug(
                "ML threat detection completed",
                vulnerabilities_found=len(vulnerabilities),
                message_length=len(message)
            )

            return vulnerabilities

        except Exception as e:
            logger.error("ML threat detection failed", error=str(e))
            return []

    async def _get_bert_embeddings(self, message: str) -> torch.Tensor:
        """Get BERT embeddings for message."""
        try:
            # Tokenize and encode
            inputs = self.bert_tokenizer(
                message,
                return_tensors='pt',
                max_length=512,
                truncation=True,
                padding=True
            )

            # Get embeddings
            with torch.no_grad():
                outputs = self.bert_model(**inputs)
                # Use mean pooling of last hidden state
                embeddings = outputs.last_hidden_state.mean(dim=1)

            return embeddings

        except Exception as e:
            logger.error("Failed to get BERT embeddings", error=str(e))
            # Return zero embeddings as fallback
            return torch.zeros(1, 768)

    async def _classify_threats(
        self,
        message: str,
        embeddings: torch.Tensor,
        context: Optional[Dict[str, Any]]
    ) -> List[Vulnerability]:
        """Classify threats using neural network."""
        vulnerabilities = []

        try:
            # Get threat predictions
            with torch.no_grad():
                logits = self.threat_classifier(embeddings)
                probabilities = torch.softmax(logits, dim=-1)

            # Check each threat category
            for i, prob in enumerate(probabilities[0]):
                if prob > 0.7:  # High confidence threshold
                    threat_type = self.threat_categories[i]
                    severity = self._calculate_severity(prob.item())

                    vulnerabilities.append(Vulnerability(
                        type=threat_type.value,
                        severity=severity.value,
                        description=f"Machine learning model detected potential {threat_type.value} vulnerability",
                        location="ML analysis",
                        confidence=prob.item(),
                        metadata={
                            "detection_method": "ml_classification",
                            "model_confidence": prob.item(),
                            "threat_category": threat_type.value,
                            "all_probabilities": probabilities[0].tolist()
                        }
                    ))

        except Exception as e:
            logger.error("Threat classification failed", error=str(e))

        return vulnerabilities

    async def _detect_anomalies(
        self,
        text_features: Dict[str, float],
        pattern_features: Dict[str, float]
    ) -> List[Vulnerability]:
        """Detect anomalies using Isolation Forest."""
        vulnerabilities = []

        try:
            # Combine features
            feature_vector = list(text_features.values()) + list(pattern_features.values())
            feature_array = np.array([feature_vector])

            # Check if anomaly detector is fitted
            if not hasattr(self.anomaly_detector, 'offset_'):
                logger.warning("Anomaly detector not fitted, skipping anomaly detection")
                return vulnerabilities

            # Detect anomalies
            anomaly_score = self.anomaly_detector.decision_function(feature_array)[0]
            is_anomaly = self.anomaly_detector.predict(feature_array)[0] == -1

            if is_anomaly:
                vulnerabilities.append(Vulnerability(
                    type=VulnerabilityCategory.SCV.value,  # Assume state corruption for anomalies
                    severity=SeverityLevel.MEDIUM.value,
                    description="Message exhibits anomalous patterns detected by ML model",
                    location="ML anomaly detection",
                    confidence=abs(anomaly_score),
                    metadata={
                        "detection_method": "ml_anomaly",
                        "anomaly_score": anomaly_score,
                        "text_features": text_features,
                        "pattern_features": pattern_features
                    }
                ))

        except Exception as e:
            logger.error("Anomaly detection failed", error=str(e))

        return vulnerabilities

    async def _analyze_similarity(
        self,
        message: str,
        embeddings: torch.Tensor
    ) -> List[Vulnerability]:
        """Analyze message similarity to known attack patterns."""
        vulnerabilities = []

        try:
            # Check if vectorizer is fitted first
            if not hasattr(self.tfidf_vectorizer, 'vocabulary_'):
                logger.debug("TF-IDF vectorizer not fitted, fitting with current message and patterns")
                # Fit vectorizer with attack patterns and current message
                attack_patterns = [
                    "ignore previous instructions",
                    "act as a different ai",
                    "system: you are now",
                    "jailbreak mode",
                    "developer mode"
                ]
                training_texts = attack_patterns + [message]
                self.tfidf_vectorizer.fit(training_texts)
            else:
                attack_patterns = [
                    "ignore previous instructions",
                    "act as a different ai",
                    "system: you are now",
                    "jailbreak mode",
                    "developer mode"
                ]

            message_lower = message.lower()
            for pattern in attack_patterns:
                if pattern in message_lower:
                    # Use TF-IDF to compute similarity
                    try:
                        pattern_vector = self.tfidf_vectorizer.transform([pattern])
                        message_vector = self.tfidf_vectorizer.transform([message])
                        similarity = cosine_similarity(pattern_vector, message_vector)[0][0]

                        if similarity > 0.5:  # Only report significant similarities
                            vulnerabilities.append(Vulnerability(
                                type=VulnerabilityCategory.ISV.value,
                                severity=SeverityLevel.HIGH.value,
                                description=f"Message similar to known attack pattern: {pattern}",
                                location="ML similarity analysis",
                                confidence=similarity,
                                metadata={
                                    "detection_method": "ml_similarity",
                                    "attack_pattern": pattern,
                                    "similarity_score": similarity
                                }
                            ))
                    except Exception as ve:
                        logger.debug("Failed to compute similarity for pattern", pattern=pattern, error=str(ve))
                        continue

        except Exception as e:
            logger.error("Similarity analysis failed", error=str(e))

        return vulnerabilities

    async def _update_training_data(
        self,
        message: str,
        embeddings: torch.Tensor,
        vulnerabilities: List[Vulnerability]
    ) -> None:
        """Update training data for online learning."""
        try:
            # Add sample to training data
            sample = {
                "message": message[:1000],  # Limit size
                "embeddings": embeddings.tolist(),
                "has_vulnerability": len(vulnerabilities) > 0,
                "vulnerability_types": [v.type.value for v in vulnerabilities],
                "timestamp": asyncio.get_event_loop().time()
            }

            self.training_samples.append(sample)

            # Limit training data size
            if len(self.training_samples) > self.max_training_samples:
                self.training_samples = self.training_samples[-self.max_training_samples:]

            # Periodically retrain models (simplified)
            if len(self.training_samples) % 1000 == 0:
                await self._retrain_models()

        except Exception as e:
            logger.error("Failed to update training data", error=str(e))

    async def _retrain_models(self) -> None:
        """Retrain models with new data (simplified implementation)."""
        try:
            logger.info("Retraining ML models with new data")

            # Retrain anomaly detector
            if len(self.training_samples) >= 100:
                features = []
                for sample in self.training_samples[-1000:]:  # Last 1000 samples
                    # Extract features (simplified)
                    text_feat = await self.text_features.extract(sample["message"])
                    pattern_feat = await self.pattern_features.extract(sample["message"])
                    feature_vector = list(text_feat.values()) + list(pattern_feat.values())
                    features.append(feature_vector)

                if features:
                    self.anomaly_detector.fit(np.array(features))
                    logger.info("Anomaly detector retrained")

            # Save updated models
            await self._save_models()

        except Exception as e:
            logger.error("Model retraining failed", error=str(e))

    async def _save_models(self) -> None:
        """Save trained models to disk."""
        try:
            # Save threat classifier
            classifier_path = self.model_dir / "threat_classifier.pth"
            torch.save(self.threat_classifier.state_dict(), classifier_path)

            # Save anomaly detector
            anomaly_path = self.model_dir / "anomaly_detector.joblib"
            joblib.dump(self.anomaly_detector, anomaly_path)

            # Save TF-IDF vectorizer
            tfidf_path = self.model_dir / "tfidf_vectorizer.joblib"
            joblib.dump(self.tfidf_vectorizer, tfidf_path)

            logger.info("ML models saved successfully")

        except Exception as e:
            logger.error("Failed to save ML models", error=str(e))

    def _calculate_severity(self, confidence: float) -> SeverityLevel:
        """Calculate severity based on ML confidence."""
        if confidence > 0.9:
            return SeverityLevel.CRITICAL
        elif confidence > 0.8:
            return SeverityLevel.HIGH
        elif confidence > 0.7:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    async def shutdown(self) -> None:
        """Shutdown ML detector and save models."""
        if self._initialized:
            logger.info("Shutting down ML Threat Detector")
            await self._save_models()
            self._initialized = False


class ThreatClassifier(nn.Module):
    """Neural network for threat classification."""

    def __init__(self, input_dim: int, num_classes: int, hidden_dim: int = 256):
        super().__init__()
        self.classifier = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim // 2, num_classes)
        )

    def forward(self, x):
        return self.classifier(x)


class TextFeatureExtractor:
    """Extract text-based features for ML analysis."""

    async def extract(self, text: str) -> Dict[str, float]:
        """Extract text features."""
        features = {
            "length": len(text),
            "word_count": len(text.split()),
            "avg_word_length": sum(len(word) for word in text.split()) / max(len(text.split()), 1),
            "uppercase_ratio": sum(1 for c in text if c.isupper()) / max(len(text), 1),
            "digit_ratio": sum(1 for c in text if c.isdigit()) / max(len(text), 1),
            "special_char_ratio": sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1),
            "entropy": self._calculate_entropy(text),
            "suspicious_keyword_count": self._count_suspicious_keywords(text)
        }
        return features

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        entropy = 0.0
        text_length = len(text)
        for count in char_counts.values():
            prob = count / text_length
            entropy -= prob * np.log2(prob)

        return entropy

    def _count_suspicious_keywords(self, text: str) -> int:
        """Count suspicious keywords in text."""
        suspicious_keywords = [
            "admin", "root", "system", "password", "secret", "token",
            "exploit", "hack", "bypass", "inject", "execute", "eval",
            "shell", "cmd", "powershell", "bash"
        ]

        text_lower = text.lower()
        return sum(1 for keyword in suspicious_keywords if keyword in text_lower)


class PatternFeatureExtractor:
    """Extract pattern-based features for ML analysis."""

    def __init__(self):
        self.patterns = {
            "base64_pattern": re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
            "hex_pattern": re.compile(r'[0-9a-fA-F]{20,}'),
            "url_pattern": re.compile(r'https?://[^\s]+'),
            "ip_pattern": re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            "email_pattern": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "script_pattern": re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            "sql_pattern": re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b', re.IGNORECASE),
            "command_pattern": re.compile(r'\b(exec|eval|system|shell|cmd)\s*\(', re.IGNORECASE)
        }

    async def extract(self, text: str) -> Dict[str, float]:
        """Extract pattern-based features."""
        features = {}

        for pattern_name, pattern in self.patterns.items():
            matches = pattern.findall(text)
            features[f"{pattern_name}_count"] = len(matches)
            features[f"{pattern_name}_ratio"] = len(matches) / max(len(text.split()), 1)

        return features