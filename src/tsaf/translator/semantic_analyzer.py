"""
Semantic Similarity Analyzer
Advanced semantic analysis using BERT embeddings and multiple similarity metrics.
"""

import asyncio
import hashlib
import time
from typing import Dict, Any, List, Tuple
import numpy as np
import structlog

from .models import SemanticSimilarity, SemanticPreservationLevel
from tsaf.core.exceptions import TSAFException

logger = structlog.get_logger(__name__)


class SemanticSimilarityAnalyzer:
    """
    Advanced semantic similarity analyzer using multiple methods.

    Combines BERT embeddings, TF-IDF, Jaccard similarity, and edit distance
    to provide comprehensive semantic analysis with confidence scoring.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.bert_model = None
        self.bert_tokenizer = None
        self.tfidf_vectorizer = None
        self._initialized = False
        self._cache = {}  # Simple in-memory cache
        self._cache_size_limit = 1000

    async def initialize(self) -> None:
        """Initialize the semantic analyzer."""
        if self._initialized:
            return

        logger.info("Initializing Semantic Similarity Analyzer")

        try:
            # Initialize BERT model for semantic embeddings
            await self._initialize_bert_model()

            # Initialize TF-IDF vectorizer
            await self._initialize_tfidf()

            self._initialized = True
            logger.info("Semantic Similarity Analyzer initialized successfully")

        except Exception as e:
            logger.error("Semantic Similarity Analyzer initialization failed", error=str(e))
            raise TSAFException(f"Semantic analyzer initialization failed: {str(e)}")

    async def analyze_similarity(self, original_text: str, translated_text: str) -> SemanticSimilarity:
        """
        Perform comprehensive semantic similarity analysis.

        Args:
            original_text: Original message text
            translated_text: Translated message text

        Returns:
            SemanticSimilarity object with detailed analysis results
        """
        if not self._initialized:
            raise TSAFException("Semantic analyzer not initialized")

        start_time = time.time()

        try:
            # Check cache first
            cache_key = self._generate_cache_key(original_text, translated_text)
            if cache_key in self._cache:
                logger.debug("Returning cached similarity result")
                return self._cache[cache_key]

            logger.info("Analyzing semantic similarity",
                       original_length=len(original_text),
                       translated_length=len(translated_text))

            # Run multiple similarity analyses in parallel
            similarity_tasks = [
                self._bert_similarity(original_text, translated_text),
                self._tfidf_similarity(original_text, translated_text),
                self._jaccard_similarity(original_text, translated_text),
                self._edit_distance_similarity(original_text, translated_text)
            ]

            results = await asyncio.gather(*similarity_tasks, return_exceptions=True)

            # Extract results and handle exceptions
            bert_sim = results[0] if not isinstance(results[0], Exception) else 0.0
            tfidf_sim = results[1] if not isinstance(results[1], Exception) else 0.0
            jaccard_sim = results[2] if not isinstance(results[2], Exception) else 0.0
            edit_sim = results[3] if not isinstance(results[3], Exception) else 0.0

            # Calculate weighted overall similarity
            overall_similarity = self._calculate_weighted_similarity(
                bert_sim, tfidf_sim, jaccard_sim, edit_sim
            )

            # Determine preservation level
            preservation_level = self._determine_preservation_level(overall_similarity)

            # Calculate confidence based on agreement between methods
            confidence = self._calculate_confidence(bert_sim, tfidf_sim, jaccard_sim, edit_sim)

            # Create result object
            result = SemanticSimilarity(
                overall_similarity=overall_similarity,
                bert_similarity=bert_sim,
                tfidf_similarity=tfidf_sim,
                jaccard_similarity=jaccard_sim,
                edit_distance_similarity=edit_sim,
                preservation_level=preservation_level,
                confidence=confidence,
                analysis_method="bert_ensemble",
                details={
                    "analysis_time_ms": (time.time() - start_time) * 1000,
                    "cache_hit": False,
                    "method_agreement": self._calculate_method_agreement(bert_sim, tfidf_sim, jaccard_sim, edit_sim),
                    "text_statistics": {
                        "original_words": len(original_text.split()),
                        "translated_words": len(translated_text.split()),
                        "length_ratio": len(translated_text) / max(len(original_text), 1)
                    }
                }
            )

            # Cache the result
            self._cache_result(cache_key, result)

            logger.info("Semantic similarity analysis completed",
                       overall_similarity=overall_similarity,
                       preservation_level=preservation_level.value,
                       confidence=confidence)

            return result

        except Exception as e:
            logger.error("Semantic similarity analysis failed", error=str(e))
            # Return fallback similarity result
            return self._fallback_similarity(original_text, translated_text)

    async def _initialize_bert_model(self) -> None:
        """Initialize BERT model for semantic embeddings."""
        try:
            import torch
            from transformers import AutoTokenizer, AutoModel

            # Use a lightweight but effective model
            model_name = self.config.get("bert_model", "sentence-transformers/all-MiniLM-L6-v2")

            logger.info(f"Loading BERT model: {model_name}")

            self.bert_tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.bert_model = AutoModel.from_pretrained(model_name)

            # Set to evaluation mode
            self.bert_model.eval()

            logger.info("BERT model loaded successfully")

        except ImportError:
            logger.warning("Transformers library not available, BERT similarity will be disabled")
            self.bert_model = None
            self.bert_tokenizer = None
        except Exception as e:
            logger.error(f"Failed to load BERT model: {e}")
            self.bert_model = None
            self.bert_tokenizer = None

    async def _initialize_tfidf(self) -> None:
        """Initialize TF-IDF vectorizer."""
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer

            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=1000,
                ngram_range=(1, 3),
                stop_words='english',
                lowercase=True,
                strip_accents='unicode'
            )

            logger.info("TF-IDF vectorizer initialized")

        except ImportError:
            logger.warning("Scikit-learn not available, TF-IDF similarity will be disabled")
            self.tfidf_vectorizer = None

    async def _bert_similarity(self, text1: str, text2: str) -> float:
        """Calculate BERT-based semantic similarity."""
        if not self.bert_model or not self.bert_tokenizer:
            return 0.0

        try:
            import torch
            import torch.nn.functional as F

            def get_embedding(text):
                inputs = self.bert_tokenizer(
                    text, return_tensors="pt",
                    truncation=True, padding=True, max_length=512
                )
                with torch.no_grad():
                    outputs = self.bert_model(**inputs)
                    # Use mean pooling
                    embeddings = outputs.last_hidden_state.mean(dim=1)
                return F.normalize(embeddings, p=2, dim=1)

            # Get embeddings
            emb1 = get_embedding(text1)
            emb2 = get_embedding(text2)

            # Calculate cosine similarity
            similarity = torch.cosine_similarity(emb1, emb2).item()

            # Ensure similarity is between 0 and 1
            return max(0.0, min(1.0, similarity))

        except Exception as e:
            logger.warning(f"BERT similarity calculation failed: {e}")
            return 0.0

    async def _tfidf_similarity(self, text1: str, text2: str) -> float:
        """Calculate TF-IDF based similarity."""
        if not self.tfidf_vectorizer:
            return 0.0

        try:
            from sklearn.metrics.pairwise import cosine_similarity

            # Fit and transform both texts
            corpus = [text1, text2]
            tfidf_matrix = self.tfidf_vectorizer.fit_transform(corpus)

            # Calculate cosine similarity
            similarity = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]

            return max(0.0, min(1.0, similarity))

        except Exception as e:
            logger.warning(f"TF-IDF similarity calculation failed: {e}")
            return 0.0

    async def _jaccard_similarity(self, text1: str, text2: str) -> float:
        """Calculate Jaccard similarity based on word sets."""
        try:
            # Tokenize and convert to sets
            words1 = set(text1.lower().split())
            words2 = set(text2.lower().split())

            if not words1 and not words2:
                return 1.0
            if not words1 or not words2:
                return 0.0

            intersection = words1.intersection(words2)
            union = words1.union(words2)

            return len(intersection) / len(union)

        except Exception as e:
            logger.warning(f"Jaccard similarity calculation failed: {e}")
            return 0.0

    async def _edit_distance_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity based on edit distance."""
        try:
            # Levenshtein distance implementation
            def levenshtein_distance(s1, s2):
                if len(s1) < len(s2):
                    return levenshtein_distance(s2, s1)

                if len(s2) == 0:
                    return len(s1)

                previous_row = list(range(len(s2) + 1))
                for i, c1 in enumerate(s1):
                    current_row = [i + 1]
                    for j, c2 in enumerate(s2):
                        insertions = previous_row[j + 1] + 1
                        deletions = current_row[j] + 1
                        substitutions = previous_row[j] + (c1 != c2)
                        current_row.append(min(insertions, deletions, substitutions))
                    previous_row = current_row

                return previous_row[-1]

            max_len = max(len(text1), len(text2))
            if max_len == 0:
                return 1.0

            distance = levenshtein_distance(text1.lower(), text2.lower())
            similarity = 1.0 - (distance / max_len)

            return max(0.0, min(1.0, similarity))

        except Exception as e:
            logger.warning(f"Edit distance similarity calculation failed: {e}")
            return 0.0

    def _calculate_weighted_similarity(self, bert: float, tfidf: float,
                                     jaccard: float, edit: float) -> float:
        """Calculate weighted overall similarity."""
        # Weights based on reliability and semantic accuracy
        weights = {
            'bert': 0.4,      # Highest weight for semantic understanding
            'tfidf': 0.3,     # Good for content similarity
            'jaccard': 0.2,   # Word overlap
            'edit': 0.1       # Lowest weight for character-level similarity
        }

        weighted_sum = (
            bert * weights['bert'] +
            tfidf * weights['tfidf'] +
            jaccard * weights['jaccard'] +
            edit * weights['edit']
        )

        return min(1.0, max(0.0, weighted_sum))

    def _determine_preservation_level(self, similarity: float) -> SemanticPreservationLevel:
        """Determine semantic preservation level based on similarity score."""
        if similarity >= 0.95:
            return SemanticPreservationLevel.EXACT
        elif similarity >= 0.85:
            return SemanticPreservationLevel.HIGH
        elif similarity >= 0.70:
            return SemanticPreservationLevel.MEDIUM
        elif similarity >= 0.50:
            return SemanticPreservationLevel.LOW
        else:
            return SemanticPreservationLevel.POOR

    def _calculate_confidence(self, bert: float, tfidf: float,
                            jaccard: float, edit: float) -> float:
        """Calculate confidence based on agreement between methods."""
        scores = [bert, tfidf, jaccard, edit]
        valid_scores = [s for s in scores if s > 0]

        if len(valid_scores) < 2:
            return 0.5  # Low confidence with insufficient methods

        # Calculate standard deviation as measure of disagreement
        mean_score = np.mean(valid_scores)
        std_dev = np.std(valid_scores)

        # Convert to confidence (lower std_dev = higher confidence)
        confidence = max(0.1, 1.0 - (std_dev * 2))

        return min(1.0, confidence)

    def _calculate_method_agreement(self, bert: float, tfidf: float,
                                  jaccard: float, edit: float) -> float:
        """Calculate agreement between different similarity methods."""
        scores = [s for s in [bert, tfidf, jaccard, edit] if s > 0]
        if len(scores) < 2:
            return 0.0

        # Calculate pairwise differences
        total_diff = 0
        pairs = 0
        for i in range(len(scores)):
            for j in range(i + 1, len(scores)):
                total_diff += abs(scores[i] - scores[j])
                pairs += 1

        avg_diff = total_diff / pairs if pairs > 0 else 1.0
        agreement = 1.0 - avg_diff  # Lower difference = higher agreement

        return max(0.0, agreement)

    def _fallback_similarity(self, text1: str, text2: str) -> SemanticSimilarity:
        """Fallback similarity calculation when other methods fail."""
        try:
            # Simple word overlap similarity
            words1 = set(text1.lower().split())
            words2 = set(text2.lower().split())

            if not words1 and not words2:
                similarity = 1.0
            elif not words1 or not words2:
                similarity = 0.0
            else:
                intersection = words1.intersection(words2)
                union = words1.union(words2)
                similarity = len(intersection) / len(union)

            return SemanticSimilarity(
                overall_similarity=similarity,
                jaccard_similarity=similarity,
                preservation_level=self._determine_preservation_level(similarity),
                confidence=0.3,  # Low confidence for fallback
                analysis_method="fallback_jaccard"
            )

        except Exception:
            return SemanticSimilarity(
                overall_similarity=0.0,
                preservation_level=SemanticPreservationLevel.POOR,
                confidence=0.1,
                analysis_method="fallback_failed"
            )

    def _generate_cache_key(self, text1: str, text2: str) -> str:
        """Generate cache key for similarity results."""
        combined = f"{text1}|{text2}"
        return hashlib.md5(combined.encode()).hexdigest()

    def _cache_result(self, key: str, result: SemanticSimilarity) -> None:
        """Cache similarity result."""
        if len(self._cache) >= self._cache_size_limit:
            # Remove oldest entry (simple FIFO)
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]

        self._cache[key] = result

    async def shutdown(self) -> None:
        """Shutdown the semantic analyzer."""
        logger.info("Shutting down Semantic Similarity Analyzer")
        self._cache.clear()
        self.bert_model = None
        self.bert_tokenizer = None
        self.tfidf_vectorizer = None
        self._initialized = False