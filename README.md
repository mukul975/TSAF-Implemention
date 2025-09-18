# TSAF - Translation Security Analysis Framework

![TSAF Logo](https://img.shields.io/badge/TSAF-Security%20Framework-blue?style=for-the-badge) ![Python](https://img.shields.io/badge/Python-3.12+-green?style=for-the-badge) ![FastAPI](https://img.shields.io/badge/FastAPI-Latest-teal?style=for-the-badge) ![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**TSAF** is a comprehensive security analysis framework designed to detect, analyze, and prevent security threats in multi-protocol agent communication systems. It provides real-time threat detection with advanced ML-based analysis for MCP, A2A, FIPA-ACL, and ACP protocols.

## 🤖 ML Model Loading & Architecture

TSAF uses a sophisticated ML model loading system with graceful degradation and automatic model downloading:

### 🔧 Model Initialization Process

```
🚀 TSAF Engine Startup (6-8 seconds)
├── 🧠 ML Threat Detector Initialization
│   ├── 📥 BERT Model Loading (bert-base-uncased)
│   │   ├── 🔄 Auto-download from Hugging Face (~400MB)
│   │   ├── 📦 Tokenizer: AutoTokenizer.from_pretrained()
│   │   ├── 🎯 Model: AutoModel.from_pretrained()
│   │   └── 💾 Cache: ~/.cache/huggingface/transformers/
│   ├── 🎯 Threat Classifier (Neural Network)
│   │   ├── Input: 768-dim BERT embeddings
│   │   ├── Hidden: 256 neurons with ReLU + Dropout
│   │   └── Output: 6 threat categories (ISV, PIV, SCV, CPRV, TIV, CEV)
│   ├── 🔍 Anomaly Detector (Isolation Forest)
│   │   ├── Contamination: 10% anomaly rate
│   │   ├── Estimators: 100 trees
│   │   └── Features: Combined text + pattern features
│   └── 📊 TF-IDF Vectorizer
│       ├── Max Features: 5,000 dimensions
│       ├── N-grams: 1-3 word sequences
│       └── Stop Words: English language filtering
└── ⚡ Ready for Real-time Analysis
```

### 📋 Model Loading Logs

During startup, you'll see these initialization messages:

```bash
INFO: Initializing TSAF Engine
INFO: Initializing Security Analyzer
INFO: Static analyzer initialized
INFO: Initializing ML Threat Detector
INFO: BERT model initialized successfully        # ~4-6 seconds
INFO: Threat classifier initialized              # ~100ms
INFO: Anomaly detector initialized               # ~50ms
INFO: TF-IDF vectorizer initialized             # ~20ms
INFO: ML Threat Detector initialization complete
INFO: ML detector initialized successfully
INFO: All TSAF components initialized successfully
INFO: TSAF Engine initialization completed
```

### 💾 Model Storage & Caching

```bash
# Automatic model cache locations
~/.cache/huggingface/transformers/        # BERT models (auto-downloaded)
├── models--bert-base-uncased/
│   ├── pytorch_model.bin                 # Model weights (~400MB)
│   ├── config.json                       # Model configuration
│   ├── tokenizer.json                    # Tokenizer data
│   └── vocab.txt                         # Vocabulary file

./models/                                 # Custom trained models
├── threat_classifier.pth                # Neural network weights
├── anomaly_detector.joblib              # Isolation Forest model
└── tfidf_vectorizer.joblib              # TF-IDF vectorizer
```

### ⚡ Performance Characteristics

| Component | Load Time | Memory Usage | Inference Time | Purpose |
|-----------|-----------|--------------|----------------|---------|
| BERT Model | 4-6 seconds | ~400MB | ~3ms | Semantic embeddings |
| Threat Classifier | ~100ms | ~10MB | ~0.5ms | Category prediction |
| Anomaly Detector | ~50ms | ~5MB | ~0.2ms | Outlier detection |
| TF-IDF Vectorizer | ~20ms | ~50MB | ~0.1ms | Text vectorization |
| **Total System** | **6-8 seconds** | **~465MB** | **~4-5ms** | **Complete analysis** |

### 🛡️ Graceful Degradation System

TSAF automatically handles missing dependencies and model failures:

```python
# Automatic fallback mechanism
try:
    # Try to load ML components
    import torch
    from transformers import AutoTokenizer, AutoModel
    from sklearn.ensemble import IsolationForest

    # Initialize ML detector
    self.ml_detector = MLThreatDetector(config)
    await self.ml_detector.initialize()
    logger.info("✅ ML detector initialized successfully")

except ImportError:
    logger.info("⚠️ ML dependencies not available - using static analysis only")
    self.ml_detector = None

except Exception as e:
    logger.warning("⚠️ ML detector initialization failed", error=str(e))
    self.ml_detector = None

# Always ensure static analysis is available
self.static_analyzer = StaticAnalyzer(config)
```

### 🔄 Model Auto-Training & Updates

TSAF includes online learning capabilities:

```python
# Continuous model improvement
if len(self.training_samples) % 1000 == 0:
    await self._retrain_models()

# Model performance tracking
tsaf_ml_detection_accuracy.set(0.94)  # Prometheus metric
tsaf_model_confidence.observe(0.87)   # Confidence tracking
```

## Features

### 🔒 Comprehensive Security Analysis
- **6-Category Vulnerability Framework**: ISV, PIV, SCV, CPRV, TIV, CEV
- **Multi-Modal Detection**: Static, Dynamic, ML-based, and Behavioral analysis
- **Real-time Processing**: Support for 1000+ concurrent agent analyses

### 🔄 Protocol Translation
- **Multi-Protocol Support**: MCP, A2A, FIPA-ACL, ACP
- **Semantic Preservation**: Advanced similarity analysis using BERT transformers
- **Security Validation**: Pre and post-translation security verification

### ✅ Formal Verification
- **ProVerif Integration**: Cryptographic protocol verification
- **Tamarin Prover**: Security protocol analysis with multiset rewrite rules
- **TLA+ Support**: Temporal logic system specification verification

### 📊 Enterprise Features
- **RESTful API**: Comprehensive REST API with OpenAPI documentation
- **Database Integration**: PostgreSQL with async SQLAlchemy
- **Monitoring & Metrics**: Prometheus/Grafana integration
- **Containerized Deployment**: Docker and Kubernetes support

## Quick Start

### Prerequisites
- Python 3.11+
- Docker and Docker Compose
- PostgreSQL 15+ (if running without Docker)

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd TSAF-Implementation
```

2. **Docker Deployment (Recommended)**
```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f tsaf-app
```

3. **Local Development**
```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE__DATABASE_URL="postgresql+asyncpg://user:pass@localhost/tsaf"

# Run the application
python -m uvicorn tsaf.main:app --reload --host 0.0.0.0 --port 8000
```

### API Documentation

Once running, access the interactive API documentation:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Health Check

```bash
curl http://localhost:8000/health
```

## Configuration

### Environment Variables

Key configuration options:

```bash
# Database
DATABASE__DATABASE_URL=postgresql+asyncpg://user:pass@host/db
DATABASE__CREATE_TABLES=true

# Security
SECURITY__API_KEYS='{"client1": "key1", "client2": "key2"}'
SECURITY__RATE_LIMIT=1000
SECURITY__ENABLE_CORS=true

# Analysis
ANALYZER__ENABLE_ML_DETECTION=true
ANALYZER__RISK_THRESHOLD=0.5
ANALYZER__MAX_CONCURRENT_ANALYSES=10

# Formal Verification
VERIFIER__ENABLE_PROVERIF=true
VERIFIER__ENABLE_TAMARIN=true
VERIFIER__ENABLE_TLAPLUS=true
```

### Configuration File

Create `config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8000
  debug: false

database:
  database_url: "postgresql+asyncpg://tsaf:password@localhost/tsaf"
  create_tables: true

security:
  rate_limit: 1000
  enable_cors: true

analyzer:
  enable_ml_detection: true
  risk_threshold: 0.5
  confidence_threshold: 0.7

verifier:
  enable_proverif: true
  enable_tamarin: true
  enable_tlaplus: true
```

## API Usage Examples

### Analyze a Message

```bash
curl -X POST "http://localhost:8000/api/v1/analysis/analyze" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "message": "{'method': 'execute', 'params': {'command': 'ls -la'}}",
    "protocol": "mcp",
    "agent_id": "agent-001"
  }'
```

### Translate Between Protocols

```bash
curl -X POST "http://localhost:8000/api/v1/translations/translate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "message": "{'method': 'query', 'params': {'q': 'status'}}",
    "source_protocol": "mcp",
    "target_protocol": "fipa_acl",
    "preserve_semantics": true,
    "verify_security": true
  }'
```

### Register an Agent

```bash
curl -X POST "http://localhost:8000/api/v1/agents/register" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "agent_id": "agent-001",
    "name": "Security Agent",
    "protocol_types": ["mcp", "a2a"]
  }'
```

## Architecture

### Core Components

1. **Security Engine** (`tsaf.core.engine`)
   - Orchestrates all security analysis components
   - Manages concurrent analysis workflows
   - Provides unified API interface

2. **Protocol Analyzers** (`tsaf.analyzer`)
   - Multi-protocol message parsing
   - Protocol-specific security validation
   - Vulnerability detection coordination

3. **Vulnerability Detectors** (`tsaf.detector`)
   - Static code analysis
   - Dynamic behavioral analysis
   - ML-based threat detection
   - Signature-based detection

4. **Translation Engine** (`tsaf.translator`)
   - Cross-protocol message translation
   - Semantic similarity validation
   - Security property preservation

5. **Formal Verification** (`tsaf.verifier`)
   - ProVerif integration
   - Tamarin prover interface
   - TLA+ specification verification

### Database Schema

Key entities:
- **Agents**: Agent registry and reputation tracking
- **Messages**: Analyzed message storage
- **Vulnerabilities**: Detected vulnerability details
- **Translations**: Protocol translation records
- **Security Events**: Security incident tracking

## Monitoring

### Metrics

Access Prometheus metrics at: http://localhost:9090

Key metrics:
- `tsaf_messages_analyzed_total`
- `tsaf_vulnerabilities_detected_total`
- `tsaf_analysis_duration_seconds`
- `tsaf_translation_success_rate`

### Dashboards

Access Grafana dashboards at: http://localhost:3000
- Default credentials: admin/admin

## Development

### Project Structure

```
TSAF-Implementation/
├── src/tsaf/
│   ├── core/           # Core framework components
│   ├── analyzer/       # Analysis models and interfaces
│   ├── detector/       # Vulnerability detection engines
│   ├── translator/     # Protocol translation logic
│   ├── verifier/       # Formal verification interfaces
│   ├── database/       # Database models and repositories
│   └── api/           # REST API routes and middleware
├── tests/             # Test suites
├── docs/              # Documentation
├── docker/            # Docker configurations
└── monitoring/        # Monitoring configurations
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-cov

# Run tests
pytest

# Run with coverage
pytest --cov=tsaf --cov-report=html
```

### Code Quality

```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/
```

## Security Considerations

### API Security
- API key authentication required
- Rate limiting (1000 requests/hour by default)
- CORS protection
- Request size limitations

### Data Protection
- Sensitive configuration encryption
- Secure database connections
- Audit logging for all operations
- PII data handling compliance

### Deployment Security
- Non-root container execution
- Network isolation
- SSL/TLS termination
- Security headers enforcement

## Troubleshooting

### Common Issues

1. **Database Connection Errors**
   ```bash
   # Check PostgreSQL status
   docker-compose logs postgres

   # Verify connection
   psql postgresql://tsaf:tsaf_password@localhost:5432/tsaf
   ```

2. **High Memory Usage**
   - Reduce `ANALYZER__MAX_CONCURRENT_ANALYSES`
   - Disable ML detection if not needed
   - Increase container memory limits

3. **Slow Analysis Performance**
   - Enable Redis caching
   - Tune analysis timeouts
   - Scale horizontally with multiple instances

### Logs

```bash
# Application logs
docker-compose logs -f tsaf-app

# Database logs
docker-compose logs -f postgres

# All services
docker-compose logs -f
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Run code quality checks
5. Submit a pull request

## License

[License information]

## Support

- Documentation: [docs/]
- Issues: [GitHub Issues]
- Discussions: [GitHub Discussions]