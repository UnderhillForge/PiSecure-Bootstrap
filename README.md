# PiSecure Bootstrap Node

An intelligent, ML-powered bootstrap node for the PiSecure P2P network with advanced threat detection, DEX coordination, and real-time network intelligence.

## 🚀 Current Status

**✅ Successfully Deployed on Railway**
- Domain: `bootstrap.pisecure.org`
- Railway Service: Active and running
- Builder: Metal (optimized for performance)

**🆕 Latest Updates (Deployed 2026-01-21)**
  - `/nodes` - Node registration and heartbeat events
  - `/threats` - Real-time threat alerts and defense coordination
  - `/health` - Network metrics and consensus status
  - `/dex` - DEX pool updates and trading activity
  - `/rates` - Rate limit and quota updates

**🆕 Latest Updates (Deployed 2026-01-25)**
 ✅ **PiSecure Blockchain Integration**: Complete bidirectional integration with pisecured
  - **Channel 1**: Blockchain Health Monitoring (difficulty, hashrate, threat level)
  - **Channel 2**: Mining Template Caching (<2ms latency for pool operators)
  - **Channel 3**: Transaction Monitoring (mempool health, fee data)
  - **Channel 4**: Wallet Balance Validation (reward fraud detection)
  - **Channel 5**: Peer Network Intelligence (cross-validation, diversity analysis)
 ✅ **WebSocket Real-Time**: All channels broadcast via `/health`, `/dex`, `/nodes` namespaces
 ✅ **HTTP Fallback**: All endpoints available via REST API
 ✅ **Documentation**: [PISECURE_INTEGRATION_GUIDE.md](docs/PISECURE_INTEGRATION_GUIDE.md) with complete specifications
 ✅ **Production Ready**: Thread-safe, failure-resistant, fully tested

**Previous Updates (Deployed 2026-01-13)**
- ✅ **Services Status API**: New `/api/v1/services/status` endpoint with real-time port information
- ✅ **Ghostwheel Support**: Added `sentinel_ai` node type for Ghostwheel registration
- ✅ **Federated Dashboards**: Secondary nodes now proxy registry + Ghostwheel status from the primary cluster
- ✅ **Dashboard Enhancements**: Service Status card now displays actual running ports
- ✅ **API Documentation**: Complete documentation for all endpoints
- ✅ **Intelligence Federation**: Cross-bootstrap threat sharing active
- ✅ **DEX Coordination**: Bootstrap-level token swap orchestration ready

**✅ Raspberry Pi 5 Support**
- Automated installation script available
- Optimized for 64-bit Raspberry Pi OS Lite
- Production-ready deployment with security hardening

## 📋 Features

### Core Functionality
- **ML-Powered Threat Detection**: Isolation Forest anomaly detection
- **Intelligent Peer Discovery**: Statistical routing optimization
- **DEX Coordination**: Bootstrap-level token swap orchestration
- **314ST Token Rewards**: Native rewards for network participation
- **Real-time Network Intelligence**: Geographic clustering and analysis

### Advanced Features
- **Node Registry System**: Automatic registration and status tracking
- **Inactive Node Cleanup**: 24-hour timeout for stale nodes
- **Intelligence Federation**: Cross-bootstrap threat sharing
- **Performance Analytics**: Real-time scoring and recommendations
- **Token Valuation Dashboard**: Fundamental + market price analysis

## 🔗 API Endpoints

### Core Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Root health check |
| `/health` | GET | Health check endpoint |
| `/api/v1/health` | GET | API health check with details |
| `/hello` | GET | DNS testing page |
| `/nodes` | GET | Real-time network dashboard |

### Intelligence & Defense
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/intelligence/health` | GET | Network intelligence analysis |
| `/api/v1/intelligence/attacks` | GET | ML-powered attack detection |
| `/api/v1/intelligence/defense` | GET | Automated defense status |
| `/api/v1/intelligence/optimize` | POST | Routing optimization |
| `/api/v1/intelligence/predict` | GET | Load prediction |

### Bootstrap Coordination
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/bootstrap/handshake` | POST | Bootstrap node registration |
| `/api/v1/bootstrap/registry` | GET | Active bootstrap nodes |
| `/api/v1/bootstrap/coordinate` | POST | Service distribution |

### Node Management & Real-Time

### PiSecure Blockchain Integration
| Endpoint | Method | Description | Spec |
|----------|--------|-------------|------|
| `/api/v1/blockchain/metrics` | GET | PiSecure chain health & threat level | [📋 PISECURE_INTEGRATION_GUIDE.md](docs/PISECURE_INTEGRATION_GUIDE.md#1️⃣-blockchain-health-monitoring) |
| `/api/v1/mining/relay` | GET | Mining template cache & distribution | [📋 PISECURE_INTEGRATION_GUIDE.md](docs/PISECURE_INTEGRATION_GUIDE.md#2️⃣-mining-template-caching--distribution) |
| `/api/v1/mempool` | GET | Transaction monitoring & mempool health | [📋 PISECURE_INTEGRATION_GUIDE.md](docs/PISECURE_INTEGRATION_GUIDE.md#3️⃣-transaction-monitoring--mempool-health) |
| `/api/v1/wallet/validate` | POST | Wallet balance validation for fraud detection | [📋 PISECURE_INTEGRATION_GUIDE.md](docs/PISECURE_INTEGRATION_GUIDE.md#4️⃣-wallet-balance-validation) |
| `/api/v1/network/peer-health` | GET | Peer network health & recommendations | [📋 PISECURE_INTEGRATION_GUIDE.md](docs/PISECURE_INTEGRATION_GUIDE.md#5️⃣-peer-network-intelligence-validation) |

| Endpoint | Method | Description | Spec |
|----------|--------|-------------|------|
| `/api/v1/nodes/register` | POST | PiSecure node registration | [📋 api-node-registration.md](docs/api-node-registration.md) |
| `/api/v1/nodes/status` | POST | Node status updates | [📋 api-node-registration.md](docs/api-node-registration.md) |
| `/api/v1/nodes/list` | GET | Registered nodes directory | [📋 api-node-registration.md](docs/api-node-registration.md) |
| `/api/v1/hardware/entropy` | POST | Hardware RNG entropy validation | [📋 api-entropy-validation.md](docs/api-entropy-validation.md) |
| **`wss:///nodes`** | **WS** | **Real-time node events** | **[📋 WEBSOCKET_SPECIFICATION.md](docs/WEBSOCKET_SPECIFICATION.md)** |
| **`wss:///threats`** | **WS** | **Real-time threat alerts** | **[📋 WEBSOCKET_SPECIFICATION.md](docs/WEBSOCKET_SPECIFICATION.md)** |
| **`wss:///health`** | **WS** | **Real-time network metrics** | **[📋 WEBSOCKET_SPECIFICATION.md](docs/WEBSOCKET_SPECIFICATION.md)** |
| **`wss:///dex`** | **WS** | **Real-time DEX updates** | **[📋 WEBSOCKET_SPECIFICATION.md](docs/WEBSOCKET_SPECIFICATION.md)** |
| **`wss:///rates`** | **WS** | **Real-time rate limits** | **[📋 WEBSOCKET_SPECIFICATION.md](docs/WEBSOCKET_SPECIFICATION.md)** |

### DEX & Token Economics
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/dex/pools` | GET | Available liquidity pools |
| `/api/v1/dex/swap` | POST | Intelligent token swaps |
| `/api/v1/dex/intelligence` | GET | DEX market analysis |
| `/api/v1/operator/314st-analytics` | GET | Reward analytics |

## 🛠️ Installation

### Raspberry Pi 5 (Recommended)
For production deployment on Raspberry Pi 5 with 64-bit OS Lite:

```bash
# Download and run the automated installation script
curl -fsSL https://raw.githubusercontent.com/UnderhillForge/PiSecure-Bootstrap/main/install.sh | bash
```

**What the script installs:**
- ✅ Complete system security hardening
- ✅ PiSecure bootstrap node with ML intelligence
- ✅ Automatic service management (systemd)
- ✅ Health monitoring and backups
- ✅ Performance optimizations for RPi 5
- ✅ Firewall and SSH hardening
- ✅ Daily security updates

**Post-installation:**
1. Configure your operator wallet: `sudo nano /opt/pisecure/bootstrap/.env`
2. Access dashboard: `http://<your-pi-ip>:8080/nodes`
3. Monitor logs: `sudo journalctl -u pisecure-bootstrap -f`

### Railway Cloud Deployment
```bash
# Clone repository
git clone https://github.com/UnderhillForge/PiSecure-Bootstrap.git
cd PiSecure-Bootstrap

# Deploy to Railway (requires Railway CLI)
railway login
railway link
railway up
```

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
python bootstrap/server.py
```

## 🔧 Configuration

### Environment Variables
```bash
# Core Configuration
FLASK_ENV=production
PORT=8080

# 314ST Rewards
BOOTSTRAP_OPERATOR_WALLET=your_pisecure_wallet_address
BOOTSTRAP_REWARD_PERCENTAGE=0.05
BOOTSTRAP_MINIMUM_PAYOUT=10
BOOTSTRAP_DAILY_BUDGET=1000

# Database & Logging
DATABASE_URL=sqlite:////var/lib/pisecure/pisecure_bootstrap.db
LOG_LEVEL=INFO
LOG_FILE=/var/log/pisecure/bootstrap.log

# Network
BOOTSTRAP_HOST=0.0.0.0
BOOTSTRAP_PORT=3142
API_HOST=0.0.0.0
API_PORT=8080

# Federation Sync
PRIMARY_BOOTSTRAP_DOMAIN=bootstrap.pisecure.org
PRIMARY_BOOTSTRAP_SCHEME=https
PRIMARY_BOOTSTRAP_TIMEOUT=6
PRIMARY_NODELIST_CACHE_TTL=15
BOOTSTRAP_PEERS_CACHE_TTL=45
PISECURE_GENESIS_HASH=2742129a6e95a85dbac0d62cb59c3b8fb9d5a4f56b67a4beec72e59a0bd0f8c2

# Startup Performance
BOOTSTRAP_LAZY_ML_INIT=1
BOOTSTRAP_LAZY_ML_DELAY=5
ASYNC_GEO_LOOKUPS=1
# Set to 1 to skip the automatic peer cache warmup thread
BOOTSTRAP_DISABLE_PEER_WARMUP=0
```

Secondary deployments automatically proxy `/api/v1/nodes/list` from the domain defined by `PRIMARY_BOOTSTRAP_DOMAIN`, and the optional `PRIMARY_NODELIST_CACHE_TTL` (seconds) controls how long the shared directory is cached locally.
`BOOTSTRAP_PEERS_CACHE_TTL` (clamped between 30-60 seconds, default 45) drives the stale-while-revalidate cache for `/api/v1/bootstrap/peers`, so clients get a cached response in <1s while a background refresh keeps the snapshot under the 5s SLA, and `PISECURE_GENESIS_HASH` sets the advertised genesis hash in peer metadata for clients that verify responses.

`/api/v1/bootstrap/registry` also includes an `origin_node` object for the hosting server, making it obvious to dashboards and operators whether the instance they are connected to is the canonical primary, an acting primary, or a secondary node.

`BOOTSTRAP_LAZY_ML_INIT` defers the scikit-learn model construction to a background thread (default on) so cold starts stay under the Railway 2s SLA. Tune `BOOTSTRAP_LAZY_ML_DELAY` (seconds) to control how long the server waits before warming those models, or set the flag to `0` to build everything synchronously. `ASYNC_GEO_LOOKUPS` shifts slow ip-api.com calls off the request path, returning cached or `'unknown'` immediately while a worker thread back-fills the database cache. Finally, the server now primes a default `/api/v1/bootstrap/peers` snapshot in the background; disable that warmup entirely by setting `BOOTSTRAP_DISABLE_PEER_WARMUP=1` if a deployment needs to minimize background threads.

Mainnet deployments should keep the default `2742129a6e95a85dbac0d62cb59c3b8fb9d5a4f56b67a4beec72e59a0bd0f8c2` hash. For testnet clusters, override `PISECURE_GENESIS_HASH` with `cedf0871ffacca577bd02d5db5e8c6ba2e1d6cdff43cdadc17c63dc58ed3c24d`.

When the canonical primary (`bootstrap.pisecure.org`) is unreachable, secondary nodes now elect an acting primary using the new health-scored failover logic. Both `/api/v1/bootstrap/peers` and `/api/v1/bootstrap/registry` include a `primary_status` object so operators and clients can see whether the canonical host is reachable, which node is currently acting primary, and when that election happened. Acting primaries are marked with `role: acting_primary` and `status: degraded` in the returned descriptors until the canonical host recovers.

### Raspberry Pi Configuration
The installation script automatically configures:
- Systemd service with security hardening
- UFW firewall with rate limiting
- Fail2ban SSH protection
- Automatic backups and log rotation
- Performance optimizations for RPi 5

## 📊 Dashboard Features

### Real-Time Network Dashboard (`/nodes`)
- **Live Statistics**: Active nodes, hashrate, block times
- **Geographic Analysis**: ML-powered region clustering
- **Threat Intelligence**: Real-time attack detection
- **DEX Analytics**: Pool health and trading volume
- **Token Valuation**: Fundamental + market price analysis
- **Node Registry**: Active participant directory

### 314ST Token Valuation
- **Fundamental Analysis**: Mining costs, development value, utility
- **Market Price Tracking**: DEX trading data and sentiment
- **Premium/Discount Analysis**: Fair value vs. market price
- **Fair Launch Tracking**: Mining progress and allocation
- **Real-Time Updates**: Live pricing and analysis

## 🔒 Security Features

### ML-Powered Defense
- **Anomaly Detection**: Isolation Forest for attack identification
- **Automated Response**: Rate limiting and traffic diversion
- **Threat Intelligence**: Cross-bootstrap threat sharing
- **Geographic Analysis**: Attack pattern recognition

### System Security
- **SSH Hardening**: Key-only authentication, hardened config
- **Firewall**: UFW with rate limiting and geo-blocking
- **Fail2ban**: SSH brute force protection
- **Automatic Updates**: Security patches applied automatically

### Application Security
- **Input Validation**: Comprehensive API input sanitization
- **Rate Limiting**: Intelligent API rate limiting
- **Access Control**: Bootstrap federation authentication
- **Data Privacy**: Privacy-preserving intelligence aggregation

## 📈 Monitoring & Maintenance

### Health Monitoring
```bash
# Check service status
sudo systemctl status pisecure-bootstrap

# View real-time logs
sudo journalctl -u pisecure-bootstrap -f

# Health check
curl http://localhost:8080/health
```

### Backup & Recovery
- **Automatic Backups**: Daily at 2 AM
- **Retention**: 7 days of backups
- **Recovery**: Simple restore from backup archives

### Performance Monitoring
- **Resource Usage**: CPU, memory, network monitoring
- **API Performance**: Response times and error rates
- **Intelligence Metrics**: ML model accuracy and processing times

## 🤝 Network Participation

### For PiSecure Nodes
```bash
# Register with bootstrap
curl -X POST "https://bootstrap.pisecure.org/api/v1/nodes/register" \
     -H "Content-Type: application/json" \
     -d '{"node_id": "your-node-id", "node_type": "miner", "services": ["mining"]}'

# Send status updates
curl -X POST "https://bootstrap.pisecure.org/api/v1/nodes/status" \
     -H "Content-Type: application/json" \
     -d '{"node_id": "your-node-id", "status": "active", "mining_active": true}'

# Submit hardware entropy for validation (32 bytes as hex)
curl -X POST "https://bootstrap.pisecure.org/api/v1/hardware/entropy" \
     -H "Content-Type: application/json" \
     -d '{"node_id": "your-node-id", "entropy_hex": "a1b2c3d4e5f6..."}'
```

### Hardware RNG Entropy Validation
The bootstrap node validates hardware random number generators (RNG) using **NIST SP 800-90B** statistical tests:

- **Chi-Square Test**: Validates uniform byte distribution
- **Runs Test**: Detects patterns in bit sequences  
- **Longest Run Test**: Identifies abnormal consecutive bit runs
- **Shannon Entropy**: Measures randomness quality (bits per byte)

**Requirements:**
- Submit 32 bytes of entropy as hexadecimal string
- Minimum acceptable entropy: 4.5 bits/byte (realistic for 32-byte samples)
- Failed submissions result in reputation penalties
- Nodes with consistent low entropy may be quarantined

**Example Response:**
```json
{
  "validation_result": true,
  "quality_score": 87.5,
  "entropy_estimate_bits_per_byte": 7.89,
  "node_entropy_history": {
    "total_samples": 15,
    "pass_rate": 0.93,
    "avg_quality": 85.2
  }
}
```

### For Bootstrap Operators
1. **Configure Wallet**: Set `BOOTSTRAP_OPERATOR_WALLET` for 314ST rewards
2. **Monitor Earnings**: Use `/api/v1/operator/314st-analytics`
3. **Federation**: Join bootstrap federation for intelligence sharing
4. **DEX Coordination**: Enable DEX pool management

## 🎯 Advanced Features

### Intelligence Federation
- **Threat Sharing**: Cross-bootstrap attack intelligence
- **Performance Correlation**: Network-wide performance analysis
- **Predictive Scaling**: ML-based capacity planning

### Token Economics
- **Fair Launch Mining**: 200K tokens earned through work
- **DEX Fee Sharing**: Bootstrap operators earn from trading
- **Utility Rewards**: Intelligence contributions earn tokens
- **Treasury Management**: Foundation funds for ecosystem growth

### Network Immune System
- **Automated Defense**: ML-driven threat response
- **Geographic Intelligence**: Region-based security analysis
- **Predictive Protection**: Proactive threat prevention
- **Federated Security**: Network-wide defense coordination

## 📄 License

This project serves as the intelligent bootstrap infrastructure for the PiSecure network, providing advanced peer discovery, threat detection, and DEX coordination capabilities.

---

**🚀 Ready to join the PiSecure network? Run the installation script on your Raspberry Pi 5 and start contributing to the network's intelligence and security!**
</content>