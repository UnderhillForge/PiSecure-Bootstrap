# PiSecure Bootstrap Node

An intelligent, ML-powered bootstrap node for the PiSecure P2P network with advanced threat detection, DEX coordination, and real-time network intelligence.

## 🚀 Current Status

**✅ Successfully Deployed on Railway**
- Domain: `bootstrap.pisecure.org`
- Railway Service: Active and running
- Builder: Metal (optimized for performance)

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

### Node Management
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/nodes/register` | POST | PiSecure node registration |
| `/api/v1/nodes/status` | POST | Node status updates |
| `/api/v1/nodes/list` | GET | Registered nodes directory |

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
```

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