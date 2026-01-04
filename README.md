# PiSecure Bootstrap Node

A lightweight Flask-based bootstrap node for the PiSecure P2P network, deployed on Railway.

## 🚀 Current Status

**✅ Successfully Deployed on Railway**
- Domain: `bootstrap.pisecure.org`
- Railway Service: Active and running
- Builder: Metal (optimized for performance)

## 📋 Features

- **Peer Discovery**: Provides initial peer lists for new nodes joining the network
- **Node Registration**: Allows nodes to register themselves for enhanced discovery
- **Network Statistics**: Public dashboard showing network health and metrics
- **Health Monitoring**: Multiple health check endpoints for Railway monitoring
- **DNS Testing**: Hello World page to verify domain routing

## 🔗 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Root health check (Railway monitoring) |
| `/health` | GET | Health check endpoint |
| `/api/v1/health` | GET | API health check with details |
| `/api/v1/bootstrap/peers` | GET | Get initial peer list |
| `/api/v1/network/stats` | GET | Network statistics and health |
| `/api/v1/nodes/register` | POST | Register a new node |
| `/api/v1/nodes/heartbeat` | POST | Send node heartbeat |
| `/hello` | GET | Hello World page for DNS testing |
| `/api/v1/docs` | GET | API documentation |

## 🛠️ Development

### Prerequisites
- Python 3.11+
- Flask
- Railway account (for deployment)

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
python bootstrap/server.py
```

### Railway Deployment
- Uses Railway Metal builder for optimal performance
- Automatically binds to port 8080 (Railway Metal requirement)
- Health checks configured for `/health` endpoint
- Domain configured: `bootstrap.pisecure.org`

## 🔧 Configuration

### Environment Variables
- `FLASK_ENV`: Set to `production` on Railway
- `RATE_LIMIT`: API rate limiting (default: 100/minute)
- `BOOTSTRAP_PEERS`: Initial peer list configuration

### Railway Configuration
- **Builder**: Metal (for performance)
- **Start Command**: `python bootstrap/server.py`
- **Health Check**: `/health`
- **Port**: 8080 (automatic)

## 📊 Monitoring

The bootstrap node provides comprehensive monitoring:
- Railway health checks every 30 seconds
- Real-time network statistics
- Node registration tracking
- Peer discovery metrics

## 🤝 Contributing

This bootstrap node serves as the entry point for the PiSecure network. New nodes connect here first to discover other peers in the network.

## 📄 License

[License information here]