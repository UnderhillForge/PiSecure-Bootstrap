# PiSecure Bootstrap Node

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template?template=https://github.com/UnderhillForge/PiSecure-Bootstrap)

A lightweight bootstrap node for the PiSecure decentralized blockchain network. Provides essential P2P discovery services for new nodes joining the network.

## 🚀 Quick Deploy

### Railway (Recommended)
1. Click the "Deploy on Railway" button above
2. Connect your GitHub account
3. Deploy automatically
4. Add custom domain (optional)

### Docker
```bash
docker run -p 3142:3142 ghcr.io/underhillforge/pisecure-bootstrap:latest
```

### Manual
```bash
git clone https://github.com/UnderhillForge/PiSecure-Bootstrap.git
cd PiSecure-Bootstrap
pip install -r requirements.txt
python bootstrap/server.py
```

## 📋 Features

- **Peer Discovery**: Serve initial peer lists for new nodes
- **Network Statistics**: Public network health and metrics
- **Node Registration**: Allow nodes to register for enhanced discovery
- **Heartbeat Monitoring**: Track active network participants
- **API Documentation**: Auto-generated OpenAPI documentation

## 🌐 API Endpoints

### Bootstrap
- `GET /api/v1/bootstrap/peers` - Get initial peer list
- `GET /api/v1/network/stats` - Network statistics and health

### Node Management
- `POST /api/v1/nodes/register` - Register node for discovery
- `POST /api/v1/nodes/heartbeat` - Send node heartbeat

### System
- `GET /api/v1/health` - Health check
- `GET /api/v1/docs` - API documentation

## ⚙️ Configuration

Environment variables:
- `BOOTSTRAP_PEERS` - Comma-separated list of known bootstrap nodes
- `RATE_LIMIT` - API rate limit (default: "100 per minute")
- `FLASK_ENV` - Flask environment (production/development)

## 🏗️ Architecture

```
PiSecure-Bootstrap/
├── bootstrap/          # Core bootstrap code
│   ├── server.py      # Flask API server
│   ├── config.py      # Configuration management
│   └── utils.py       # Helper utilities
├── tests/             # Test suite
├── Dockerfile         # Container definition
├── railway.json       # Railway deployment config
├── requirements.txt   # Python dependencies
└── README.md          # This file
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## 📄 License

MIT License - see [PiSecure main repository](https://github.com/UnderhillForge/PiSecure) for details.

## 🔗 Links

- [PiSecure Main Repository](https://github.com/UnderhillForge/PiSecure)
- [Documentation](https://docs.pisecure.net)
- [Community](https://discord.gg/pisecure)