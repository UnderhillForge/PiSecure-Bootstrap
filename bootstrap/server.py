#!/usr/bin/env python3
"""
PiSecure Bootstrap Node Server with Live Network Statistics
"""

import logging
import time
import hashlib
import ipaddress
import json
from collections import deque, defaultdict
from flask import Flask, jsonify, request
from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
DATABASE_URL = "sqlite:///pisecure_bootstrap.db"
engine = create_engine(DATABASE_URL, echo=False)
Base = declarative_base()
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

# Create minimal Flask app
app = Flask(__name__)

# Database Models (matching API specification)
class Node(Base):
    __tablename__ = 'nodes'

    id = Column(Integer, primary_key=True)
    node_id = Column(String(64), unique=True, nullable=False, index=True)
    address = Column(String(45), nullable=False)
    port = Column(Integer, nullable=False)
    capabilities = Column(Text, default='[]')
    hashrate = Column(Float, default=0.0)
    location = Column(String(50), default='unknown')
    country_code = Column(String(2))
    region = Column(String(50))
    city = Column(String(50))
    latitude = Column(Float)
    longitude = Column(Float)
    is_mining = Column(Boolean, default=False)
    registered_at = Column(Float, default=lambda: time.time())
    last_seen = Column(Float, default=lambda: time.time())
    first_seen = Column(Float, default=lambda: time.time())
    version = Column(String(20), default='unknown')
    blocks_mined = Column(Integer, default=0)
    uptime_percentage = Column(Float, default=0.0)
    total_connections = Column(Integer, default=0)

    def to_dict(self):
        return {
            'node_id': self.node_id,
            'address': self.address,
            'port': self.port,
            'capabilities': json.loads(self.capabilities) if self.capabilities else [],
            'hashrate': self.hashrate,
            'location': self.location,
            'country_code': self.country_code,
            'region': self.region,
            'city': self.city,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'is_mining': self.is_mining,
            'registered_at': self.registered_at,
            'last_seen': self.last_seen,
            'first_seen': self.first_seen,
            'version': self.version,
            'blocks_mined': self.blocks_mined,
            'uptime_percentage': self.uptime_percentage,
            'total_connections': self.total_connections
        }

class GeoCache(Base):
    __tablename__ = "geo_cache"

    ip_address = Column(String, primary_key=True, index=True)
    country_code = Column(String)
    region = Column(String)
    city = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    cached_at = Column(Float)

class NetworkStats(Base):
    __tablename__ = "network_stats"

    timestamp = Column(Float, primary_key=True)
    active_nodes = Column(Integer)
    total_hashrate = Column(Float)
    blocks_per_hour = Column(Float)
    health_score = Column(Float)

# Create database tables
Base.metadata.create_all(bind=engine)

# Core Service Classes

class NodeTracker:
    def __init__(self):
        self.nodes = {}
        self.active_connections = set()

    def register_node(self, node_data: dict):
        node_id = node_data['node_id']
        current_time = time.time()

        self.nodes[node_id] = {
            'node_id': node_id,
            'address': node_data['address'],
            'port': node_data['port'],
            'capabilities': node_data.get('capabilities', []),
            'hashrate': node_data.get('hashrate', 0),
            'location': self._geolocate_ip(node_data['address']),
            'is_mining': node_data.get('is_mining', False),
            'registered_at': current_time,
            'last_seen': current_time,
            'first_seen': node_data.get('first_seen', current_time),
            'version': node_data.get('version', 'unknown'),
            'uptime_percentage': self._calculate_uptime(node_id)
        }

        # Save to database
        db = SessionLocal()
        try:
            node_data = self.nodes[node_id].copy()
            node_data['capabilities'] = json.dumps(node_data['capabilities'])  # Convert list to JSON string
            db_node = Node(**node_data)
            db.merge(db_node)
            db.commit()
        except Exception as e:
            logger.error(f"Failed to save node to database: {e}")
            db.rollback()
        finally:
            db.close()

    def update_heartbeat(self, node_id: str, status_data: dict):
        if node_id in self.nodes:
            current_time = time.time()
            self.nodes[node_id].update({
                'last_seen': current_time,
                'hashrate': status_data.get('hashrate', self.nodes[node_id]['hashrate']),
                'is_mining': status_data.get('is_mining', self.nodes[node_id]['is_mining']),
                'blocks_mined': status_data.get('blocks_mined', 0)
            })

            # Update database
            db = SessionLocal()
            try:
                db.query(Node).filter(Node.node_id == node_id).update({
                    'last_seen': current_time,
                    'hashrate': self.nodes[node_id]['hashrate'],
                    'is_mining': self.nodes[node_id]['is_mining'],
                    'blocks_mined': self.nodes[node_id]['blocks_mined']
                })
                db.commit()
            except Exception as e:
                logger.error(f"Failed to update node heartbeat in database: {e}")
                db.rollback()
            finally:
                db.close()

    def _geolocate_ip(self, ip_address: str) -> str:
        if geo_locator:
            return geo_locator.geolocate_ip(ip_address)
        return 'unknown'

    def _calculate_uptime(self, node_id: str) -> float:
        if node_id not in self.nodes:
            return 0.0

        node = self.nodes[node_id]
        total_time = time.time() - node['first_seen']
        if total_time <= 0:
            return 0.0

        # Simple uptime calculation (could be more sophisticated)
        time_since_last_seen = time.time() - node['last_seen']
        if time_since_last_seen > 300:  # 5 minutes offline = 0 uptime
            return 0.0

        return min(100.0, (1 - (time_since_last_seen / total_time)) * 100)

class MiningStatsAggregator:
    def __init__(self, node_tracker: NodeTracker):
        self.node_tracker = node_tracker
        self.block_history = deque(maxlen=100)
        self.hashrate_history = deque(maxlen=60)

    def get_mining_stats(self) -> dict:
        active_miners = 0
        total_hashrate = 0.0
        mining_nodes = []

        for node_id, node_data in self.node_tracker.nodes.items():
            if node_data.get('is_mining') and self._is_node_active(node_id):
                active_miners += 1
                total_hashrate += node_data.get('hashrate', 0)

                mining_nodes.append({
                    'node_id': node_id,
                    'hashrate': node_data.get('hashrate', 0),
                    'location': node_data.get('location', 'unknown'),
                    'uptime': node_data.get('uptime_percentage', 0)
                })

        # Sort by hashrate for top miners
        mining_nodes.sort(key=lambda x: x['hashrate'], reverse=True)
        mining_nodes = mining_nodes[:10]  # Top 10 miners

        return {
            'total_miners': len(mining_nodes),
            'active_miners': active_miners,
            'idle_miners': len(mining_nodes) - active_miners,
            'total_mining_hashrate': total_hashrate,
            'blocks_last_hour': self._calculate_blocks_last_hour(),
            'avg_blocks_per_hour': self._calculate_avg_blocks_per_hour(),
            'mining_nodes': mining_nodes
        }

    def _is_node_active(self, node_id: str) -> bool:
        if node_id not in self.node_tracker.nodes:
            return False

        time_since_last_seen = time.time() - self.node_tracker.nodes[node_id]['last_seen']
        return time_since_last_seen < 300  # 5 minutes

    def _calculate_blocks_last_hour(self) -> int:
        # Mock implementation - would track actual blocks
        return 12

    def _calculate_avg_blocks_per_hour(self) -> float:
        # Mock implementation - would calculate from history
        return 11.8

class GeoLocator:
    def __init__(self, api_key: str = None):
        self.cache = {}
        self.api_key = api_key

    def geolocate_ip(self, ip_address: str) -> str:
        # Check cache first
        if ip_address in self.cache:
            return self.cache[ip_address]

        try:
            # Use IP-API (free tier)
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            data = response.json()

            if data['status'] == 'success':
                location = f"{data['countryCode'].lower()}-{data['regionName'].lower().replace(' ', '-')}"
                self.cache[ip_address] = location

                # Save to database cache
                db = SessionLocal()
                try:
                    geo_entry = GeoCache(
                        ip_address=ip_address,
                        country_code=data['countryCode'],
                        region=data['regionName'],
                        city=data['city'],
                        latitude=data.get('lat', 0),
                        longitude=data.get('lon', 0),
                        cached_at=time.time()
                    )
                    db.merge(geo_entry)
                    db.commit()
                except Exception as e:
                    logger.error(f"Failed to save geo data to database: {e}")
                    db.rollback()
                finally:
                    db.close()

                return location
        except Exception as e:
            logger.warning(f"Geolocation failed for {ip_address}: {e}")

        return 'unknown'

class PeerDiscoveryService:
    def __init__(self, node_tracker: NodeTracker):
        self.node_tracker = node_tracker
        self.verified_peers_cache = {}
        self.cache_timeout = 300  # 5 minutes

    def get_bootstrap_peers(self) -> list:
        current_time = time.time()

        # Check cache
        if (self.verified_peers_cache and
            current_time - self.verified_peers_cache.get('timestamp', 0) < self.cache_timeout):
            return self.verified_peers_cache['peers']

        verified_peers = []

        # Add active registered nodes with p2p_sync capability
        for node_id, node_data in self.node_tracker.nodes.items():
            if (self._is_node_active(node_id) and
                'p2p_sync' in node_data.get('capabilities', [])):
                verified_peers.append(self._format_registered_peer(node_data))

        # Sort by reliability and limit
        verified_peers.sort(key=lambda x: x.get('reliability_score', 0), reverse=True)
        verified_peers = verified_peers[:50]  # Limit for performance

        # Cache result
        self.verified_peers_cache = {
            'peers': verified_peers,
            'timestamp': current_time
        }

        return verified_peers

    def _is_node_active(self, node_id: str) -> bool:
        if node_id not in self.node_tracker.nodes:
            return False

        time_since_last_seen = time.time() - self.node_tracker.nodes[node_id]['last_seen']
        return time_since_last_seen < 300  # 5 minutes

    def _format_registered_peer(self, node_data: dict) -> dict:
        return {
            'node_id': node_data['node_id'],
            'address': node_data['address'],
            'port': node_data['port'],
            'capabilities': node_data.get('capabilities', []),
            'last_seen': node_data.get('last_seen', time.time()),
            'reliability_score': self._calculate_peer_reliability(node_data)
        }

    def _calculate_peer_reliability(self, node_data: dict) -> float:
        # Simple reliability score based on uptime and recent activity
        uptime = node_data.get('uptime_percentage', 0)
        time_since_seen = time.time() - node_data.get('last_seen', 0)
        recency_score = max(0, 1 - (time_since_seen / 3600))  # 1 hour window

        return (uptime / 100) * 0.7 + recency_score * 0.3

# Initialize global service instances
node_tracker = NodeTracker()
mining_aggregator = MiningStatsAggregator(node_tracker)
geo_locator = GeoLocator()
peer_discovery = PeerDiscoveryService(node_tracker)

@app.route('/', methods=['GET'])
def root_health():
    logger.info("Root health check called")
    return jsonify({'status': 'healthy', 'service': 'bootstrap'})

@app.route('/health', methods=['GET'])
def health():
    logger.info("Health check called")
    return jsonify({
        "status": "healthy",
        "timestamp": time.time(),
        "uptime": int(time.time() - time.time()),  # Would track actual server start time
        "version": "1.0.0",
        "service": "bootstrap"
    })

@app.route('/api/v1/health', methods=['GET'])
def api_health():
    logger.info("API health check called")
    return jsonify({
        'status': 'healthy',
        'service': 'bootstrap',
        'version': '1.0.0'
    })

@app.route('/api/v1/network/stats', methods=['GET'])
def network_stats():
    """Comprehensive network statistics endpoint"""
    logger.info("Network stats endpoint called")

    # Get data from service classes
    mining_stats = mining_aggregator.get_mining_stats()

    # Calculate network health metrics
    active_nodes = sum(1 for node in node_tracker.nodes.values()
                      if time.time() - node.get('last_seen', 0) < 300)
    total_registered = len(node_tracker.nodes)
    participation_score = (active_nodes / max(total_registered, 1)) * 100
    health_score = min(100, participation_score * 0.8 + 20)  # Basic health calculation

    # Geographic distribution (simplified for now)
    geo_dist = defaultdict(int)
    for node in node_tracker.nodes.values():
        location = node.get('location', 'unknown')
        geo_dist[location] += 1

    # Known peers count
    known_peers = len(peer_discovery.get_bootstrap_peers())

    network_data = {
        'network_health': {
            'active_nodes': active_nodes,
            'total_registered_nodes': total_registered,
            'connected_peers': len(node_tracker.active_connections),
            'estimated_hashrate': mining_stats['total_mining_hashrate'],
            'participation_score': round(participation_score, 2),
            'health_score': round(health_score, 1),
            'active_miners': mining_stats['active_miners'],
            'total_known_peers': known_peers,
            'uptime': int(time.time() - time.time())  # Would track server uptime
        },
        'mining_stats': {
            'active_miners': mining_stats['active_miners'],
            'total_mining_hashrate': mining_stats['total_mining_hashrate'],
            'blocks_last_hour': mining_stats['blocks_last_hour'],
            'avg_blocks_per_hour': mining_stats['avg_blocks_per_hour'],
            'mining_nodes': mining_stats['mining_nodes']
        },
        'geographic_distribution': {
            'total_locations': len(geo_dist),
            'top_locations': dict(sorted(geo_dist.items(), key=lambda x: x[1], reverse=True)[:6]),
            'distribution': dict(geo_dist)
        },
        'protocol_info': {
            'version': '1.0',
            'features': ['p2p_sync', 'mining_teams', 'hardware_verification'],
            'consensus': 'proof_of_work'
        },
        'last_updated': time.time()
    }

    return jsonify(network_data)

@app.route('/api/v1/nodes/register', methods=['POST'])
def register_node():
    """Register a new node for enhanced discovery"""
    logger.info("Node registration endpoint called")

    try:
        node_data = request.get_json()
        if not node_data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate required fields
        required_fields = ['node_id', 'address', 'port']
        for field in required_fields:
            if field not in node_data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Register the node
        node_tracker.register_node(node_data)

        # Get bootstrap peers count
        bootstrap_peers_count = len(peer_discovery.get_bootstrap_peers())

        return jsonify({
            'success': True,
            'node_id': node_data['node_id'],
            'registered_at': time.time(),
            'location': node_data.get('location', 'unknown'),
            'bootstrap_peers': bootstrap_peers_count
        })

    except Exception as e:
        logger.error(f"Node registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/v1/nodes/heartbeat', methods=['POST'])
def node_heartbeat():
    """Update node status and statistics"""
    logger.info("Node heartbeat endpoint called")

    try:
        data = request.get_json()
        if not data or 'node_id' not in data:
            return jsonify({'error': 'Node ID required'}), 400

        node_id = data['node_id']
        status_data = data.get('status', {})

        # Update heartbeat
        node_tracker.update_heartbeat(node_id, status_data)

        return jsonify({
            'status': 'updated',
            'node_id': node_id,
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"Heartbeat error: {e}")
        return jsonify({'error': 'Heartbeat update failed'}), 500

@app.route('/api/v1/bootstrap/peers', methods=['GET'])
def bootstrap_peers():
    """Provide initial peer list for new nodes"""
    logger.info("Bootstrap peers endpoint called")

    try:
        peers = peer_discovery.get_bootstrap_peers()
        current_time = time.time()

        # Count active nodes
        active_nodes = sum(1 for node in node_tracker.nodes.values()
                          if time.time() - node.get('last_seen', 0) < 300)

        response = {
            "peers": peers,
            "bootstrap_node": {
                "host": "bootstrap.pisecure.org",
                "port": 3142,
                "node_id": "bootstrap_xyz",
                "capabilities": ["bootstrap", "api", "p2p_sync"]
            },
            "network_info": {
                "total_nodes": len(node_tracker.nodes),
                "active_nodes": active_nodes,
                "protocol_version": "1.0",
                "features": ["p2p_sync", "mining_teams", "hardware_verification"]
            },
            "last_updated": current_time,
            "ttl": 300
        }

        return jsonify(response)

    except Exception as e:
        logger.error(f"Bootstrap peers error: {e}")
        return jsonify({'error': 'Failed to retrieve peers'}), 500

@app.route('/blockchain/info', methods=['GET'])
def blockchain_info():
    """Get comprehensive blockchain information"""
    logger.info("Blockchain info endpoint called")

    # Mock blockchain data - would connect to actual blockchain
    response = {
        "blocks": 1250,
        "pending_transactions": 15,
        "difficulty": 4.0,
        "is_valid": True,
        "network_health": {
            "active_nodes": len(node_tracker.nodes),
            "sync_status": "healthy",
            "avg_block_time": 600.0,
            "forks_detected": 0
        },
        "latest_block": {
            "index": 1249,
            "hash": "abc123def45678901234567890abcdef1234567890abcdef1234567890abcdef",
            "timestamp": time.time() - 120,
            "transactions": 3,
            "miner": "miner-node-001"
        }
    }

    return jsonify(response)

@app.route('/mining/status', methods=['GET'])
def mining_status():
    """Get current mining status"""
    logger.info("Mining status endpoint called")

    mining_stats = mining_aggregator.get_mining_stats()

    response = {
        "is_mining": mining_stats['active_miners'] > 0,
        "blocks_mined": sum(node.get('blocks_mined', 0) for node in node_tracker.nodes.values()),
        "current_difficulty": 4.0,
        "network_hashrate": mining_stats['total_mining_hashrate'],
        "miner_hashrate": mining_stats['total_mining_hashrate'] / max(mining_stats['active_miners'], 1),
        "shares_submitted": 1250,  # Mock data
        "efficiency": 0.85,  # Mock data
        "temperature": 45.2,  # Mock data
        "power_consumption": 15.5,  # Mock data
        "uptime": int(time.time() - time.time()),  # Mock data
        "last_block_time": time.time() - 600,  # Mock data
        "next_block_estimate": 600
    }

    return jsonify(response)

@app.route('/network/status', methods=['GET'])
def network_status():
    """Get network status"""
    logger.info("Network status endpoint called")

    active_nodes = sum(1 for node in node_tracker.nodes.values()
                      if time.time() - node.get('last_seen', 0) < 300)

    response = {
        "connected_peers": active_nodes,
        "known_peers": len(node_tracker.nodes),
        "node_id": "bootstrap-main",
        "listening_port": 3142,
        "network_type": "mainnet",
        "sync_status": "synced",
        "last_sync_time": time.time()
    }

    return jsonify(response)

@app.route('/trust', methods=['POST'])
def create_trust():
    """Create developer trust fund"""
    logger.info("Create trust endpoint called")

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate required fields
        required_fields = ['developer_address', 'trust_type']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Mock trust creation - would integrate with actual trust system
        trust_input = f"{data['developer_address']}_{time.time()}"
        trust_id = f"trust_{hashlib.sha256(trust_input.encode()).hexdigest()[:16]}"

        response = {
            'success': True,
            'trust_id': trust_id,
            'status': {
                'balance': data.get('initial_funding', 0.0),
                'trust_type': data['trust_type'],
                'subscribers': 0,
                'monthly_revenue': 0.0
            }
        }

        return jsonify(response)

    except Exception as e:
        logger.error(f"Create trust error: {e}")
        return jsonify({'error': 'Failed to create trust'}), 500

@app.route('/trust/<trust_id>', methods=['GET'])
def get_trust(trust_id):
    """Get trust fund status"""
    logger.info(f"Get trust endpoint called for {trust_id}")

    # Mock trust data - would query actual trust system
    response = {
        'trust_id': trust_id,
        'developer_address': 'mock_developer_wallet',
        'trust_type': 'public',
        'balance': 150.0,
        'total_funding': 250.0,
        'subscribers': 15,
        'monthly_revenue': 45.0,
        'plans': [
            {
                'plan_id': 'basic_plan',
                'name': 'Basic Access',
                'price': 5.0,
                'subscribers': 10
            }
        ],
        'created_at': time.time() - 86400  # 1 day ago
    }

    return jsonify(response)

@app.route('/names/check/<name>', methods=['GET'])
def check_name(name):
    """Check if PiNS name is available"""
    logger.info(f"Check name endpoint called for {name}")

    # Mock name availability check - would query actual PiNS system
    response = {
        'name': name,
        'available': True,  # Mock: assume available
        'registration_fee': 5.0,
        'estimated_confirmation': 600
    }

    return jsonify(response)

@app.route('/names/<name>', methods=['GET'])
def resolve_name(name):
    """Resolve PiNS name to address"""
    logger.info(f"Resolve name endpoint called for {name}")

    # Mock name resolution - would query actual PiNS system
    response = {
        'name': name,
        'address': 'mock_pisecure_wallet_address',
        'registered_at': time.time() - 86400,
        'block_index': 1200,
        'tx_hash': 'tx123def45678901234567890abcdef1234567890abcdef1234567890abcdef',
        'expires_at': time.time() + 31536000  # 1 year from now
    }

    return jsonify(response)

@app.route('/names/register', methods=['POST'])
def register_name():
    """Register new PiNS name"""
    logger.info("Register name endpoint called")

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate required fields
        required_fields = ['name', 'wallet_address']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Mock name registration - would submit to actual PiNS system
        tx_input = f"{data['name']}_{data['wallet_address']}_{time.time()}"
        tx_hash = f"tx_{hashlib.sha256(tx_input.encode()).hexdigest()}"

        response = {
            'success': True,
            'name': data['name'],
            'address': data['wallet_address'],
            'transaction_hash': tx_hash,
            'fee_deducted': 5.0,
            'expires_at': time.time() + (data.get('years', 1) * 31536000),
            'status': 'pending_mining'
        }

        return jsonify(response)

    except Exception as e:
        logger.error(f"Register name error: {e}")
        return jsonify({'error': 'Failed to register name'}), 500

@app.route('/transaction', methods=['POST'])
def submit_transaction():
    """Submit new transaction to network"""
    logger.info("Submit transaction endpoint called")

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No transaction data provided'}), 400

        # Mock transaction submission - would validate and broadcast to network
        tx_input = f"{data.get('type', 'transfer')}_{time.time()}"
        tx_hash = f"tx_{hashlib.sha256(tx_input.encode()).hexdigest()}"

        response = {
            'success': True,
            'transaction_hash': tx_hash,
            'status': 'submitted',
            'estimated_confirmation': 600
        }

        return jsonify(response)

    except Exception as e:
        logger.error(f"Submit transaction error: {e}")
        return jsonify({'error': 'Failed to submit transaction'}), 500

@app.route('/nodes', methods=['GET'])
def nodes():
    """Legacy /nodes endpoint - now returns formatted network stats"""
    logger.info("Legacy nodes endpoint called")

    # Get current network statistics
    mining_stats = mining_aggregator.get_mining_stats()
    active_nodes = sum(1 for node in node_tracker.nodes.values()
                      if time.time() - node.get('last_seen', 0) < 300)

    # Build comprehensive response
    network_stats = {
        'network_overview': {
            'total_nodes': len(node_tracker.nodes),
            'active_nodes': active_nodes,
            'total_connections': len(node_tracker.active_connections),
            'network_hashrate': f"{mining_stats['total_mining_hashrate']:.1f} MH/s",
            'difficulty': '1,234,567,890',  # Mock for now
            'block_height': 456789,  # Mock for now
            'avg_block_time': '12.5 seconds',
            'network_status': 'healthy' if active_nodes > 0 else 'initializing'
        },
        'bootstrap_nodes': [
            {
                'id': 'bootstrap-primary',
                'address': 'bootstrap.pisecure.org:3142',
                'status': 'active',
                'uptime': '99.97%',
                'region': 'US-East',
                'connections': len(peer_discovery.get_bootstrap_peers()),
                'version': '1.0.0'
            }
        ],
        'mining_nodes': mining_stats,
        'network_health': {
            'status': 'excellent' if active_nodes > 0 else 'initializing',
            'latency_avg': '45ms',
            'packet_loss': '0.01%',
            'sync_status': 'fully_synced',
            'fork_risk': 'low',
            'last_block_time': '8 seconds ago',
            'mempool_size': 234,
            'pending_transactions': 1247
        },
        'recent_blocks': [
            {
                'height': 456789,
                'hash': 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef',
                'miner': 'unknown',
                'timestamp': '2026-01-04T12:01:30Z',
                'transactions': 45,
                'size': '1.2 MB',
                'reward': '50 PISC'
            }
        ],
        'protocol_info': {
            'version': '1.0.0',
            'network_id': 'pisecure-mainnet',
            'consensus': 'PoW + PoS hybrid',
            'block_time_target': '12 seconds',
            'max_block_size': '4 MB',
            'total_supply': '21,000,000 PISC',
            'circulating_supply': '12,456,789 PISC'
        },
        'geographic_distribution': dict(defaultdict(int, {
            loc: count for loc, count in [
                (node.get('location', 'unknown'), 1)
                for node in node_tracker.nodes.values()
            ]
        })),
        'last_updated': time.time(),
        'api_version': '1.0'
    }

    return jsonify(network_stats)

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('FLASK_ENV') == 'development'

    logger.info(f"Starting Flask app on port={port}, debug={debug}")
    app.run(host='0.0.0.0', port=port, debug=debug)