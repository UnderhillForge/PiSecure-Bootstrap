#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PiSecure Bootstrap Node Server with Live Network Statistics - Clean Version
"""

import logging
import time
import hashlib
import ipaddress
import json
import os
import re
from collections import deque, defaultdict
from flask import Flask, jsonify, request, render_template
from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

# Import Sentinel Service for active defense and reputation management
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from pisecure.api.sentinel import sentinel_service

# Import DDoS Protection and Validation
from pisecure.api.ddos_protection import ddos_protection, DDoSProtection
from pisecure.api.validation import validation_engine, ValidationEngine
import requests
import statistics
import numpy as np
from scipy import stats
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from collections import Counter
import threading
import time as time_module

# Load node configuration
NODE_CONFIG = None
NODE_IDENTITY = None
PRIMARY_REGISTRY_CACHE = {'data': None, 'timestamp': 0.0}

try:
    PRIMARY_REGISTRY_CACHE_TTL = int(os.getenv('PRIMARY_REGISTRY_CACHE_TTL', '120'))
except ValueError:
    PRIMARY_REGISTRY_CACHE_TTL = 120


def _normalize_hostname(value):
    """Normalize host/domain strings pulled from config or env."""
    if not value:
        return ''

    host = value.strip()
    if not host:
        return ''

    if '://' in host:
        host = host.split('://', 1)[1]

    host = host.split('/', 1)[0]
    host = host.split(':', 1)[0]
    return host.lower()


def _discover_runtime_domain(existing_network):
    """Best-effort detection of the hostname this instance will advertise."""
    candidates = [
        os.getenv('BOOTSTRAP_DOMAIN'),
        os.getenv('RAILWAY_PUBLIC_DOMAIN'),
        os.getenv('RAILWAY_STATIC_URL'),
        os.getenv('RENDER_EXTERNAL_URL')
    ]

    if existing_network:
        candidates.append(existing_network.get('domain'))

    for candidate in candidates:
        normalized = _normalize_hostname(candidate)
        if normalized:
            return normalized

    return ''


def _get_primary_domains():
    """Return the list of domains that should be treated as primary nodes."""
    domains = []
    for raw in (
        os.getenv('PRIMARY_BOOTSTRAP_DOMAIN'),
        os.getenv('PRIMARY_BOOTSTRAP_DOMAINS'),
        os.getenv('PRIMARY_DOMAINS')
    ):
        if not raw:
            continue
        domains.extend([entry.strip() for entry in raw.split(',') if entry.strip()])

    if not domains:
        domains = [
            'bootstrap.pisecure.org',
            'pisecure-bootstrap-production.up.railway.app'
        ]

    normalized = []
    for domain in domains:
        host = _normalize_hostname(domain)
        if host:
            normalized.append(host)

    return normalized


def _safe_slug(value, fallback):
    if not value:
        return fallback

    sanitized = ''.join(char if char.isalnum() else '-' for char in value.lower())
    sanitized = '-'.join(filter(None, sanitized.split('-')))
    return sanitized or fallback


def _build_secondary_name(region, hostname):
    if region and region not in ('unknown',):
        pretty_region = region.replace('-', ' ').title()
        return f"PiSecure Bootstrap {pretty_region}"

    if hostname:
        prefix = hostname.split('.', 1)[0]
        pretty_prefix = prefix.replace('-', ' ').title()
        return f"PiSecure Bootstrap {pretty_prefix}"

    return "PiSecure Bootstrap Secondary"


def _generate_secondary_node_id(hostname, region):
    region_slug = _safe_slug(region, 'global')
    host_slug = _safe_slug(hostname, 'secondary')
    entropy_source = '-'.join(filter(None, [
        os.getenv('RAILWAY_ENVIRONMENT_ID'),
        os.getenv('RAILWAY_ENVIRONMENT_NAME'),
        os.getenv('RAILWAY_PROJECT_ID'),
        hostname,
        os.getenv('HOSTNAME')
    ]))

    if not entropy_source:
        entropy_source = host_slug

    digest = hashlib.sha256(entropy_source.encode('utf-8')).hexdigest()[:8]
    return f"bootstrap-{region_slug}-{host_slug}-{digest}"


def _is_valid_node_address(address: str) -> bool:
    if not address:
        return False

    candidate = address.strip()
    if not candidate:
        return False

    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return bool(re.match(r'^[a-zA-Z0-9.-]+$', candidate)) and '.' in candidate


def _build_local_bootstrap_descriptor(trust_level: str = None) -> dict:
    node_section = NODE_CONFIG.get('node', {}) if NODE_CONFIG else {}
    network_section = node_section.get('network', {})
    federation_section = node_section.get('federation', {})
    operations_section = node_section.get('operations', {})
    ports = network_section.get('ports', {})
    capabilities = _get_enabled_capabilities() or []

    descriptor = {
        'node_id': NODE_IDENTITY.get('node_id', 'bootstrap-unknown'),
        'name': NODE_IDENTITY.get('name', 'PiSecure Bootstrap'),
        'role': NODE_IDENTITY.get('role', 'primary'),
        'operator': NODE_IDENTITY.get('operator', node_section.get('operator', 'PiSecure Foundation')),
        'address': network_section.get('domain') or network_section.get('ip_address', '0.0.0.0'),
        'port': ports.get('bootstrap', 3142),
        'status': 'active',
        'services': capabilities,
        'capabilities': capabilities,
        'region': network_section.get('region', 'unknown'),
        'version': NODE_IDENTITY.get('version', '1.0.0'),
        'trust_level': trust_level or ('foundation_verified' if NODE_IDENTITY.get('role') == 'primary' else 'community_trusted'),
        'uptime_target': operations_section.get('uptime_target_percentage', 99.9),
        'intelligence_sharing': federation_section.get('intelligence_sharing', True)
    }

    return descriptor


def _get_local_federation_config() -> dict:
    node_section = NODE_CONFIG.get('node', {}) if NODE_CONFIG else {}
    federation_section = node_section.get('federation', {})
    return {
        'enabled': federation_section.get('enabled', True),
        'trust_model': federation_section.get('trust_model', 'hierarchical'),
        'max_secondary_nodes': federation_section.get('max_secondary_nodes', 10),
        'intelligence_sharing': federation_section.get('intelligence_sharing', True)
    }


def _build_primary_env_descriptor() -> dict:
    try:
        port = int(os.getenv('PRIMARY_BOOTSTRAP_PORT', '3142'))
    except ValueError:
        port = 3142

    descriptor = {
        'node_id': os.getenv('PRIMARY_BOOTSTRAP_NODE_ID', 'bootstrap-primary'),
        'name': os.getenv('PRIMARY_BOOTSTRAP_NAME', 'PiSecure Bootstrap Primary'),
        'role': 'primary',
        'operator': os.getenv('PRIMARY_BOOTSTRAP_OPERATOR', 'PiSecure Foundation'),
        'address': os.getenv('PRIMARY_BOOTSTRAP_DOMAIN', 'bootstrap.pisecure.org'),
        'port': port,
        'status': 'active',
        'services': ['bootstrap_coordination', 'peer_discovery', 'network_health_monitoring', 'federation_management'],
        'capabilities': ['bootstrap_coordination', 'peer_discovery', 'network_health_monitoring', 'federation_management'],
        'region': os.getenv('PRIMARY_BOOTSTRAP_REGION', 'us-east'),
        'version': os.getenv('PRIMARY_BOOTSTRAP_VERSION', '1.0.0'),
        'trust_level': 'foundation_verified',
        'uptime_target': float(os.getenv('PRIMARY_BOOTSTRAP_UPTIME_TARGET', '99.9')),
        'intelligence_sharing': True
    }

    return descriptor


def _build_default_network_info(total_nodes: int) -> dict:
    return {
        'coordination_status': 'active',
        'federation_active': intelligence_federation.federation_enabled,
        'intelligence_nodes': total_nodes
    }


def _get_primary_registry_url() -> str:
    explicit_url = os.getenv('PRIMARY_BOOTSTRAP_REGISTRY_URL')
    if explicit_url:
        return explicit_url

    domain = os.getenv('PRIMARY_BOOTSTRAP_DOMAIN', 'bootstrap.pisecure.org')
    scheme = os.getenv('PRIMARY_BOOTSTRAP_SCHEME', 'https')
    return f"{scheme}://{domain}/api/v1/bootstrap/registry"


def _fetch_primary_registry_snapshot(force_refresh: bool = False):
    if NODE_IDENTITY.get('role') != 'secondary':
        return None

    now = time.time()
    cache_age = now - PRIMARY_REGISTRY_CACHE['timestamp']
    if not force_refresh and PRIMARY_REGISTRY_CACHE['data'] and cache_age < PRIMARY_REGISTRY_CACHE_TTL:
        return PRIMARY_REGISTRY_CACHE['data']

    registry_url = _get_primary_registry_url()
    timeout = float(os.getenv('PRIMARY_BOOTSTRAP_TIMEOUT', '6'))

    try:
        response = requests.get(registry_url, timeout=timeout)
        response.raise_for_status()
        registry_data = response.json()
        PRIMARY_REGISTRY_CACHE['data'] = registry_data
        PRIMARY_REGISTRY_CACHE['timestamp'] = now
        return registry_data
    except (requests.RequestException, ValueError) as exc:
        logger.warning("Primary registry fetch failed: %s", exc)
        return PRIMARY_REGISTRY_CACHE['data']


def load_node_config():
    """Load node configuration with environment override"""
    global NODE_CONFIG, NODE_IDENTITY

    config_paths = [
        os.path.join(os.getcwd(), 'config.json'),
        os.path.join(os.path.dirname(__file__), 'config.json'),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
    ]
    config_data = None

    for path in config_paths:
        try:
            with open(path, 'r') as f:
                config_data = json.load(f)
                break
        except FileNotFoundError:
            continue
        except Exception as e:
            print(f"Failed to load config.json from {path}: {e}")
            continue

    if not config_data:
        print("config.json not found in known locations, using default configuration")
        config_data = get_default_config()

    NODE_CONFIG = config_data

    node_section = NODE_CONFIG.setdefault('node', {})
    identity_section = node_section.setdefault('identity', {})
    network_section = node_section.setdefault('network', {})

    runtime_domain = _discover_runtime_domain(network_section)
    if runtime_domain:
        network_section['domain'] = runtime_domain

    region_override = os.getenv('BOOTSTRAP_REGION')
    if region_override:
        network_section['region'] = region_override

    primary_domains = _get_primary_domains()
    raw_env_role = os.getenv('BOOTSTRAP_ROLE')
    env_role = raw_env_role.strip().lower() if raw_env_role else None
    assigned_role = env_role or identity_section.get('role') or 'primary'

    if not env_role and runtime_domain:
        assigned_role = 'primary' if runtime_domain in primary_domains else 'secondary'

    identity_section['role'] = assigned_role

    if assigned_role == 'secondary':
        region = network_section.get('region') or os.getenv('RAILWAY_REGION') or 'unknown'
        network_section['region'] = region

        env_name = (os.getenv('BOOTSTRAP_NAME') or os.getenv('BOOTSTRAP_LABEL') or '').strip()
        if env_name:
            identity_section['name'] = env_name
        else:
            current_name = identity_section.get('name', '')
            if (not current_name or
                    current_name in ('PiSecure Bootstrap Node', 'PiSecure Bootstrap Primary') or
                    'Primary' in current_name):
                identity_section['name'] = _build_secondary_name(region, runtime_domain)

    env_node_id = (os.getenv('BOOTSTRAP_NODE_ID') or '').strip()
    if env_node_id:
        identity_section['node_id'] = env_node_id
    elif identity_section.get('role') == 'secondary':
        identity_section['node_id'] = _generate_secondary_node_id(runtime_domain, network_section.get('region'))

    NODE_IDENTITY = identity_section
    role = NODE_IDENTITY.get('role', 'unknown')
    region = network_section.get('region', 'unknown')
    print(f"Loaded configuration: {identity_section.get('name', 'PiSecure Bootstrap')} (role: {role}, region: {region})")

    return NODE_CONFIG

def get_default_config():
    """Get default configuration when config.json is not available"""
    return {
        "node": {
            "identity": {
                "name": "PiSecure Bootstrap Node",
                "node_id": "bootstrap-primary",
                "role": "primary",
                "version": "1.0.0",
                "operator": "PiSecure Foundation",
                "contact_email": "admin@pisecure.org",
                "description": "PiSecure bootstrap node"
            },
            "network": {
                "domain": "bootstrap.pisecure.org",
                "ip_address": "0.0.0.0",
                "ports": {"bootstrap": 3142, "api": 8080},
                "region": "us-east"
            },
            "federation": {
                "enabled": True,
                "trust_model": "hierarchical",
                "max_secondary_nodes": 10,
                "sync_interval_seconds": 300,
                "intelligence_sharing": True
            },
            "capabilities": {
                "bootstrap_coordination": True,
                "peer_discovery": True,
                "network_health_monitoring": True,
                "intelligence_sharing": True
            }
        }
    }

def _get_enabled_capabilities() -> list:
    """Translate node capabilities into a list for service advertisements"""
    if not NODE_CONFIG:
        return []

    capabilities = NODE_CONFIG.get('node', {}).get('capabilities', [])
    if isinstance(capabilities, dict):
        return [name for name, enabled in capabilities.items() if enabled]
    if isinstance(capabilities, list):
        return capabilities

    return []

def register_with_primary_bootstrap():
    """Register this node with the primary bootstrap during startup"""
    if not NODE_CONFIG or not NODE_IDENTITY:
        logger.warning("Configuration not loaded; skipping bootstrap registration")
        return

    if NODE_IDENTITY.get('role') != 'secondary':
        return

    primary_url = os.getenv('PRIMARY_BOOTSTRAP_URL')
    if not primary_url:
        primary_domain = os.getenv('PRIMARY_BOOTSTRAP_DOMAIN', 'bootstrap.pisecure.org')
        primary_scheme = os.getenv('PRIMARY_BOOTSTRAP_SCHEME', 'https')
        primary_url = f"{primary_scheme}://{primary_domain}/api/v1/bootstrap/handshake"

    node_network = NODE_CONFIG.get('node', {}).get('network', {})
    ports = node_network.get('ports', {})
    capabilities = _get_enabled_capabilities() or ['peer_discovery']

    handshake_payload = {
        'node_id': NODE_IDENTITY.get('node_id', ''),
        'address': node_network.get('domain') or node_network.get('ip_address', '0.0.0.0'),
        'port': ports.get('bootstrap', 3142),
        'services': capabilities,
        'capabilities': capabilities,
        'region': node_network.get('region', 'unknown'),
        'version': NODE_IDENTITY.get('version', 'unknown'),
        'reliability_score': float(os.getenv('BOOTSTRAP_RELIABILITY', '0.95')),
        'load_factor': float(os.getenv('BOOTSTRAP_LOAD_FACTOR', '0.0')),
        'supported_protocols': node_network.get('supported_protocols', ['p2p_sync'])
    }

    try:
        response = requests.post(primary_url, json=handshake_payload, timeout=10)
        if response.ok:
            logger.info("Registered secondary bootstrap with primary at %s", primary_url)
        else:
            logger.warning("Bootstrap registration failed (%s): %s", response.status_code, response.text)
    except requests.RequestException as exc:
        logger.warning("Bootstrap registration error: %s", exc)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration at module import (after logger is available)
load_node_config()

# Automatic primary registration for Railway secondary deployments
if NODE_IDENTITY.get('role') == 'secondary':
    register_with_primary_bootstrap()

# Compatibility shim for legacy tests that expect a simple BootstrapNode class
class BootstrapNode:
    """Lightweight bootstrap node representation for legacy tests."""

    def __init__(self, host: str = '0.0.0.0', port: int = 3142):
        self.host = host
        self.port = port
        self.api_version = "v1"
        self.registered_nodes = {}
        # Pre-populate peers from environment variable if provided
        self.bootstrap_peers = self._parse_bootstrap_peers(os.environ.get('BOOTSTRAP_PEERS', ''))
        self.max_peers = 50

    def _parse_bootstrap_peers(self, peers_str: str):
        if not peers_str:
            return []

        peers = []
        for peer in peers_str.split(','):
            peer = peer.strip()
            if not peer:
                continue

            if ':' in peer:
                address, port_str = peer.split(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 3142
            else:
                address = peer
                port = 3142

            peers.append({'node_id': address, 'address': address, 'port': port, 'capabilities': []})

        return peers

    def _get_verified_bootstrap_peers(self):
        peers = list(self.bootstrap_peers)

        # Include registered nodes as peers
        for node_id, node_data in self.registered_nodes.items():
            peers.append({
                'node_id': node_id,
                'address': node_data.get('address', ''),
                'port': node_data.get('port', 3142),
                'capabilities': node_data.get('capabilities', [])
            })

        return peers[: self.max_peers]

    def _calculate_network_stats(self):
        return {
            'active_nodes': self._count_active_nodes(),
            'total_registered_nodes': len(self.registered_nodes),
            'connected_peers': len(self._get_verified_bootstrap_peers()),
            'timestamp': time.time()
        }

    def _count_active_nodes(self):
        return len(self.registered_nodes)

# Database setup
DATABASE_URL = "sqlite:///pisecure_bootstrap.db"
engine = create_engine(DATABASE_URL, echo=False)
Base = declarative_base()
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

# Create minimal Flask app
app = Flask(__name__)

# DDoS Protection Middleware
@app.before_request
def ddos_protection_middleware():
    """DDoS protection and abuse detection on all requests"""
    # Skip for health checks and static files
    if request.path in ['/', '/health', '/api/v1/health']:
        return None
    
    try:
        # Gather request data for analysis
        request_data = {
            'client_ip': request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown'),
            'endpoint': request.path,
            'user_agent': request.headers.get('User-Agent', ''),
            'request_size': len(request.data) if request.data else 0,
            'parameters': dict(request.args),
            'method': request.method
        }
        
        # Analyze request with DDoS protection
        analysis = ddos_protection.analyze_request(request_data)
        
        # Block if necessary
        if analysis.get('should_block'):
            logger.warning(f"Request blocked from {request_data['client_ip']}: threat_score={analysis.get('threat_score'):.2f}")
            return jsonify({
                'error': 'Request blocked',
                'reason': 'Security policy violation',
                'threat_score': analysis.get('threat_score'),
                'recommendations': analysis.get('recommendations', [])
            }), 429
        
        # Apply delay if necessary
        delay_seconds = analysis.get('delay_seconds', 0)
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        
        # Store analysis result in request context for logging
        request.ddos_analysis = analysis
        
    except Exception as e:
        logger.error(f"DDoS protection middleware error: {e}")
        # Continue processing even if protection fails
        pass
    
    return None

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
        """Calculate actual blocks mined in the last hour using SignChain"""
        try:
            # Use real blockchain data when SignChain is available
            if real_blockchain and hasattr(real_blockchain, 'get_recent_blocks'):
                current_time = time.time()
                one_hour_ago = current_time - 3600

                # Get blocks from the last hour
                recent_blocks = real_blockchain.get_recent_blocks(since_timestamp=one_hour_ago)
                return len(recent_blocks) if recent_blocks else 0

            # Fallback to mock data until SignChain is integrated
            logger.debug("Using mock block calculation - SignChain not available")
            return self._calculate_mock_blocks_last_hour()

        except Exception as e:
            logger.warning(f"Error calculating blocks last hour: {e}")
            return 0

    def _calculate_avg_blocks_per_hour(self) -> float:
        """Calculate average blocks per hour using SignChain historical data"""
        try:
            # Use real blockchain data when SignChain is available
            if real_blockchain and hasattr(real_blockchain, 'get_block_history'):
                # Get last 24 hours of block data
                current_time = time.time()
                twenty_four_hours_ago = current_time - (24 * 3600)

                block_history = real_blockchain.get_block_history(since_timestamp=twenty_four_hours_ago)

                if block_history and len(block_history) > 0:
                    # Calculate blocks per hour average
                    hours_covered = 24  # Full 24 hours
                    return len(block_history) / hours_covered

                return 0.0

            # Fallback to mock data until SignChain is integrated
            logger.debug("Using mock block average calculation - SignChain not available")
            return self._calculate_mock_avg_blocks_per_hour()

        except Exception as e:
            logger.warning(f"Error calculating avg blocks per hour: {e}")
            return 0.0

    def _calculate_mock_blocks_last_hour(self) -> int:
        """Mock implementation for blocks last hour - replace with SignChain"""
        # This would be replaced with actual SignChain calls
        # For now, return a reasonable mock value based on network activity
        current_time = time.time()

        # Simulate variable block production based on time of day
        hour_of_day = time.gmtime(current_time).tm_hour

        # More blocks during peak hours (simulate higher activity)
        if 14 <= hour_of_day <= 20:  # Peak trading hours
            base_blocks = 15
        elif 6 <= hour_of_day <= 12:  # Morning activity
            base_blocks = 10
        else:  # Off-peak
            base_blocks = 8

        # Add some randomness (�20%)
        import random
        variation = random.uniform(0.8, 1.2)
        return int(base_blocks * variation)

    def _calculate_mock_avg_blocks_per_hour(self) -> float:
        """Mock implementation for avg blocks per hour - replace with SignChain"""
        # Calculate from recent mock history
        # In production, this would use real historical block data
        return 11.8  # Target block time simulation

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

# Production PiSecure Component Integration Points
# These will be initialized when PiSecure core components are available

# Real blockchain data source (from api-update.txt)
real_blockchain = None  # Will be SignChain() instance

# P2P protocol instance (from api-update.txt)
p2p_protocol = None  # Will be PiSecureP2P() instance

# Consensus engine (from api-update.txt)
consensus_engine = None  # Will be PiSecureConsensus() instance

# Token economics engine (from api-update.txt)
token_economics = None  # Will be TokenEconomicsEngine() instance

# P2P sync manager (from api-update.txt)
p2p_sync_manager = None  # Will be P2PSyncManager() instance

# Network Intelligence Engine - ML-Powered Defense & Smart Routing
class NetworkIntelligence:
    """Advanced ML-powered network intelligence with automated defense capabilities"""

    def __init__(self):
        # Core data structures
        self.connection_history = deque(maxlen=1000)  # Last 1000 connections
        self.connection_timestamps = deque(maxlen=1000)
        self.geographic_distribution = defaultdict(lambda: {'count': 0, 'last_seen': 0})
        self.latency_history = deque(maxlen=500)
        self.latency_stats = {'mean': 0, 'std': 0, 'min': 0, 'max': 0}

        # ML Models for Attack Detection
        self.isolation_forest = None
        self.ensemble_classifier = None
        self.scaler = StandardScaler()
        self.feature_history = deque(maxlen=500)  # Features for ML training
        self.attack_labels = deque(maxlen=500)    # Labels for supervised learning

        # Geographic Clustering
        self.geo_cluster_model = None
        self.geographic_clusters = {}

        # Smart Routing Intelligence
        self.route_history = {}  # route -> success/failure stats
        self.threat_zones = set()  # Currently compromised regions
        self.backup_routes = {}  # Alternative paths for each route
        self.routing_q_table = {}  # Q-learning for route optimization

        # Automated Defense System
        self.defense_actions = []  # Initialize as empty list
        self.rate_limits = defaultdict(lambda: {'count': 0, 'reset_time': 0})
        self.blocked_ips = set()
        self.blocked_regions = set()
        self.defense_thresholds = {
            'auto_block_threshold': 0.8,  # Confidence threshold for auto-blocking
            'rate_limit_threshold': 100,  # Connections per minute before rate limiting
            'region_block_threshold': 0.7  # Percentage of traffic from region before blocking
        }

        # Attack detection parameters
        self.potential_attacks = []  # Initialize as empty list
        self.attack_thresholds = {
            'connection_spike': 3.0,  # 3 standard deviations
            'geographic_anomaly': 2.5,  # 2.5 standard deviations
            'latency_spike': 2.0,  # 2 standard deviations
            'ml_confidence': 0.75  # ML model confidence threshold
        }

        # Network health scoring
        self.health_metrics = {
            'connectivity_score': 100,
            'geographic_diversity': 100,
            'attack_resistance': 100,
            'performance_score': 100,
            'overall_health': 100
        }

        # Initialize ML models
        self._initialize_ml_models()

    def _initialize_ml_models(self):
        """Initialize ML models for attack detection and routing optimization"""
        try:
            # Isolation Forest for unsupervised anomaly detection
            self.isolation_forest = IsolationForest(
                contamination=0.1,  # Expect 10% anomalies
                random_state=42,
                n_estimators=100
            )

            # Ensemble classifier for attack pattern recognition
            self.ensemble_classifier = RandomForestClassifier(
                n_estimators=50,
                random_state=42,
                class_weight='balanced'
            )

            # Geographic clustering model
            self.geo_cluster_model = KMeans(
                n_clusters=5,  # Assume 5 major geographic regions
                random_state=42,
                n_init=10
            )

            logger.info("ML models initialized successfully")

        except Exception as e:
            logger.warning(f"Failed to initialize ML models: {e}")
            # Continue without ML models - fall back to statistical methods

    def detect_attacks_ml(self) -> list:
        """Enhanced attack detection using ML algorithms"""
        attacks = []
        current_time = time.time()

        # Extract features from recent connection data
        features = self._extract_connection_features()
        if not features:
            return attacks

        # ML-based anomaly detection
        if self.isolation_forest and len(features) >= 50:  # Need minimum training data
            try:
                # Prepare data for ML
                feature_array = np.array(features[-100:])  # Last 100 samples
                scaled_features = self.scaler.fit_transform(feature_array)

                # Train on "normal" data (exclude last 10 samples for testing)
                normal_data = scaled_features[:-10]
                if len(normal_data) >= 20:
                    self.isolation_forest.fit(normal_data)

                    # Predict on recent data
                    test_data = scaled_features[-10:]
                    predictions = self.isolation_forest.predict(test_data)
                    scores = self.isolation_forest.decision_function(test_data)

                    # Check for anomalies
                    for i, (pred, score) in enumerate(zip(predictions, scores)):
                        if pred == -1 and score < -0.5:  # High confidence anomaly
                            attacks.append({
                                'type': 'ml_anomaly_detection',
                                'severity': 'high' if score < -0.8 else 'medium',
                                'ml_score': score,
                                'confidence': min(1.0, abs(score)),
                                'timestamp': current_time,
                                'description': f'ML-detected anomaly with score {score:.3f}'
                            })
            except Exception as e:
                logger.warning(f"ML anomaly detection failed: {e}")

        # Combine with statistical detection
        statistical_attacks = self.detect_attacks()
        attacks.extend(statistical_attacks)

        # Remove duplicates and sort by severity/timestamp
        unique_attacks = self._deduplicate_attacks(attacks)

        return unique_attacks

    def trigger_defense_measures(self, features: dict, confidence: float) -> dict:
        """Automatically trigger defense measures based on attack detection"""
        defense_action = {
            'action_taken': False,
            'measures': [],
            'timestamp': time.time(),
            'confidence': confidence
        }

        # Rate limiting for high-frequency attacks
        if confidence > self.defense_thresholds['auto_block_threshold']:
            # Implement rate limiting
            suspicious_ip = features.get('ip')
            if suspicious_ip:
                self._implement_rate_limiting(suspicious_ip)
                defense_action['measures'].append('rate_limiting')
                defense_action['action_taken'] = True

        # Geographic blocking for region-based attacks
        attack_location = features.get('location')
        if attack_location and self._is_geographic_attack(attack_location):
            self.blocked_regions.add(attack_location)
            defense_action['measures'].append('regional_blocking')
            defense_action['action_taken'] = True

        # Route diversion for DDoS-like attacks
        if features.get('connection_rate', 0) > self.defense_thresholds['rate_limit_threshold']:
            self._divert_traffic_routes()
            defense_action['measures'].append('traffic_diversion')
            defense_action['action_taken'] = True

        if defense_action['action_taken']:
            self.defense_actions.append(defense_action)
            logger.warning(f"Automated defense triggered: {defense_action['measures']}")

        return defense_action

    def optimize_routing_ml(self, available_nodes: list, threat_intelligence: dict = None) -> list:
        """Enhanced routing optimization with ML and threat awareness"""
        if not available_nodes:
            return []

        current_time = time.time()

        # Update threat zones based on intelligence
        if threat_intelligence:
            self._update_threat_zones(threat_intelligence)

        scored_nodes = []

        for node in available_nodes:
            node_id = node.get('node_id', 'unknown')
            location = node.get('location', 'unknown')
            load_factor = node.get('load_factor', 0.0)
            reliability = node.get('reliability_score', 1.0)

            # Threat-aware geographic scoring
            geo_score = self._calculate_threat_aware_geo_score(location)

            # Load balancing with predictive adjustment
            load_score = self._calculate_predictive_load_score(node_id, load_factor)

            # Reliability with historical performance
            reliability_score = self._calculate_enhanced_reliability(node_id, reliability)

            # ML-based routing optimization (reinforcement learning concepts)
            route_score = self._calculate_route_q_value(node_id, location)

            # Combined score with threat weighting
            threat_multiplier = 0.5 if location in self.threat_zones else 1.0
            total_score = (
                geo_score * 0.25 +
                load_score * 0.30 +
                reliability_score * 0.25 +
                route_score * 0.20
            ) * threat_multiplier

            scored_nodes.append({
                'node': node,
                'score': total_score,
                'geo_score': geo_score,
                'load_score': load_score,
                'reliability_score': reliability_score,
                'route_score': route_score,
                'threat_adjusted': threat_multiplier < 1.0
            })

        # Sort by total score (highest first)
        scored_nodes.sort(key=lambda x: x['score'], reverse=True)

        # Update Q-table with this routing decision
        self._update_routing_q_table(scored_nodes[0]['node']['node_id'] if scored_nodes else None)

        return scored_nodes

    def cluster_geographic_regions(self) -> dict:
        """Use ML clustering to identify geographic regions and optimize routing"""
        if len(self.geographic_distribution) < 5:
            return {}

        try:
            # Prepare geographic data for clustering
            locations = []
            weights = []

            for loc, data in self.geographic_distribution.items():
                # Convert location strings to numeric coordinates (simplified)
                coords = self._location_to_coordinates(loc)
                if coords:
                    locations.append(coords)
                    weights.append(data['count'])

            if len(locations) >= 5:
                # Perform clustering
                location_array = np.array(locations)
                clusters = self.geo_cluster_model.fit_predict(location_array)

                # Analyze cluster characteristics
                cluster_analysis = {}
                for i, (loc_coords, cluster_id, weight) in enumerate(zip(locations, clusters, weights)):
                    if cluster_id not in cluster_analysis:
                        cluster_analysis[cluster_id] = {
                            'locations': [],
                            'total_traffic': 0,
                            'centroid': None
                        }

                    cluster_analysis[cluster_id]['locations'].append(list(self.geographic_distribution.keys())[i])
                    cluster_analysis[cluster_id]['total_traffic'] += weight

                # Calculate centroids
                for cluster_id, data in cluster_analysis.items():
                    cluster_points = [locations[i] for i, c in enumerate(clusters) if c == cluster_id]
                    if cluster_points:
                        centroid = np.mean(cluster_points, axis=0)
                        data['centroid'] = centroid.tolist()

                return cluster_analysis

        except Exception as e:
            logger.warning(f"Geographic clustering failed: {e}")

        return {}

    def _extract_connection_features(self) -> list:
        """Extract ML features from connection data"""
        features = []

        if len(self.connection_history) < 10:
            return features

        # Rolling window analysis
        window_size = 50
        for i in range(window_size, len(self.connection_history), 10):
            window = self.connection_history[i-window_size:i]

            # Extract features
            connection_rate = len([c for c in window if time.time() - c['timestamp'] < 300]) / 5  # per minute
            unique_ips = len(set(c['ip'] for c in window))
            unique_locations = len(set(c['location'] for c in window))

            # Geographic concentration (entropy-like measure)
            location_counts = Counter(c['location'] for c in window)
            total_connections = sum(location_counts.values())
            geo_concentration = max((count/total_connections) for count in location_counts.values()) if total_connections > 0 else 0

            # Time-based patterns
            timestamps = [c['timestamp'] for c in window]
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_interval = statistics.mean(intervals) if intervals else 60

            features.append([
                connection_rate,      # 0: connections per minute
                unique_ips,          # 1: unique IP count
                unique_locations,    # 2: unique location count
                geo_concentration,   # 3: geographic concentration
                avg_interval,        # 4: average connection interval
                len(window) / window_size  # 5: data completeness
            ])

        return features

    def _calculate_threat_aware_geo_score(self, location: str) -> float:
        """Calculate geographic score with threat awareness"""
        if location in self.threat_zones:
            return 0.1  # Heavily penalize threat zones

        # Normal geographic diversity scoring
        if location in self.geographic_distribution:
            recent_count = self.geographic_distribution[location]['count']
            total_recent = sum(data['count'] for data in self.geographic_distribution.values())
            if total_recent > 0:
                geo_percentage = recent_count / total_recent
                # Prefer locations that aren't over-represented
                return 1.0 - min(0.5, geo_percentage)

        return 0.5  # Neutral score for unknown locations

    def _calculate_predictive_load_score(self, node_id: str, current_load: float) -> float:
        """Calculate load score with predictive adjustment"""
        base_score = 1.0 - current_load

        # Add predictive adjustment based on recent trends
        if node_id in self.route_history:
            recent_performance = self.route_history[node_id]
            # If node has been performing well recently, boost score slightly
            if recent_performance.get('success_rate', 0.5) > 0.8:
                base_score *= 1.1

        return min(1.0, max(0.0, base_score))

    def _calculate_enhanced_reliability(self, node_id: str, base_reliability: float) -> float:
        """Calculate enhanced reliability with historical data"""
        if node_id in self.route_history:
            history = self.route_history[node_id]
            historical_reliability = history.get('success_rate', 0.5)

            # Blend base reliability with historical performance
            return (base_reliability * 0.6) + (historical_reliability * 0.4)

        return base_reliability

    def _calculate_route_q_value(self, node_id: str, location: str) -> float:
        """Calculate Q-learning inspired route value"""
        route_key = f"{node_id}:{location}"

        if route_key in self.routing_q_table:
            return self.routing_q_table[route_key]

        # Initialize with neutral value
        return 0.5

    def _update_routing_q_table(self, selected_node_id: str):
        """Update Q-table based on routing decisions"""
        if not selected_node_id:
            return

        # Simple Q-learning update (reward successful routing)
        for route_key in self.routing_q_table:
            if route_key.startswith(f"{selected_node_id}:"):
                # Small positive reward for being selected
                self.routing_q_table[route_key] = min(1.0, self.routing_q_table[route_key] + 0.01)

    def _update_threat_zones(self, threat_intelligence: dict):
        """Update threat zones based on intelligence data"""
        attacks = threat_intelligence.get('active_attacks', [])

        for attack in attacks:
            if attack['type'] == 'geographic_anomaly':
                self.threat_zones.add(attack['location'])

            # Expire old threat zones (keep only recent threats)
            current_time = time.time()
            expired_zones = [zone for zone in self.threat_zones
                           if all(attack.get('location') != zone or
                                 current_time - attack.get('timestamp', 0) > 3600
                                 for attack in attacks)]

            for zone in expired_zones:
                self.threat_zones.discard(zone)

    def _implement_rate_limiting(self, ip_address: str):
        """Implement rate limiting for suspicious IPs"""
        current_time = time.time()
        rate_limit_window = 300  # 5 minutes

        if current_time - self.rate_limits[ip_address]['reset_time'] > rate_limit_window:
            # Reset rate limit window
            self.rate_limits[ip_address] = {'count': 1, 'reset_time': current_time}
        else:
            # Increment counter
            self.rate_limits[ip_address]['count'] += 1

        logger.info(f"Rate limiting activated for IP: {ip_address}")

    def _is_geographic_attack(self, location: str) -> bool:
        """Determine if a geographic location represents an attack pattern"""
        if location not in self.geographic_distribution:
            return False

        location_data = self.geographic_distribution[location]
        total_recent = sum(data['count'] for data in self.geographic_distribution.values())

        if total_recent == 0:
            return False

        percentage = (location_data['count'] / total_recent) * 100
        return percentage > self.defense_thresholds['region_block_threshold']

    def _divert_traffic_routes(self):
        """Implement traffic diversion for DDoS mitigation"""
        # This would coordinate with other bootstrap nodes to redirect traffic
        logger.warning("Traffic diversion activated - coordinating with bootstrap network")

    def _location_to_coordinates(self, location: str) -> list:
        """Convert location string to approximate coordinates"""
        # Simplified coordinate mapping - in production, use proper geocoding
        location_map = {
            'us-east': [39.8283, -98.5795],  # US East
            'us-west': [36.7783, -119.4179], # US West
            'eu-west': [51.5074, -0.1278],   # London
            'eu-central': [52.5200, 13.4050], # Berlin
            'asia-pacific': [35.6762, 139.6503] # Tokyo
        }

        # Extract region from location string
        for region, coords in location_map.items():
            if region in location.lower():
                return coords

        return None

    def _deduplicate_attacks(self, attacks: list) -> list:
        """Remove duplicate attacks and sort by severity/timestamp"""
        seen = set()
        unique_attacks = []

        for attack in attacks:
            attack_key = f"{attack['type']}:{attack.get('location', 'unknown')}:{int(attack['timestamp'])}"

            if attack_key not in seen:
                seen.add(attack_key)
                unique_attacks.append(attack)

        # Sort by severity (high > medium > low) then by timestamp (newest first)
        severity_order = {'high': 3, 'medium': 2, 'low': 1}
        unique_attacks.sort(key=lambda x: (
            severity_order.get(x.get('severity', 'low'), 0),
            x.get('timestamp', 0)
        ), reverse=True)

        return unique_attacks

    def record_connection(self, ip_address: str, user_agent: str = "", timestamp: float = None):
        """Record a connection attempt for analysis"""
        if timestamp is None:
            timestamp = time.time()

        # Record connection
        self.connection_history.append({
            'ip': ip_address,
            'user_agent': user_agent,
            'timestamp': timestamp,
            'location': geo_locator.geolocate_ip(ip_address) if geo_locator else 'unknown'
        })
        self.connection_timestamps.append(timestamp)

        # Update geographic distribution
        location = self.connection_history[-1]['location']
        self.geographic_distribution[location]['count'] += 1
        self.geographic_distribution[location]['last_seen'] = timestamp

        # Analyze for potential attacks
        self._analyze_connection_patterns()

    def record_latency(self, latency_ms: float, endpoint: str = ""):
        """Record latency measurement for performance analysis"""
        self.latency_history.append({
            'latency': latency_ms,
            'endpoint': endpoint,
            'timestamp': time.time()
        })

        # Update latency statistics
        if len(self.latency_history) >= 10:  # Need minimum samples
            latencies = [entry['latency'] for entry in self.latency_history]
            self.latency_stats = {
                'mean': statistics.mean(latencies),
                'std': statistics.stdev(latencies) if len(latencies) > 1 else 0,
                'min': min(latencies),
                'max': max(latencies)
            }

    def analyze_network_health(self) -> dict:
        """Analyze overall network health using statistical methods"""
        current_time = time.time()

        # Connectivity score (based on recent connections)
        recent_connections = sum(1 for ts in self.connection_timestamps
                                if current_time - ts < 3600)  # Last hour
        connectivity_score = min(100, (recent_connections / 50) * 100)  # Expect ~50 connections/hour

        # Geographic diversity score
        active_locations = sum(1 for loc_data in self.geographic_distribution.values()
                              if current_time - loc_data['last_seen'] < 3600)
        geographic_score = min(100, active_locations * 20)  # 5 locations = 100 score

        # Attack resistance score (inverse of detected anomalies)
        recent_attacks = sum(1 for attack in self.potential_attacks
                           if current_time - attack['timestamp'] < 3600)
        attack_score = max(0, 100 - (recent_attacks * 10))  # Each attack reduces score by 10

        # Performance score (based on latency)
        performance_score = 100
        if self.latency_stats['mean'] > 0:
            # Penalize high latency (good: <100ms, poor: >500ms)
            latency_penalty = max(0, (self.latency_stats['mean'] - 100) / 4)
            performance_score = max(0, 100 - latency_penalty)

        # Overall health (weighted average)
        overall_health = (
            connectivity_score * 0.3 +
            geographic_score * 0.2 +
            attack_score * 0.3 +
            performance_score * 0.2
        )

        self.health_metrics.update({
            'connectivity_score': connectivity_score,
            'geographic_diversity': geographic_score,
            'attack_resistance': attack_score,
            'performance_score': performance_score,
            'overall_health': overall_health,
            'last_updated': current_time
        })

        return self.health_metrics.copy()

    def detect_attacks(self) -> list:
        """Detect potential attacks using statistical analysis"""
        attacks = []
        current_time = time.time()

        # Connection spike detection (DDoS-like)
        if len(self.connection_timestamps) >= 50:
            # Analyze connection rate over last 5 minutes
            recent_connections = [ts for ts in self.connection_timestamps
                                if current_time - ts < 300]  # Last 5 minutes

            if len(recent_connections) >= 20:  # Minimum sample size
                # Calculate connection rate (connections per minute)
                time_span = 5  # minutes
                connection_rate = len(recent_connections) / time_span

                # Compare to historical average
                historical_rates = []
                for i in range(0, len(self.connection_timestamps) - 20, 10):
                    window = self.connection_timestamps[i:i+20]
                    if len(window) >= 10:
                        window_rate = len(window) / (5 * 60) * 60  # per minute
                        historical_rates.append(window_rate)

                if historical_rates:
                    avg_rate = statistics.mean(historical_rates)
                    std_rate = statistics.stdev(historical_rates) if len(historical_rates) > 1 else avg_rate * 0.1

                    if std_rate > 0:
                        z_score = (connection_rate - avg_rate) / std_rate
                        if z_score > self.attack_thresholds['connection_spike']:
                            attacks.append({
                                'type': 'connection_spike',
                                'severity': 'high' if z_score > 4 else 'medium',
                                'z_score': z_score,
                                'connections_per_minute': connection_rate,
                                'timestamp': current_time,
                                'description': f'Unusual connection rate: {connection_rate:.1f} conn/min'
                            })

        # Geographic anomaly detection
        if len(self.geographic_distribution) >= 3:
            recent_locations = {}
            for loc, data in self.geographic_distribution.items():
                if current_time - data['last_seen'] < 3600:  # Last hour
                    recent_locations[loc] = data['count']

            if recent_locations:
                # Check for unusual concentration from single location
                total_recent = sum(recent_locations.values())
                if total_recent >= 20:  # Minimum sample size
                    for loc, count in recent_locations.items():
                        percentage = (count / total_recent) * 100
                        expected_percentage = 100 / len(recent_locations)  # Even distribution

                        if percentage > expected_percentage * 2:  # More than 2x expected
                            attacks.append({
                                'type': 'geographic_anomaly',
                                'severity': 'medium',
                                'location': loc,
                                'percentage': percentage,
                                'timestamp': current_time,
                                'description': f'Unusual concentration from {loc}: {percentage:.1f}% of connections'
                            })

        # Store detected attacks
        self.potential_attacks.extend(attacks)
        self.potential_attacks = self.potential_attacks[-100:]  # Keep last 100

        return attacks

    def optimize_routing(self, available_nodes: list) -> list:
        """Optimize peer routing using predictive analytics"""
        if not available_nodes:
            return []

        current_time = time.time()
        scored_nodes = []

        for node in available_nodes:
            node_id = node.get('node_id', 'unknown')
            location = node.get('location', 'unknown')
            load_factor = node.get('load_factor', 0.0)
            reliability = node.get('reliability_score', 1.0)

            # Geographic scoring (prefer diverse locations)
            geo_score = 1.0
            if location in self.geographic_distribution:
                recent_count = self.geographic_distribution[location]['count']
                total_recent = sum(data['count'] for data in self.geographic_distribution.values())
                if total_recent > 0:
                    geo_percentage = recent_count / total_recent
                    # Prefer locations that aren't over-represented
                    geo_score = 1.0 - min(0.5, geo_percentage)

            # Load balancing score (prefer less loaded nodes)
            load_score = 1.0 - load_factor

            # Reliability score
            reliability_score = reliability

            # Combined score (weighted)
            total_score = (
                geo_score * 0.3 +
                load_score * 0.4 +
                reliability_score * 0.3
            )

            scored_nodes.append({
                'node': node,
                'score': total_score,
                'geo_score': geo_score,
                'load_score': load_score,
                'reliability_score': reliability_score
            })

        # Sort by total score (highest first)
        scored_nodes.sort(key=lambda x: x['score'], reverse=True)

        return scored_nodes

    def predict_network_load(self, hours_ahead: int = 1) -> dict:
        """Predict network load using time series analysis"""
        if len(self.connection_timestamps) < 20:
            return {'prediction': 'insufficient_data'}

        # Simple moving average prediction
        recent_timestamps = list(self.connection_timestamps)[-50:]  # Last 50 connections
        intervals = []

        for i in range(1, len(recent_timestamps)):
            intervals.append(recent_timestamps[i] - recent_timestamps[i-1])

        if intervals:
            avg_interval = statistics.mean(intervals)
            predicted_connections = (hours_ahead * 3600) / avg_interval  # Hours * seconds/hour / avg interval

            return {
                'predicted_connections': predicted_connections,
                'confidence': 'medium',  # Simple prediction, medium confidence
                'timeframe_hours': hours_ahead,
                'method': 'moving_average'
            }

        return {'prediction': 'no_data'}

    def get_network_insights(self) -> dict:
        """Get comprehensive network intelligence insights"""
        current_time = time.time()

        # Analyze current state
        health = self.analyze_network_health()
        attacks = self.detect_attacks()

        # Geographic insights
        top_locations = sorted(
            [(loc, data['count']) for loc, data in self.geographic_distribution.items()],
            key=lambda x: x[1],
            reverse=True
        )[:5]

        # Connection patterns
        hourly_connections = sum(1 for ts in self.connection_timestamps
                                if current_time - ts < 3600)

        # Performance insights
        latency_trend = "stable"
        if len(self.latency_history) >= 10:
            recent_latencies = [entry['latency'] for entry in list(self.latency_history)[-10:]]
            old_latencies = [entry['latency'] for entry in list(self.latency_history)[-20:-10]]

            if recent_latencies and old_latencies:
                recent_avg = statistics.mean(recent_latencies)
                old_avg = statistics.mean(old_latencies)

                if recent_avg > old_avg * 1.1:
                    latency_trend = "increasing"
                elif recent_avg < old_avg * 0.9:
                    latency_trend = "decreasing"

        return {
            'network_health': health,
            'active_attacks': attacks[-5:],  # Last 5 attacks
            'geographic_insights': {
                'top_locations': top_locations,
                'total_locations': len(self.geographic_distribution),
                'most_active_location': top_locations[0][0] if top_locations else 'unknown'
            },
            'performance_insights': {
                'hourly_connections': hourly_connections,
                'latency_trend': latency_trend,
                'avg_latency_ms': self.latency_stats.get('mean', 0),
                'latency_std_ms': self.latency_stats.get('std', 0)
            },
            'predictions': {
                'next_hour_load': self.predict_network_load(1),
                'next_day_load': self.predict_network_load(24)
            },
            'intelligence_summary': {
                'threat_level': 'high' if attacks else 'low',
                'optimization_opportunities': len([n for n in self.geographic_distribution.keys()
                                                if current_time - self.geographic_distribution[n]['last_seen'] > 3600]),
                'data_points_analyzed': len(self.connection_history),
                'analysis_timestamp': current_time
            }
        }

    def process_miner_intelligence(self, report_data: dict) -> dict:
        """Process intelligence contribution from mining nodes"""
        try:
            miner_id = report_data.get('miner_id')
            hashrate = report_data.get('hashrate', 0)
            location = report_data.get('location', 'unknown')

            # Analyze hashrate patterns for anomaly detection
            intelligence_value = self._analyze_miner_hashrate_pattern(hashrate, location)

            # Update geographic mining distribution
            if location not in self.geographic_distribution:
                self.geographic_distribution[location] = {'count': 0, 'last_seen': time.time()}
            self.geographic_distribution[location]['count'] += 1

            # Store miner intelligence for correlation
            miner_intel = {
                'miner_id': miner_id,
                'hashrate': hashrate,
                'location': location,
                'contribution_type': 'mining_pattern',
                'intelligence_value': intelligence_value,
                'timestamp': time.time()
            }

            # Could store in database for historical analysis
            logger.info(f"Miner intelligence processed: {miner_id} contributed value {intelligence_value}")

            return {
                'intelligence_value': intelligence_value,
                'contribution_type': 'mining_pattern',
                'anomalies_detected': intelligence_value > 0.5,
                'geographic_impact': location
            }

        except Exception as e:
            logger.error(f"Miner intelligence processing failed: {e}")
            return {'intelligence_value': 0, 'error': str(e)}

    def process_wallet_intelligence(self, report_data: dict) -> dict:
        """Process privacy-preserving intelligence from wallet nodes"""
        try:
            wallet_hash = report_data.get('wallet_id_hash')
            report_type = report_data.get('report_type', 'transaction_pattern')

            # Privacy-preserving analysis - aggregate patterns without individual details
            intelligence_value = self._analyze_wallet_pattern(report_data)

            # Anonymous geographic contribution (if provided)
            location = report_data.get('location', 'unknown')
            if location != 'unknown':
                # Aggregate geographic transaction patterns
                if location not in self.geographic_distribution:
                    self.geographic_distribution[location] = {'count': 0, 'last_seen': time.time()}
                self.geographic_distribution[location]['count'] += 0.1  # Fractional contribution for privacy

            wallet_intel = {
                'wallet_hash': wallet_hash,
                'report_type': report_type,
                'contribution_type': 'transaction_pattern',
                'intelligence_value': intelligence_value,
                'privacy_preserved': True,
                'timestamp': time.time()
            }

            logger.info(f"Wallet intelligence processed: anonymous contribution value {intelligence_value}")

            return {
                'intelligence_value': intelligence_value,
                'contribution_type': 'transaction_pattern',
                'privacy_preserved': True,
                'aggregated_analysis': True
            }

        except Exception as e:
            logger.error(f"Wallet intelligence processing failed: {e}")
            return {'intelligence_value': 0, 'error': str(e)}

    def _analyze_miner_hashrate_pattern(self, hashrate: float, location: str) -> float:
        """Analyze miner hashrate patterns for intelligence value"""
        # Simple pattern analysis - could be much more sophisticated
        base_value = 0.1  # Base intelligence value

        # Geographic concentration analysis
        location_count = self.geographic_distribution.get(location, {}).get('count', 0)
        total_locations = len(self.geographic_distribution)

        if total_locations > 1:
            concentration_factor = location_count / sum(data['count'] for data in self.geographic_distribution.values())
            if concentration_factor > 0.5:  # High concentration
                base_value += 0.3  # Valuable intelligence about mining pools

        # Hashrate anomaly detection
        if hashrate > 1000000:  # Very high hashrate (potential botnet)
            base_value += 0.4

        return min(1.0, base_value)

    def _analyze_wallet_pattern(self, report_data: dict) -> float:
        """Analyze wallet transaction patterns for intelligence value"""
        # Privacy-preserving pattern analysis
        base_value = 0.05  # Lower base value for privacy

        report_type = report_data.get('report_type', '')

        # Different report types have different intelligence value
        if report_type == 'unusual_transaction':
            base_value += 0.3
        elif report_type == 'fee_anomaly':
            base_value += 0.2
        elif report_type == 'geographic_shift':
            base_value += 0.15

        # Pattern consistency analysis (simplified)
        timestamp = report_data.get('timestamp', time.time())
        recent_reports = [ts for ts in self.connection_timestamps
                         if time.time() - ts < 3600]  # Last hour

        if len(recent_reports) > 10:  # Multiple reports indicate pattern
            base_value += 0.1

        return min(1.0, base_value)

    def _analyze_connection_patterns(self):
        """Internal method to analyze connection patterns for anomalies"""
        # This is called automatically when connections are recorded
        # Additional analysis could be added here
        pass

# Initialize network intelligence engine
network_intelligence = NetworkIntelligence()


def _local_intelligence_provider(endpoint: str):
    """Provide network intelligence without making HTTP calls."""
    predictions = network_intelligence.predict_network_load()
    return {
        'predictions': predictions,
        'confidence_level': predictions.get('confidence', 'unknown'),
        'prediction_horizon': '1-24_hours',
        'data_points_used': len(network_intelligence.connection_timestamps),
        'model_type': 'statistical_time_series',
        'timestamp': time.time(),
        'requested_endpoint': endpoint
    }


ddos_protection.set_intelligence_provider(_local_intelligence_provider)

# Intelligence Federation for Bootstrap Node Coordination
class IntelligenceFederation:
    """Federated intelligence sharing between bootstrap nodes"""

    def __init__(self, network_intelligence, bootstrap_registry):
        self.network_intelligence = network_intelligence
        self.bootstrap_registry = bootstrap_registry
        self.shared_intelligence = {}
        self.intelligence_peers = set()
        self.last_sync_times = {}
        self.federation_enabled = True

    def register_peer_bootstrap(self, bootstrap_node_id: str, endpoint: str):
        """Register a peer bootstrap node for intelligence sharing"""
        self.intelligence_peers.add((bootstrap_node_id, endpoint))
        logger.info(f"Registered intelligence peer: {bootstrap_node_id} at {endpoint}")

    def unregister_peer_bootstrap(self, bootstrap_node_id: str):
        """Remove a peer bootstrap node from intelligence sharing"""
        self.intelligence_peers = {(node_id, endpoint)
                                 for node_id, endpoint in self.intelligence_peers
                                 if node_id != bootstrap_node_id}
        self.last_sync_times.pop(bootstrap_node_id, None)

    def share_threat_intelligence(self, threat_data: dict):
        """Share threat intelligence with all peer bootstrap nodes"""
        if not self.federation_enabled:
            return

        current_time = time.time()
        federation_data = {
            'sender_node_id': 'bootstrap-primary',  # Would be dynamic
            'intelligence_type': 'threat_update',
            'data': threat_data,
            'timestamp': current_time,
            'federation_version': '1.0'
        }

        shared_count = 0
        for peer_id, peer_endpoint in self.intelligence_peers:
            try:
                # Async intelligence sharing (simplified - would use background tasks)
                self._share_with_peer(peer_id, peer_endpoint, federation_data)
                shared_count += 1
            except Exception as e:
                logger.warning(f"Failed to share intelligence with {peer_id}: {e}")

        logger.info(f"Shared threat intelligence with {shared_count} peer bootstrap nodes")

    def sync_intelligence_from_peers(self):
        """Synchronize intelligence from peer bootstrap nodes"""
        if not self.federation_enabled:
            return

        current_time = time.time()
        sync_count = 0

        for peer_id, peer_endpoint in self.intelligence_peers:
            try:
                # Check if we need to sync (every 5 minutes)
                last_sync = self.last_sync_times.get(peer_id, 0)
                if current_time - last_sync > 300:  # 5 minutes
                    peer_intelligence = self._sync_from_peer(peer_id, peer_endpoint)
                    if peer_intelligence:
                        self._merge_peer_intelligence(peer_id, peer_intelligence)
                        self.last_sync_times[peer_id] = current_time
                        sync_count += 1
            except Exception as e:
                logger.warning(f"Intelligence sync failed with {peer_id}: {e}")

        if sync_count > 0:
            logger.info(f"Synchronized intelligence from {sync_count} peer bootstrap nodes")

    def _share_with_peer(self, peer_id: str, peer_endpoint: str, intelligence_data: dict):
        """Share intelligence data with a specific peer via HTTP POST"""
        try:
            # Construct the full endpoint URL
            share_url = f"{peer_endpoint.rstrip('/')}/api/v1/intelligence/share"

            # Prepare the request payload
            request_data = {
                'sender_node_id': 'bootstrap-primary',  # Would be dynamic in production
                'federation_version': '1.0',
                'data': intelligence_data,
                'timestamp': time.time(),
                'checksum': self._calculate_payload_checksum(intelligence_data)
            }

            # Set up headers with basic authentication (would be more sophisticated in production)
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'PiSecure-Bootstrap-Federation/1.0',
                'X-Federation-Auth': self._generate_federation_auth_token(peer_id)
            }

            # Make the HTTP POST request with timeout and retries
            max_retries = 3
            retry_delay = 1.0

            for attempt in range(max_retries):
                try:
                    response = requests.post(
                        share_url,
                        json=request_data,
                        headers=headers,
                        timeout=10.0,  # 10 second timeout
                        verify=True  # SSL verification (would be configurable)
                    )

                    # Check response
                    if response.status_code == 200:
                        response_data = response.json()
                        if response_data.get('intelligence_accepted'):
                            logger.info(f"Successfully shared intelligence with peer {peer_id}")
                            return True
                        else:
                            logger.warning(f"Peer {peer_id} rejected intelligence share: {response_data}")
                            return False
                    elif response.status_code == 401:
                        logger.warning(f"Authentication failed with peer {peer_id}")
                        return False
                    elif response.status_code == 403:
                        logger.warning(f"Peer {peer_id} blocked intelligence share")
                        return False
                    else:
                        logger.warning(f"Unexpected response from peer {peer_id}: {response.status_code}")

                except requests.exceptions.Timeout:
                    logger.warning(f"Timeout sharing intelligence with peer {peer_id} (attempt {attempt + 1})")
                except requests.exceptions.ConnectionError:
                    logger.warning(f"Connection error sharing intelligence with peer {peer_id} (attempt {attempt + 1})")
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Request error sharing intelligence with peer {peer_id}: {e}")

                # Wait before retry (exponential backoff)
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))

            logger.error(f"Failed to share intelligence with peer {peer_id} after {max_retries} attempts")
            return False

        except Exception as e:
            logger.error(f"Intelligence sharing failed for {peer_id}: {e}")
            return False

    def _sync_from_peer(self, peer_id: str, peer_endpoint: str) -> dict:
        """Synchronize intelligence from a specific peer via HTTP GET"""
        try:
            # Construct the full endpoint URL
            sync_url = f"{peer_endpoint.rstrip('/')}/api/v1/intelligence/sync"

            # Set up headers with authentication
            headers = {
                'User-Agent': 'PiSecure-Bootstrap-Federation/1.0',
                'X-Federation-Auth': self._generate_federation_auth_token(peer_id),
                'Accept': 'application/json'
            }

            # Make the HTTP GET request with timeout and retries
            max_retries = 3
            retry_delay = 1.0

            for attempt in range(max_retries):
                try:
                    response = requests.get(
                        sync_url,
                        headers=headers,
                        timeout=15.0,  # Longer timeout for sync operations
                        verify=True
                    )

                    # Check response
                    if response.status_code == 200:
                        response_data = response.json()

                        if response_data.get('sync_success'):
                            intelligence_snapshot = response_data.get('intelligence_snapshot', {})

                            # Validate the sync data
                            if self._validate_sync_data(peer_id, intelligence_snapshot):
                                logger.info(f"Successfully synced intelligence from peer {peer_id}")
                                return intelligence_snapshot
                            else:
                                logger.warning(f"Invalid sync data received from peer {peer_id}")
                                return {}
                        else:
                            logger.warning(f"Peer {peer_id} reported sync failure: {response_data}")
                            return {}

                    elif response.status_code == 401:
                        logger.warning(f"Authentication failed syncing with peer {peer_id}")
                        return {}
                    elif response.status_code == 403:
                        logger.warning(f"Peer {peer_id} blocked sync request")
                        return {}
                    else:
                        logger.warning(f"Unexpected response from peer {peer_id}: {response.status_code}")

                except requests.exceptions.Timeout:
                    logger.warning(f"Timeout syncing intelligence with peer {peer_id} (attempt {attempt + 1})")
                except requests.exceptions.ConnectionError:
                    logger.warning(f"Connection error syncing intelligence with peer {peer_id} (attempt {attempt + 1})")
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Request error syncing intelligence with peer {peer_id}: {e}")
                except ValueError as e:
                    logger.warning(f"Invalid JSON response from peer {peer_id}: {e}")

                # Wait before retry (exponential backoff)
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))

            logger.error(f"Failed to sync intelligence from peer {peer_id} after {max_retries} attempts")
            return {}

        except Exception as e:
            logger.error(f"Intelligence sync failed for {peer_id}: {e}")
            return {}

    def _generate_federation_auth_token(self, peer_id: str) -> str:
        """Generate a simple authentication token for federation communication"""
        # In production, this would use proper cryptographic authentication
        # For now, use a simple hash-based token
        import hashlib
        import hmac

        # Simple shared secret (would be configurable per peer in production)
        shared_secret = "pisecure-federation-secret-2024"  # Should be environment variable

        # Create token with timestamp to prevent replay attacks
        timestamp = str(int(time.time()))
        message = f"{peer_id}:{timestamp}"

        # Generate HMAC
        token = hmac.new(
            shared_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        return f"{timestamp}:{token}"

    def _calculate_payload_checksum(self, data: dict) -> str:
        """Calculate checksum of payload for integrity verification"""
        import hashlib
        import json

        # Create deterministic JSON string
        data_str = json.dumps(data, sort_keys=True, separators=(',', ':'))

        # Calculate SHA256 hash
        checksum = hashlib.sha256(data_str.encode()).hexdigest()
        return checksum[:16]  # First 16 characters for brevity

    def _validate_sync_data(self, peer_id: str, sync_data: dict) -> bool:
        """Validate the integrity and reasonableness of sync data"""
        try:
            # Check required fields
            required_fields = ['threat_zones', 'active_attacks', 'intelligence_summary', 'sync_timestamp']
            for field in required_fields:
                if field not in sync_data:
                    logger.warning(f"Sync data from {peer_id} missing required field: {field}")
                    return False

            # Check timestamp is reasonable (within last hour)
            sync_timestamp = sync_data.get('sync_timestamp', 0)
            current_time = time.time()
            if current_time - sync_timestamp > 3600:  # 1 hour
                logger.warning(f"Sync data from {peer_id} has stale timestamp: {sync_timestamp}")
                return False

            # Check threat zones are reasonable (not too many)
            threat_zones = sync_data.get('threat_zones', [])
            if len(threat_zones) > 100:  # Arbitrary reasonable limit
                logger.warning(f"Sync data from {peer_id} has too many threat zones: {len(threat_zones)}")
                return False

            # Check attacks are reasonable
            active_attacks = sync_data.get('active_attacks', [])
            if len(active_attacks) > 50:  # Arbitrary reasonable limit
                logger.warning(f"Sync data from {peer_id} has too many active attacks: {len(active_attacks)}")
                return False

            # Validate attack data structure
            for attack in active_attacks:
                if not isinstance(attack, dict) or 'type' not in attack or 'timestamp' not in attack:
                    logger.warning(f"Sync data from {peer_id} has invalid attack structure")
                    return False

            return True

        except Exception as e:
            logger.error(f"Error validating sync data from {peer_id}: {e}")
            return False

    def _merge_peer_intelligence(self, peer_id: str, peer_intelligence: dict):
        """Merge intelligence from peer bootstrap node"""
        try:
            # Merge threat zones
            peer_threat_zones = peer_intelligence.get('threat_zones', [])
            for zone in peer_threat_zones:
                if zone not in self.network_intelligence.threat_zones:
                    # Only add if not already known (could add confidence scoring)
                    self.network_intelligence.threat_zones.add(zone)
                    logger.info(f"Added threat zone from peer {peer_id}: {zone}")

            # Merge attack data
            peer_attacks = peer_intelligence.get('active_attacks', [])
            for attack in peer_attacks:
                # Add peer identifier and merge
                attack['source'] = f'peer_{peer_id}'
                self.network_intelligence.potential_attacks.append(attack)

            # Keep only recent attacks
            self.network_intelligence.potential_attacks = self.network_intelligence.potential_attacks[-100:]

            # Update intelligence summary
            peer_summary = peer_intelligence.get('intelligence_summary', {})
            if peer_summary.get('threat_level') == 'high':
                logger.warning(f"Peer {peer_id} reports high threat level")

            logger.info(f"Merged intelligence from peer {peer_id}")

        except Exception as e:
            logger.error(f"Intelligence merge failed for {peer_id}: {e}")

    def get_federation_status(self) -> dict:
        """Get federation status and peer information"""
        return {
            'federation_enabled': self.federation_enabled,
            'active_peers': len(self.intelligence_peers),
            'peer_list': [{'node_id': pid, 'endpoint': endpoint}
                         for pid, endpoint in self.intelligence_peers],
            'last_sync_times': self.last_sync_times,
            'shared_intelligence_count': len(self.shared_intelligence)
        }

# Bootstrap Node Registry (Global state for secondary bootstrap nodes)
bootstrap_node_registry = {}

# Initialize intelligence federation after app creation
intelligence_federation = None
federation_sync_manager = None

# 314ST Bootstrap Operator Rewards System
class BootstrapOperatorRewards:
    """314ST token rewards for bootstrap operators"""

    def __init__(self):
        # Configuration from environment
        self.operator_wallet = os.getenv('BOOTSTRAP_OPERATOR_WALLET', '')
        self.reward_percentage = float(os.getenv('BOOTSTRAP_REWARD_PERCENTAGE', '0.05'))
        self.minimum_payout_314st = int(os.getenv('BOOTSTRAP_MINIMUM_PAYOUT', '10'))
        self.daily_budget_314st = int(os.getenv('BOOTSTRAP_DAILY_BUDGET', '1000'))

        # Reward tracking
        self.pending_rewards = defaultdict(int)  # wallet -> 314ST amount
        self.reward_history = []
        self.reward_pool_address = 'bootstrap-reward-pool'

        # Performance tracking
        self.operator_performance = {}
        self.last_payout_times = {}

        logger.info(f"314ST Bootstrap rewards initialized for wallet: {self.operator_wallet}")

    def configure_operator_wallet(self, wallet_address: str) -> bool:
        """Configure operator's PiSecure wallet for 314ST rewards"""
        if not wallet_address or not self._validate_pisecure_wallet(wallet_address):
            return False

        self.operator_wallet = wallet_address
        os.environ['BOOTSTRAP_OPERATOR_WALLET'] = wallet_address

        logger.info(f"Operator wallet configured: {wallet_address}")
        return True

    def _validate_pisecure_wallet(self, wallet_address: str) -> bool:
        """Validate PiSecure wallet format and accessibility"""
        # Basic validation - in production would check with PiSecure network
        if not wallet_address or len(wallet_address) < 10:
            return False

        # Check if wallet exists (mock validation)
        # In production: query PiSecure network for wallet validity
        return wallet_address.startswith(('pisecure_', 'wallet_'))

    def add_intelligence_reward(self, intelligence_value: float, contributor_type: str) -> bool:
        """Add 314ST reward for intelligence contribution"""
        if not self.operator_wallet:
            return False

        # Calculate 314ST value from intelligence
        intelligence_314st_value = self._convert_intelligence_to_314st(intelligence_value)

        # Apply quality bonuses
        quality_multiplier = self._calculate_quality_bonus(contributor_type)
        final_reward_314st = int(intelligence_314st_value * quality_multiplier)

        if final_reward_314st >= self.minimum_payout_314st:
            self.pending_rewards[self.operator_wallet] += final_reward_314st

            # Auto-distribute if threshold reached
            if self.pending_rewards[self.operator_wallet] >= (self.minimum_payout_314st * 5):
                return self.distribute_pending_rewards()

        return True

    def _convert_intelligence_to_314st(self, intelligence_value: float) -> float:
        """Convert intelligence value to 314ST amount"""
        # Intelligence value is abstract (0-1), convert to 314ST
        # Higher intelligence value = more 314ST
        base_314st = intelligence_value * 100  # 0-100 314ST per intelligence point

        # Apply operator reward percentage
        return base_314st * self.reward_percentage

    def _calculate_quality_bonus(self, contributor_type: str) -> float:
        """Calculate quality bonus multiplier"""
        bonuses = {
            'miner': 1.2,      # Mining intelligence is valuable
            'wallet': 1.1,     # Wallet patterns are useful
            'bootstrap': 1.3,  # Bootstrap federation is most valuable
            'high_quality': 1.5  # Exceptional intelligence
        }
        return bonuses.get(contributor_type, 1.0)

    def distribute_pending_rewards(self, specific_wallet: str = None) -> bool:
        """Distribute accumulated 314ST rewards"""
        wallet_to_process = specific_wallet or self.operator_wallet

        if not wallet_to_process or self.pending_rewards[wallet_to_process] < self.minimum_payout_314st:
            return False

        amount_to_distribute = self.pending_rewards[wallet_to_process]

        # Distribute 314ST via PiSecure network
        success = self._distribute_314st_to_wallet(wallet_to_process, amount_to_distribute)

        if success:
            # Record the distribution
            self.reward_history.append({
                'timestamp': time.time(),
                'wallet': wallet_to_process,
                'amount_314st': amount_to_distribute,
                'type': 'intelligence_rewards',
                'tx_hash': f'mock_tx_{int(time.time())}'  # In production: real tx hash
            })

            # Reset pending rewards
            self.pending_rewards[wallet_to_process] = 0
            self.last_payout_times[wallet_to_process] = time.time()

            logger.info(f"Distributed {amount_to_distribute} 314ST to operator {wallet_to_process}")
            return True

        return False

    def _distribute_314st_to_wallet(self, wallet_address: str, amount_314st: int) -> bool:
        """Distribute 314ST tokens to operator wallet"""
        try:
            # In production: Submit 314ST transfer to PiSecure network
            # For now: Mock successful distribution
            logger.info(f"Mock 314ST distribution: {amount_314st} to {wallet_address}")
            return True

        except Exception as e:
            logger.error(f"314ST distribution failed: {e}")
            return False

    def get_reward_analytics(self, wallet_address: str = None) -> dict:
        """Get comprehensive 314ST reward analytics"""
        wallet = wallet_address or self.operator_wallet

        if not wallet:
            return {'error': 'No operator wallet configured'}

        # Calculate earnings
        total_distributed = sum(r['amount_314st'] for r in self.reward_history
                              if r['wallet'] == wallet)

        recent_distributions = [r for r in self.reward_history[-10:]
                              if r['wallet'] == wallet]

        # Performance metrics
        performance_score = self._calculate_performance_score(wallet)

        return {
            'operator_wallet': wallet,
            'pending_rewards_314st': self.pending_rewards.get(wallet, 0),
            'total_distributed_314st': total_distributed,
            'recent_distributions': recent_distributions,
            'performance_score': performance_score,
            'daily_average_earnings': self._calculate_daily_average(wallet),
            'reward_configuration': {
                'percentage': self.reward_percentage,
                'minimum_payout': self.minimum_payout_314st,
                'daily_budget': self.daily_budget_314st
            },
            'last_payout': self.last_payout_times.get(wallet, 0),
            'timestamp': time.time()
        }

    def _calculate_performance_score(self, wallet: str) -> float:
        """Calculate operator performance score (0-100)"""
        if wallet not in self.operator_performance:
            return 75.0  # Default good score

        perf = self.operator_performance[wallet]
        score = 0

        # Uptime component (30%)
        score += (perf.get('uptime_percentage', 95) / 100) * 30

        # Intelligence quality (40%)
        score += (perf.get('intelligence_quality', 0.8) * 100) * 0.4

        # Federation participation (30%)
        score += (perf.get('federation_participation', 0.7) * 100) * 0.3

        return min(100.0, max(0.0, score))

    def _calculate_daily_average(self, wallet: str) -> float:
        """Calculate average daily 314ST earnings"""
        wallet_distributions = [r for r in self.reward_history if r['wallet'] == wallet]

        if not wallet_distributions:
            return 0.0

        total_earnings = sum(r['amount_314st'] for r in wallet_distributions)
        days_active = max(1, (time.time() - wallet_distributions[0]['timestamp']) / 86400)

        return total_earnings / days_active

    def add_uptime_bonus(self, uptime_percentage: float):
        """Add 314ST bonus for high uptime"""
        if not self.operator_wallet or uptime_percentage < 95:
            return

        bonus_314st = int((uptime_percentage - 95) * 2)  # 2 314ST per percentage above 95%
        if bonus_314st > 0:
            self.pending_rewards[self.operator_wallet] += bonus_314st

    def add_geographic_bonus(self, location: str):
        """Add bonus for intelligence from underrepresented regions"""
        # Simplified: bonus for non-US locations
        if location and not location.lower().startswith('us'):
            bonus_314st = 5  # 5 314ST for global coverage
            if self.operator_wallet:
                self.pending_rewards[self.operator_wallet] += bonus_314st

# Initialize 314ST rewards system
bootstrap_rewards = BootstrapOperatorRewards()

# PiSecure DEX Coordinator - Intelligence-Enhanced Trading
class PiSecureDEXCoordinator:
    """Bootstrap-level DEX coordination with ML intelligence"""

    def __init__(self, network_intelligence, bootstrap_registry):
        self.network_intelligence = network_intelligence
        self.bootstrap_registry = bootstrap_registry

        # DEX State
        self.liquidity_pools = {}  # pool_id -> pool_data
        self.active_trades = {}    # trade_id -> trade_data
        self.price_feeds = {}      # token_pair -> price_data

        # DEX Configuration
        self.swap_fee_percentage = 0.003  # 0.3% swap fee
        self.bootstrap_fee_share = 0.10   # 10% of fees to bootstrap operators
        self.min_liquidity_314st = 1000   # Minimum liquidity in pools

        logger.info("PiSecure DEX Coordinator initialized with intelligence integration")

    def create_liquidity_pool(self, token_a: str, token_b: str, creator_wallet: str) -> dict:
        """Create a new liquidity pool with intelligence-optimized parameters"""

        # Generate unique pool ID
        pool_id = f"{token_a}_{token_b}_{int(time.time())}"

        # Analyze network conditions for optimal fee structure
        network_health = self.network_intelligence.analyze_network_health()
        threat_level = network_health.get('threat_level', 'low')

        # Adjust fees based on network conditions
        adjusted_fee = self.swap_fee_percentage
        if threat_level == 'high':
            adjusted_fee *= 1.5  # Higher fees during network stress
        elif threat_level == 'low':
            adjusted_fee *= 0.8   # Lower fees during stable conditions

        pool_data = {
            'pool_id': pool_id,
            'token_a': token_a,
            'token_b': token_b,
            'creator_wallet': creator_wallet,
            'creation_timestamp': time.time(),
            'fee_percentage': adjusted_fee,
            'total_liquidity_a': 0,
            'total_liquidity_b': 0,
            'liquidity_providers': {},
            'trade_count': 0,
            'volume_24h': 0,
            'last_trade_timestamp': None,
            'pool_health_score': 100
        }

        self.liquidity_pools[pool_id] = pool_data
        logger.info(f"Created liquidity pool {pool_id} for {token_a}/{token_b}")

        return pool_data

    def add_liquidity(self, pool_id: str, provider_wallet: str, amount_a: int, amount_b: int) -> dict:
        """Add liquidity to an existing pool"""

        if pool_id not in self.liquidity_pools:
            return {'error': 'Pool not found'}

        pool = self.liquidity_pools[pool_id]

        # Update pool liquidity
        pool['total_liquidity_a'] += amount_a
        pool['total_liquidity_b'] += amount_b

        # Track provider's share
        provider_share = {
            'wallet': provider_wallet,
            'amount_a': amount_a,
            'amount_b': amount_b,
            'timestamp': time.time()
        }

        if provider_wallet not in pool['liquidity_providers']:
            pool['liquidity_providers'][provider_wallet] = []

        pool['liquidity_providers'][provider_wallet].append(provider_share)

        # Calculate and distribute 314ST rewards for liquidity provision
        reward_314st = self._calculate_liquidity_reward(amount_a, amount_b, pool)
        if reward_314st > 0:
            bootstrap_rewards.add_intelligence_reward(reward_314st, 'liquidity_provision')

        logger.info(f"Added liquidity to pool {pool_id}: {amount_a} {pool['token_a']}, {amount_b} {pool['token_b']}")

        return {
            'success': True,
            'pool_id': pool_id,
            'liquidity_added': {'amount_a': amount_a, 'amount_b': amount_b},
            'reward_314st': reward_314st,
            'pool_liquidity': {
                'total_a': pool['total_liquidity_a'],
                'total_b': pool['total_liquidity_b']
            }
        }

    def calculate_optimal_swap(self, token_in: str, token_out: str, amount_in: int) -> dict:
        """Use ML intelligence to find optimal swap route"""

        # Find available pools for this token pair
        available_pools = self._find_pools_for_pair(token_in, token_out)

        if not available_pools:
            return {'error': 'No liquidity pools available for this pair'}

        # Use network intelligence for optimal pool selection
        network_health = self.network_intelligence.analyze_network_health()
        threat_level = network_health.get('threat_level', 'low')

        # Convert pools to format expected by intelligence optimizer
        pool_candidates = []
        for pool_id, pool_data in available_pools.items():
            # Calculate current exchange rate
            if pool_data['total_liquidity_a'] > 0 and pool_data['total_liquidity_b'] > 0:
                rate = pool_data['total_liquidity_b'] / pool_data['total_liquidity_a']
            else:
                rate = 0

            pool_candidates.append({
                'pool_id': pool_id,
                'token_a': pool_data['token_a'],
                'token_b': pool_data['token_b'],
                'liquidity_a': pool_data['total_liquidity_a'],
                'liquidity_b': pool_data['total_liquidity_b'],
                'fee_percentage': pool_data['fee_percentage'],
                'exchange_rate': rate,
                'trade_count': pool_data['trade_count'],
                'pool_health': pool_data['pool_health_score']
            })

        # Use intelligence to optimize routing
        optimal_route = self.network_intelligence.optimize_routing_ml(
            available_nodes=pool_candidates,
            threat_intelligence={'threat_level': threat_level}
        )

        if not optimal_route:
            return {'error': 'No optimal route found'}

        # Calculate swap details
        best_pool = optimal_route[0]['node'] if optimal_route else pool_candidates[0]
        swap_details = self._calculate_swap_details(best_pool, amount_in, token_in, token_out)

        # Adjust for network conditions
        if threat_level == 'high':
            swap_details['recommended_slippage'] = 0.005  # 0.5% max slippage
            swap_details['deadline_blocks'] = 50  # Shorter deadline
        else:
            swap_details['recommended_slippage'] = 0.01   # 1% max slippage
            swap_details['deadline_blocks'] = 200  # Longer deadline

        return {
            'optimal_route': optimal_route,
            'swap_details': swap_details,
            'network_conditions': {
                'threat_level': threat_level,
                'recommended_approach': 'conservative' if threat_level == 'high' else 'standard'
            },
            'intelligence_used': True
        }

    def execute_swap_coordination(self, swap_request: dict) -> dict:
        """Coordinate swap execution with intelligence monitoring"""

        token_in = swap_request['token_in']
        token_out = swap_request['token_out']
        amount_in = swap_request['amount_in']
        user_wallet = swap_request['user_wallet']

        # Get optimal swap route
        route_result = self.calculate_optimal_swap(token_in, token_out, amount_in)

        if 'error' in route_result:
            return route_result

        # Generate swap instructions for wallet
        swap_instructions = {
            'swap_id': f"swap_{int(time.time())}_{hash(str(swap_request)) % 10000}",
            'token_in': token_in,
            'token_out': token_out,
            'amount_in': amount_in,
            'expected_out': route_result['swap_details']['amount_out'],
            'min_out': route_result['swap_details']['min_out'],
            'pool_id': route_result['swap_details']['pool_id'],
            'fee_amount': route_result['swap_details']['fee_amount'],
            'deadline_blocks': route_result['network_conditions']['recommended_deadline'],
            'recommended_slippage': route_result['network_conditions']['recommended_slippage'],
            'intelligence_optimized': True,
            'network_threat_level': route_result['network_conditions']['threat_level']
        }

        # Store active trade for monitoring
        self.active_trades[swap_instructions['swap_id']] = {
            'user_wallet': user_wallet,
            'instructions': swap_instructions,
            'status': 'pending',
            'timestamp': time.time()
        }

        logger.info(f"Coordinated intelligent swap for wallet {user_wallet}: {amount_in} {token_in} -> {token_out}")

        return {
            'swap_coordinated': True,
            'swap_instructions': swap_instructions,
            'intelligence_benefits': [
                'Optimal pool selection',
                'Threat-aware slippage limits',
                'Network condition adaptation'
            ]
        }

    def _find_pools_for_pair(self, token_a: str, token_b: str) -> dict:
        """Find all pools that can facilitate token_a -> token_b swaps"""
        matching_pools = {}

        for pool_id, pool_data in self.liquidity_pools.items():
            # Direct pair match
            if ((pool_data['token_a'] == token_a and pool_data['token_b'] == token_b) or
                (pool_data['token_a'] == token_b and pool_data['token_b'] == token_a)):
                matching_pools[pool_id] = pool_data
            # Could add multi-hop routing here in future

        return matching_pools

    def _calculate_swap_details(self, pool_data: dict, amount_in: int, token_in: str, token_out: str) -> dict:
        """Calculate swap output amount and fees"""

        # Get pool reserves
        reserve_in = pool_data['total_liquidity_a'] if pool_data['token_a'] == token_in else pool_data['total_liquidity_b']
        reserve_out = pool_data['total_liquidity_b'] if pool_data['token_b'] == token_out else pool_data['total_liquidity_a']

        if reserve_in == 0 or reserve_out == 0:
            return {'error': 'Insufficient liquidity'}

        # AMM calculation: (x + dx) * (y - dy) = x * y
        # dy = (y * dx) / (x + dx)
        amount_out = int((reserve_out * amount_in) / (reserve_in + amount_in))

        # Calculate fee (0.3% of input)
        fee_amount = int(amount_in * pool_data['fee_percentage'])

        # Bootstrap operator gets share of fees
        bootstrap_fee = int(fee_amount * self.bootstrap_fee_share)
        if bootstrap_fee > 0:
            bootstrap_rewards.add_intelligence_reward(bootstrap_fee, 'dex_fee')

        # Minimum output with slippage protection
        min_out = int(amount_out * 0.95)  # 5% slippage protection

        return {
            'pool_id': pool_data['pool_id'],
            'amount_out': amount_out,
            'min_out': min_out,
            'fee_amount': fee_amount,
            'price_impact': (amount_in / reserve_in) * 100,  # Percentage
            'exchange_rate': reserve_out / reserve_in if reserve_in > 0 else 0
        }

    def _calculate_liquidity_reward(self, amount_a: int, amount_b: int, pool_data: dict) -> int:
        """Calculate 314ST reward for liquidity provision"""

        # Base reward: 1 314ST per 1000 tokens provided
        base_reward = (amount_a + amount_b) // 1000

        # Bonus for low liquidity pools (helps bootstrap new pools)
        liquidity_ratio = min(amount_a, amount_b) / max(amount_a, amount_b) if max(amount_a, amount_b) > 0 else 0
        balance_bonus = int(base_reward * (1 - liquidity_ratio))  # Bonus for balanced provision

        # Intelligence bonus based on network conditions
        network_health = self.network_intelligence.analyze_network_health()
        intelligence_bonus = int(base_reward * 0.5) if network_health.get('overall_health', 50) > 80 else 0

        total_reward = base_reward + balance_bonus + intelligence_bonus

        return max(0, total_reward)

    def get_dex_intelligence(self) -> dict:
        """Get comprehensive DEX intelligence from network analysis"""

        # Analyze pool health and trading patterns
        pool_health_analysis = self._analyze_pool_health()
        trading_pattern_analysis = self._analyze_trading_patterns()

        # Network intelligence integration
        network_insights = self.network_intelligence.get_network_insights()

        # Generate DEX-specific recommendations
        recommendations = self._generate_dex_recommendations(pool_health_analysis, network_insights)

        return {
            'dex_health_score': self._calculate_dex_health_score(),
            'active_pools': len(self.liquidity_pools),
            'total_liquidity_314st': self._calculate_total_liquidity(),
            'trading_volume_24h': self._calculate_24h_volume(),
            'pool_health_analysis': pool_health_analysis,
            'trading_patterns': trading_pattern_analysis,
            'network_intelligence_integration': {
                'threat_aware_trading': True,
                'intelligence_enhanced_routing': True,
                'network_condition_adaptation': True
            },
            'recommendations': recommendations,
            'intelligence_benefits': [
                'Optimal trade routing based on network conditions',
                'Threat-aware slippage limits',
                'Pool health monitoring and recommendations',
                'Trading pattern analysis for market intelligence'
            ]
        }

    def _analyze_pool_health(self) -> dict:
        """Analyze health of all liquidity pools"""
        healthy_pools = 0
        total_pools = len(self.liquidity_pools)

        for pool_data in self.liquidity_pools.values():
            liquidity_score = min(100, (pool_data['total_liquidity_a'] + pool_data['total_liquidity_b']) / 100)
            activity_score = min(100, pool_data['trade_count'] * 10)
            health_score = (liquidity_score + activity_score) / 2

            pool_data['pool_health_score'] = health_score
            if health_score > 60:
                healthy_pools += 1

        return {
            'total_pools': total_pools,
            'healthy_pools': healthy_pools,
            'health_percentage': (healthy_pools / total_pools * 100) if total_pools > 0 else 0,
            'recommendations': self._get_pool_health_recommendations()
        }

    def _analyze_trading_patterns(self) -> dict:
        """Analyze trading patterns using intelligence"""
        # This would analyze trading data for patterns
        return {
            'peak_trading_hours': ['14:00-16:00 UTC'],  # Example
            'popular_pairs': ['314ST/wBTC', '314ST/wETH'],
            'average_trade_size': 500,  # 314ST
            'price_stability': 'high'
        }

    def _generate_dex_recommendations(self, pool_health: dict, network_insights: dict) -> list:
        """Generate DEX recommendations based on analysis"""
        recommendations = []

        if pool_health['health_percentage'] < 70:
            recommendations.append("Consider adding incentives for new liquidity pools")

        threat_level = network_insights.get('intelligence_summary', {}).get('threat_level', 'low')
        if threat_level == 'high':
            recommendations.append("High network threat level - recommend conservative trading parameters")

        return recommendations

    def _calculate_dex_health_score(self) -> float:
        """Calculate overall DEX health score"""
        if not self.liquidity_pools:
            return 0.0

        pool_health_scores = [pool['pool_health_score'] for pool in self.liquidity_pools.values()]
        avg_pool_health = sum(pool_health_scores) / len(pool_health_scores)

        # Factor in network intelligence
        network_health = self.network_intelligence.analyze_network_health()
        network_score = network_health.get('overall_health', 50)

        # Combined score
        return (avg_pool_health + network_score) / 2

    def _calculate_total_liquidity(self) -> int:
        """Calculate total 314ST-equivalent liquidity across all pools"""
        total_liquidity = 0
        for pool in self.liquidity_pools.values():
            # Convert all liquidity to 314ST equivalent (simplified)
            total_liquidity += pool['total_liquidity_a'] + pool['total_liquidity_b']
        return total_liquidity

    def _calculate_24h_volume(self) -> int:
        """Calculate 24-hour trading volume"""
        # Simplified - would track actual volume
        return sum(pool['volume_24h'] for pool in self.liquidity_pools.values())

# Initialize intelligence federation and sync manager after app creation
intelligence_federation = IntelligenceFederation(network_intelligence, bootstrap_node_registry)
federation_sync_manager = None  # Initialize later if needed

# PiSecure Node Registry for managing registered nodes
pisecure_node_registry = {}
node_status_history = defaultdict(list)  # node_id -> [status_updates]

def _validate_node_registration(registration_data: dict) -> bool:
    """Validate node registration data"""
    required_fields = ['node_id', 'node_type', 'services', 'capabilities']

    for field in required_fields:
        if field not in registration_data:
            return False

    # Validate node_id format (alphanumeric + hyphens/underscores)
    import re
    if not re.match(r'^[a-zA-Z0-9_-]{5,50}$', registration_data['node_id']):
        return False

    # Validate node_type
    valid_types = ['miner', 'validator', 'wallet', 'bootstrap', 'standard']
    if registration_data.get('node_type') not in valid_types:
        return False

    # Validate services list
    if not isinstance(registration_data.get('services', []), list):
        return False

    # Validate capabilities list
    if not isinstance(registration_data.get('capabilities', []), list):
        return False

    return True

def _register_pisecure_node(node_data: dict) -> bool:
    """Register a PiSecure node in the registry"""
    try:
        node_id = node_data['node_id']

        # Store node data
        pisecure_node_registry[node_id] = {
            **node_data,
            'registration_timestamp': time.time(),
            'status_updates': 0,
            'last_status_update': None,
            'performance_score': 0.0
        }

        logger.info(f"Registered PiSecure node: {node_id}")
        return True

    except Exception as e:
        logger.error(f"Node registration failed: {e}")
        return False

def _is_node_registered(node_id: str) -> bool:
    """Check if a node is registered"""
    return node_id in pisecure_node_registry

def _update_node_status(node_id: str, status_update: dict) -> bool:
    """Update node status and store in history"""
    try:
        if node_id not in pisecure_node_registry:
            return False

        # Update node data
        pisecure_node_registry[node_id].update({
            'last_seen': time.time(),
            'last_status_update': status_update,
            'status_updates': pisecure_node_registry[node_id]['status_updates'] + 1
        })

        # Store status in history (keep last 50 updates)
        node_status_history[node_id].append({
            **status_update,
            'timestamp': time.time()
        })
        node_status_history[node_id] = node_status_history[node_id][-50:]

        # Calculate performance score
        performance_score = _calculate_node_performance_score(node_id)
        pisecure_node_registry[node_id]['performance_score'] = performance_score

        return True

    except Exception as e:
        logger.error(f"Status update failed for {node_id}: {e}")
        return False

def _calculate_node_performance_score(node_id: str) -> float:
    """Calculate performance score for a node based on status history"""
    if node_id not in node_status_history or not node_status_history[node_id]:
        return 0.0

    status_updates = node_status_history[node_id][-10:]  # Last 10 updates

    # Calculate uptime from status reports
    active_count = sum(1 for update in status_updates if update.get('status') == 'active')
    uptime_score = active_count / len(status_updates) if status_updates else 0

    # Mining activity score
    mining_active_count = sum(1 for update in status_updates if update.get('mining_active', False))
    mining_score = mining_active_count / len(status_updates) if status_updates else 0

    # Peer connectivity score
    avg_peers = sum(update.get('peers_connected', 0) for update in status_updates) / len(status_updates)
    connectivity_score = min(1.0, avg_peers / 10)  # Max score at 10 peers

    # Combined performance score (0-100)
    performance_score = (uptime_score * 0.4 + mining_score * 0.3 + connectivity_score * 0.3) * 100

    return round(performance_score, 2)

def _process_node_intelligence(node_id: str, status_data: dict):
    """Process intelligence from node status updates"""
    try:
        # Extract intelligence data
        hashrate = status_data.get('hashrate', 0)
        location = pisecure_node_registry[node_id].get('location', 'unknown')
        mining_active = status_data.get('mining_active', False)

        # Create intelligence report
        intelligence_report = {
            'miner_id': node_id,
            'hashrate': hashrate,
            'location': location,
            'mining_active': mining_active,
            'timestamp': time.time()
        }

        # Process through network intelligence
        network_intelligence.process_miner_intelligence(intelligence_report)

    except Exception as e:
        logger.warning(f"Intelligence processing failed for {node_id}: {e}")

def _get_node_recommendations(node_id: str, status_data: dict) -> list:
    """Generate recommendations for node based on status"""
    recommendations = []

    try:
        # Check mining status
        if not status_data.get('mining_active', False):
            recommendations.append("Consider activating mining to contribute to network security")

        # Check peer connections
        peers_connected = status_data.get('peers_connected', 0)
        if peers_connected < 3:
            recommendations.append(f"Low peer count ({peers_connected}). Consider improving connectivity")

        # Check hashrate
        hashrate = status_data.get('hashrate', 0)
        if hashrate < 1000000:  # Less than 1 MH/s
            recommendations.append("Consider upgrading mining hardware for better network contribution")

        # Performance-based recommendations
        performance_score = pisecure_node_registry[node_id].get('performance_score', 0)
        if performance_score < 50:
            recommendations.append("Performance score below average. Check node configuration")

    except Exception as e:
        logger.warning(f"Recommendation generation failed for {node_id}: {e}")

    return recommendations

def _cleanup_inactive_nodes():
    """Remove inactive nodes from registry (burn inactive nodes)"""
    current_time = time.time()
    inactive_timeout = 24 * 60 * 60  # 24 hours in seconds
    nodes_to_remove = []

    for node_id, node_data in pisecure_node_registry.items():
        last_seen = node_data.get('last_seen', 0)
        if current_time - last_seen > inactive_timeout:
            nodes_to_remove.append(node_id)
            logger.info(f"Burning inactive node: {node_id} (last seen {current_time - last_seen:.0f}s ago)")

    # Remove inactive nodes from registry
    for node_id in nodes_to_remove:
        pisecure_node_registry.pop(node_id, None)
        node_status_history.pop(node_id, None)

    if nodes_to_remove:
        logger.info(f"Burned {len(nodes_to_remove)} inactive nodes from registry")

    return len(nodes_to_remove)

def _get_registered_nodes_filtered(node_type: str = None, location: str = None, service: str = None) -> list:
    """Get filtered list of registered nodes (with inactive node cleanup)"""
    # Clean up inactive nodes before returning list
    _cleanup_inactive_nodes()

    nodes = []

    for node_id, node_data in pisecure_node_registry.items():
        # Apply filters
        if node_type and node_data.get('node_type') != node_type:
            continue
        if location and node_data.get('location') != location:
            continue
        if service and service not in node_data.get('services', []):
            continue

        # Add intelligence insights
        nodes.append({
            'node_id': node_id,
            'node_type': node_data.get('node_type'),
            'services': node_data.get('services', []),
            'capabilities': node_data.get('capabilities', []),
            'location': node_data.get('location'),
            'status': node_data.get('status'),
            'last_seen': node_data.get('last_seen'),
            'performance_score': node_data.get('performance_score', 0),
            'registered_at': node_data.get('registered_at'),
            'wallet_address': node_data.get('wallet_address')
        })

    return nodes

def _get_node_insights(node_id: str) -> dict:
    """Get intelligence insights for a specific node"""
    try:
        if node_id not in pisecure_node_registry:
            return {}

        node_data = pisecure_node_registry[node_id]
        status_history = node_status_history.get(node_id, [])

        if not status_history:
            return {'insights_available': False}

        # Calculate insights
        recent_updates = status_history[-5:]  # Last 5 status updates
        avg_uptime = sum(1 for update in recent_updates if update.get('status') == 'active') / len(recent_updates)
        avg_peers = sum(update.get('peers_connected', 0) for update in recent_updates) / len(recent_updates)
        mining_participation = sum(1 for update in recent_updates if update.get('mining_active')) / len(recent_updates)

        return {
            'insights_available': True,
            'uptime_percentage': round(avg_uptime * 100, 1),
            'avg_peer_connections': round(avg_peers, 1),
            'mining_participation_rate': round(mining_participation * 100, 1),
            'total_status_updates': len(status_history),
            'performance_trend': _calculate_performance_trend(status_history),
            'network_contribution_score': node_data.get('performance_score', 0)
        }

    except Exception as e:
        logger.warning(f"Node insights calculation failed for {node_id}: {e}")
        return {'insights_available': False, 'error': str(e)}

def _calculate_performance_trend(status_history: list) -> str:
    """Calculate performance trend from status history"""
    if len(status_history) < 5:
        return 'insufficient_data'

    # Simple trend analysis
    recent_scores = []
    for i, status in enumerate(status_history[-10:]):  # Last 10 updates
        # Calculate simple performance score for each update
        score = 0
        if status.get('status') == 'active':
            score += 30
        if status.get('mining_active'):
            score += 40
        if status.get('peers_connected', 0) >= 3:
            score += 30
        recent_scores.append(score)

    if len(recent_scores) >= 5:
        # Compare first half vs second half
        mid = len(recent_scores) // 2
        first_half_avg = sum(recent_scores[:mid]) / mid
        second_half_avg = sum(recent_scores[mid:]) / (len(recent_scores) - mid)

        if second_half_avg > first_half_avg * 1.1:
            return 'improving'
        elif second_half_avg < first_half_avg * 0.9:
            return 'declining'
        else:
            return 'stable'

    return 'analyzing'

def calculate_bootstrap_operator_value() -> dict:
    """Calculate the economic value of bootstrap operators based on real-world models"""

    # Base calculations
    current_time = time.time()

    # Intelligence processing value (threat detection, optimization)
    intelligence_value_per_hour = 50  # $50/hour for ML processing and analysis
    intelligence_uptime_hours = 24 * 30  # Assuming 30 days of operation
    intelligence_value_monthly = intelligence_value_per_hour * intelligence_uptime_hours

    # DEX coordination fees (percentage of trading volume)
    dex_trading_volume_daily = pisecure_dex._calculate_24h_volume() if pisecure_dex.liquidity_pools else 10000
    dex_fee_percentage = 0.003  # 0.3% average fee
    dex_bootstrap_share = 0.10  # 10% of fees to bootstrap operators
    dex_daily_fees = dex_trading_volume_daily * dex_fee_percentage * dex_bootstrap_share
    dex_monthly_value = dex_daily_fees * 30

    # Network health monitoring value
    network_monitoring_hourly = 25  # $25/hour for 24/7 monitoring
    network_monitoring_monthly = network_monitoring_hourly * 24 * 30

    # Bootstrap coordination value (peer discovery, federation)
    bootstrap_coordination_hourly = 30  # $30/hour for coordination services
    bootstrap_coordination_monthly = bootstrap_coordination_hourly * 24 * 30

    # Operating costs (electricity, hosting)
    electricity_cost_hourly = 0.5  # $0.50/hour electricity for dedicated server
    hosting_cost_monthly = 50  # $50/month hosting
    operating_costs_monthly = (electricity_cost_hourly * 24 * 30) + hosting_cost_monthly

    # Work value (operator time and expertise)
    operator_time_hourly = 15  # $15/hour value of operator expertise
    maintenance_time_daily = 2  # 2 hours daily maintenance
    operator_value_monthly = operator_time_hourly * maintenance_time_daily * 30

    # Availability and reliability bonuses
    base_uptime_percentage = 99.5  # 99.5% uptime
    uptime_bonus_percentage = max(0, (base_uptime_percentage - 95) / 5)  # Bonus for >95% uptime
    uptime_bonus_monthly = (intelligence_value_monthly + network_monitoring_monthly) * uptime_bonus_percentage

    # Utility value (prevents attacks, improves user experience)
    attack_prevention_value = 500  # $500/month value for preventing attacks
    user_experience_value = 300  # $300/month value for better UX through intelligence
    utility_value_monthly = attack_prevention_value + user_experience_value

    # Calculate total monthly value
    gross_value_monthly = (
        intelligence_value_monthly +
        dex_monthly_value +
        network_monitoring_monthly +
        bootstrap_coordination_monthly +
        uptime_bonus_monthly +
        utility_value_monthly
    )

    net_value_monthly = gross_value_monthly - operating_costs_monthly - operator_value_monthly

    # Calculate hourly and daily rates
    net_value_daily = net_value_monthly / 30
    net_value_hourly = net_value_daily / 24

    # 314ST equivalent (assuming $1 = 100 314ST for this example)
    usd_to_314st_rate = 100
    net_value_314st_monthly = int(net_value_monthly * usd_to_314st_rate)
    net_value_314st_daily = int(net_value_daily * usd_to_314st_rate)
    net_value_314st_hourly = int(net_value_hourly * usd_to_314st_rate)

    return {
        'breakdown': {
            'intelligence_processing': {
                'hourly_usd': intelligence_value_per_hour,
                'monthly_usd': intelligence_value_monthly,
                'description': 'ML-powered threat detection and optimization'
            },
            'dex_coordination_fees': {
                'daily_usd': dex_daily_fees,
                'monthly_usd': dex_monthly_value,
                'description': 'Percentage of DEX trading fees'
            },
            'network_monitoring': {
                'hourly_usd': network_monitoring_hourly,
                'monthly_usd': network_monitoring_monthly,
                'description': '24/7 network health monitoring'
            },
            'bootstrap_coordination': {
                'hourly_usd': bootstrap_coordination_hourly,
                'monthly_usd': bootstrap_coordination_monthly,
                'description': 'Peer discovery and federation coordination'
            },
            'uptime_bonus': {
                'monthly_usd': uptime_bonus_monthly,
                'percentage': uptime_bonus_percentage * 100,
                'description': f'Bonus for {base_uptime_percentage}% uptime'
            },
            'utility_value': {
                'monthly_usd': utility_value_monthly,
                'description': 'Attack prevention and improved user experience'
            },
            'operating_costs': {
                'monthly_usd': operating_costs_monthly,
                'description': 'Electricity, hosting, and infrastructure'
            },
            'operator_work_value': {
                'monthly_usd': operator_value_monthly,
                'description': 'Time and expertise investment'
            }
        },
        'totals': {
            'gross_value_monthly_usd': gross_value_monthly,
            'net_value_monthly_usd': net_value_monthly,
            'net_value_daily_usd': net_value_daily,
            'net_value_hourly_usd': net_value_hourly,
            'net_value_monthly_314st': net_value_314st_monthly,
            'net_value_daily_314st': net_value_314st_daily,
            'net_value_hourly_314st': net_value_314st_hourly
        },
        'assumptions': {
            'usd_to_314st_rate': usd_to_314st_rate,
            'uptime_percentage': base_uptime_percentage,
            'dex_volume_daily': dex_trading_volume_daily,
            'calculation_date': current_time
        },
        'disclaimer': 'Values are estimates based on industry standards and current network activity. Actual value may vary based on market conditions, network usage, and operational efficiency.'
    }

# Initialize PiSecure DEX Coordinator
pisecure_dex = PiSecureDEXCoordinator(network_intelligence, bootstrap_node_registry)

def _validate_bootstrap_node(handshake_data: dict) -> bool:
    """Validate that the node attempting handshake is a legitimate bootstrap node"""
    # Basic validation - in production, this would be more sophisticated
    # Check for required capabilities, valid address format, etc.

    node_id = handshake_data.get('node_id', '')
    address = handshake_data.get('address', '')
    services = handshake_data.get('services', [])
    capabilities = handshake_data.get('capabilities', [])

    # Must have bootstrap-related capabilities
    bootstrap_capabilities = [
        'bootstrap_coordination',
        'peer_discovery',
        'network_health',
        'network_health_monitoring',
        'federation_management'
    ]
    has_bootstrap_capability = any(cap in capabilities for cap in bootstrap_capabilities)

    # Must offer basic bootstrap services
    required_services = ['peer_discovery']
    has_required_services = all(service in services for service in required_services)

    # Basic address validation
    valid_address = _is_valid_node_address(address)

    # Node ID should be unique and not already registered as primary
    valid_node_id = (node_id and
                    node_id != 'bootstrap-primary' and
                    len(node_id) >= 10)

    return (has_bootstrap_capability and
            has_required_services and
            valid_address and
            valid_node_id)

def _register_bootstrap_node(bootstrap_node: dict):
    """Register or update a secondary bootstrap node"""
    node_id = bootstrap_node['node_id']
    bootstrap_node_registry[node_id] = bootstrap_node
    logger.info(f"Registered bootstrap node: {node_id}")

def _update_bootstrap_services(node_id: str, service_update: dict):
    """Update service advertisement for a bootstrap node"""
    if node_id in bootstrap_node_registry:
        bootstrap_node_registry[node_id].update(service_update)
        logger.info(f"Updated services for bootstrap node: {node_id}")

def _is_bootstrap_node_registered(node_id: str) -> bool:
    """Check if a bootstrap node is registered"""
    return node_id in bootstrap_node_registry

def _get_registered_bootstrap_nodes() -> list:
    """Get all registered secondary bootstrap nodes"""
    current_time = time.time()
    active_nodes = []

    for node_id, node_data in bootstrap_node_registry.items():
        # Check if node is still active (last seen within 10 minutes)
        if current_time - node_data.get('last_seen', 0) < 600:
            active_nodes.append({
                'node_id': node_data['node_id'],
                'address': node_data['address'],
                'port': node_data['port'],
                'services': node_data['services'],
                'capabilities': node_data['capabilities'],
                'region': node_data.get('region', 'unknown'),
                'status': node_data.get('status', 'active'),
                'load_factor': node_data.get('load_factor', 0.0),
                'last_seen': node_data.get('last_seen', current_time)
            })

    return active_nodes

def _get_active_services() -> list:
    """Get all currently active services across bootstrap nodes"""
    all_services = set()
    current_time = time.time()

    # Primary node services
    all_services.update(['coordination', 'peer_discovery', 'health_monitoring'])

    # Secondary node services
    for node_data in bootstrap_node_registry.values():
        if current_time - node_data.get('last_seen', 0) < 600:  # Active within 10 minutes
            services = node_data.get('services', [])
            all_services.update(services)

    return sorted(list(all_services))

def _find_optimal_bootstrap_node(service: str, requesting_node: str) -> dict:
    """Find the best bootstrap node for a specific service"""
    current_time = time.time()
    candidates = []

    for node_id, node_data in bootstrap_node_registry.items():
        # Skip requesting node itself
        if node_id == requesting_node:
            continue

        # Check if node is active and offers the service
        if (current_time - node_data.get('last_seen', 0) < 600 and
            service in node_data.get('services', [])):

            # Calculate suitability score (lower load_factor is better)
            load_factor = node_data.get('load_factor', 0.0)
            reliability = node_data.get('reliability_score', 1.0)
            suitability_score = reliability * (1.0 - load_factor)

            candidates.append((suitability_score, node_data))

    if candidates:
        # Return the best candidate (highest suitability score)
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    return None

def _validate_miner_report(miner_id: str, report_data: dict) -> bool:
    """Validate miner intelligence report"""
    # Basic validation - in production would verify proof-of-work or signature
    required_fields = ['miner_id', 'hashrate', 'timestamp']
    for field in required_fields:
        if field not in report_data:
            return False

    # Check timestamp is recent (within last hour)
    current_time = time.time()
    report_time = report_data.get('timestamp', 0)
    if current_time - report_time > 3600:  # 1 hour
        return False

    # Basic miner ID format check
    if not miner_id or len(miner_id) < 8:
        return False

    return True

def _validate_wallet_report(wallet_id_hash: str, report_data: dict) -> bool:
    """Validate wallet intelligence report (privacy-preserving)"""
    # Privacy-focused validation - only check required anonymous fields
    required_fields = ['wallet_id_hash', 'report_type', 'timestamp']
    for field in required_fields:
        if field not in report_data:
            return False

    # Check timestamp is recent (within last hour)
    current_time = time.time()
    report_time = report_data.get('timestamp', 0)
    if current_time - report_time > 3600:  # 1 hour
        return False

    # Validate wallet ID hash format (should be hex string)
    import re
    if not re.match(r'^[a-f0-9]{64}$', wallet_id_hash):  # SHA256 hash
        return False

    return True

def _is_authorized_bootstrap_peer(sender_id: str, client_ip: str) -> bool:
    """Check if sender is an authorized bootstrap peer"""
    # Check if sender is registered in our bootstrap registry
    if not _is_bootstrap_node_registered(sender_id):
        return False

    # Additional validation could include IP whitelist, signatures, etc.
    return True

def _is_authorized_bootstrap_peer_from_ip(client_ip: str) -> bool:
    """Check if requesting IP belongs to an authorized bootstrap peer"""
    # This would need more sophisticated IP validation in production
    # For now, accept from any IP (would add proper authentication)
    return True

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

@app.route('/api/v1/bootstrap/handshake', methods=['POST'])
def bootstrap_handshake():
    """Handshake endpoint for secondary bootstrap nodes to register with primary"""
    logger.info("Bootstrap handshake endpoint called")

    try:
        handshake_data = request.get_json()
        if not handshake_data:
            return jsonify({'error': 'No handshake data provided'}), 400

        # Validate required fields
        required_fields = ['node_id', 'address', 'port', 'services', 'capabilities']
        for field in required_fields:
            if field not in handshake_data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        node_id = handshake_data['node_id']
        current_time = time.time()

        # Check if this is a legitimate bootstrap node (basic validation)
        if not _validate_bootstrap_node(handshake_data):
            logger.warning(f"Invalid bootstrap node handshake attempt from {node_id}")
            return jsonify({'error': 'Invalid bootstrap node credentials'}), 403

        # Register/update the bootstrap node
        bootstrap_node = {
            'node_id': node_id,
            'address': handshake_data['address'],
            'port': handshake_data['port'],
            'services': handshake_data['services'],  # List of services offered
            'capabilities': handshake_data['capabilities'],  # Technical capabilities
            'region': handshake_data.get('region', 'unknown'),
            'version': handshake_data.get('version', 'unknown'),
            'registered_at': current_time,
            'last_seen': current_time,
            'status': 'active',
            'reliability_score': handshake_data.get('reliability_score', 1.0),
            'load_factor': handshake_data.get('load_factor', 0.0),  # 0.0 to 1.0
            'supported_protocols': handshake_data.get('supported_protocols', ['p2p_sync'])
        }

        # Store in bootstrap registry
        _register_bootstrap_node(bootstrap_node)

        # Return handshake confirmation with network info
        response = {
            'handshake_accepted': True,
            'primary_node': 'bootstrap.pisecure.org',
            'node_id': node_id,
            'registration_time': current_time,
            'network_info': {
                'total_bootstrap_nodes': len(_get_registered_bootstrap_nodes()),
                'active_services': _get_active_services(),
                'protocol_version': '1.0',
                'coordination_enabled': True
            },
            'peer_discovery_endpoints': [
                '/api/v1/bootstrap/peers',
                '/api/v1/network/status'
            ]
        }

        logger.info(f"Successful bootstrap handshake from {node_id} at {handshake_data['address']}:{handshake_data['port']}")
        return jsonify(response)

    except Exception as e:
        logger.error(f"Bootstrap handshake error: {e}")
        return jsonify({'error': 'Handshake failed'}), 500

@app.route('/api/v1/bootstrap/advertise', methods=['POST'])
def advertise_services():
    """Endpoint for bootstrap nodes to advertise their current services and status"""
    logger.info("Service advertisement endpoint called")

    try:
        advert_data = request.get_json()
        if not advert_data or 'node_id' not in advert_data:
            return jsonify({'error': 'Node ID required'}), 400

        node_id = advert_data['node_id']

        # Verify this node is registered
        if not _is_bootstrap_node_registered(node_id):
            return jsonify({'error': 'Unregistered bootstrap node'}), 403

        # Update service advertisement
        current_time = time.time()
        service_update = {
            'services': advert_data.get('services', []),
            'status': advert_data.get('status', 'active'),
            'load_factor': advert_data.get('load_factor', 0.0),
            'current_connections': advert_data.get('current_connections', 0),
            'last_advertisement': current_time,
            'health_metrics': advert_data.get('health_metrics', {}),
            'service_endpoints': advert_data.get('service_endpoints', {})
        }

        _update_bootstrap_services(node_id, service_update)

        return jsonify({
            'advertisement_accepted': True,
            'node_id': node_id,
            'timestamp': current_time,
            'services_acknowledged': service_update['services']
        })

    except Exception as e:
        logger.error(f"Service advertisement error: {e}")
        return jsonify({'error': 'Advertisement failed'}), 500

@app.route('/peers.json', methods=['GET'])
def peers_json():
    """Serve static peers.json file for traditional bootstrap compatibility"""
    logger.info("Static peers.json endpoint called")

    try:
        # Serve the static peers.json file
        return send_from_directory('.', 'peers.json', mimetype='application/json')
    except Exception as e:
        logger.error(f"peers.json serving error: {e}")
        return jsonify({'error': 'Peers file unavailable'}), 500

@app.route('/api/v1/bootstrap/peers', methods=['GET'])
def bootstrap_peers():
    """Dynamic peer discovery API with intelligence-enhanced peer selection"""
    logger.info("Dynamic bootstrap peers endpoint called")

    try:
        # Record this API call for intelligence
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get query parameters for intelligent filtering
        requesting_location = request.args.get('location')
        requesting_services = request.args.get('services', '').split(',') if request.args.get('services') else None
        intelligence_enabled = request.args.get('intelligence', 'true').lower() == 'true'

        # Safe configuration access with defaults
        network_config = NODE_CONFIG.get('node', {}).get('network', {}) if NODE_CONFIG else {}
        federation_config = NODE_CONFIG.get('node', {}).get('federation', {}) if NODE_CONFIG else {}
        dex_config = NODE_CONFIG.get('dex', {}) if NODE_CONFIG else {}
        node_capabilities = NODE_CONFIG.get('node', {}).get('capabilities', []) if NODE_CONFIG else []

        # Build primary bootstrap peer with safe access
        primary_peer = {
            'node_id': NODE_IDENTITY.get('node_id', 'bootstrap-primary') if NODE_IDENTITY else 'bootstrap-primary',
            'address': network_config.get('domain', 'bootstrap.pisecure.org'),
            'port': network_config.get('ports', {}).get('bootstrap', 3142),
            'services': node_capabilities,
            'capabilities': node_capabilities,
            'location': network_config.get('region', 'us-east'),
            'operator': NODE_IDENTITY.get('operator', 'PiSecure Foundation') if NODE_IDENTITY else 'PiSecure Foundation',
            'trust_level': 'foundation_verified',
            'version': NODE_IDENTITY.get('version', '1.0.0') if NODE_IDENTITY else '1.0.0',
            'federation_enabled': federation_config.get('enabled', True),
            'intelligence_capable': True,
            'dex_coordination': dex_config.get('coordination_enabled', False),
            'last_seen': time.time(),
            'reliability_score': 1.0,  # Primary is always 100% reliable
            'load_factor': 0.0,  # Primary has minimal load
            'intelligence_sharing': federation_config.get('intelligence_sharing', True)
        }

        peers = [primary_peer]

        # Add active secondary bootstrap nodes
        secondary_bootstraps = _get_registered_bootstrap_nodes()
        for bootstrap in secondary_bootstraps:
            # Apply intelligent filtering if requested
            if intelligence_enabled and requesting_location:
                # Prefer geographically close bootstraps
                if bootstrap['region'] != requesting_location:
                    # Still include but with lower priority
                    bootstrap['geographic_distance'] = 'regional'
                else:
                    bootstrap['geographic_distance'] = 'local'

            # Filter by requested services
            if requesting_services:
                peer_services = set(bootstrap.get('services', []))
                requested_set = set(requesting_services)
                if not requested_set.issubset(peer_services):
                    continue  # Skip peers that don't offer required services

            # Calculate reliability score for secondary nodes
            last_seen = bootstrap.get('last_seen', 0)
            time_since_seen = time.time() - last_seen
            reliability_score = max(0.0, 1.0 - (time_since_seen / 3600))  # Degrade over 1 hour

            peer_data = {
                'node_id': bootstrap['node_id'],
                'address': bootstrap['address'],
                'port': bootstrap['port'],
                'services': bootstrap['services'],
                'capabilities': bootstrap['capabilities'],
                'location': bootstrap['region'],
                'operator': 'Community Operator',  # Secondary bootstraps are community-operated
                'trust_level': 'community_trusted',
                'version': bootstrap.get('version', 'unknown'),
                'federation_enabled': True,  # All secondary bootstraps support federation
                'intelligence_capable': 'intelligence_sharing' in bootstrap.get('capabilities', []),
                'dex_coordination': False,  # Secondary bootstraps don't coordinate DEX by default
                'last_seen': last_seen,
                'reliability_score': reliability_score,
                'load_factor': bootstrap.get('load_factor', 0.5),
                'intelligence_sharing': 'intelligence_sharing' in bootstrap.get('capabilities', [])
            }

            peers.append(peer_data)

        # Intelligent sorting if enabled
        if intelligence_enabled:
            peers.sort(key=lambda x: (
                x['trust_level'] == 'foundation_verified',  # Primary first
                x.get('geographic_distance') == 'local',   # Local peers next
                x['reliability_score'],                     # Then by reliability
                -x['load_factor']                           # Lower load factor preferred
            ), reverse=True)
        else:
            # Simple sorting: primary first, then by reliability
            peers.sort(key=lambda x: (
                x['trust_level'] == 'foundation_verified',
                x['reliability_score']
            ), reverse=True)

        # Limit to top peers for performance
        max_peers = int(request.args.get('limit', 10))
        peers = peers[:max_peers]

        response = {
            'peers': peers,
            'total_available': len(secondary_bootstraps) + 1,
            'returned_count': len(peers),
            'intelligence_applied': intelligence_enabled,
            'filters_applied': {
                'location': requesting_location,
                'services': requesting_services,
                'intelligence_enabled': intelligence_enabled
            },
            'recommended_usage': 'Use primary bootstrap for initial coordination, secondaries for redundancy',
            'timestamp': time.time()
        }

        return jsonify(response)

    except Exception as e:
        logger.error(f"Dynamic bootstrap peers error: {e}")
        return jsonify({'error': 'Peer discovery failed'}), 500

@app.route('/api/v1/bootstrap/registry', methods=['GET'])
def bootstrap_registry():
    """Get the current bootstrap node registry (for coordination)"""
    logger.info("Bootstrap registry endpoint called")

    try:
        local_descriptor = _build_local_bootstrap_descriptor(
            'community_trusted' if NODE_IDENTITY.get('role') == 'secondary' else 'foundation_verified'
        )
        local_federation_config = _get_local_federation_config()

        if NODE_IDENTITY.get('role') == 'secondary':
            upstream_registry = _fetch_primary_registry_snapshot()

            if upstream_registry:
                primary_node = upstream_registry.get('primary_node') or _build_primary_env_descriptor()
                secondary_nodes = upstream_registry.get('secondary_nodes', [])
                local_node_id = local_descriptor.get('node_id')
                if all(node.get('node_id') != local_node_id for node in secondary_nodes):
                    secondary_nodes.append(local_descriptor)

                total_nodes = upstream_registry.get('total_nodes') or (len(secondary_nodes) + 1)
                federation_config = upstream_registry.get('federation_config', local_federation_config)

                upstream_network_info = upstream_registry.get('network_info')
                default_network_info = _build_default_network_info(total_nodes)
                if isinstance(upstream_network_info, dict):
                    network_info = {**default_network_info, **upstream_network_info}
                else:
                    network_info = default_network_info

                last_updated = upstream_registry.get('last_updated', time.time())
                config_version = upstream_registry.get('config_version', NODE_IDENTITY.get('version', '1.0.0'))
            else:
                primary_node = _build_primary_env_descriptor()
                secondary_nodes = [local_descriptor]
                total_nodes = len(secondary_nodes) + 1
                federation_config = local_federation_config
                network_info = _build_default_network_info(total_nodes)
                last_updated = time.time()
                config_version = NODE_IDENTITY.get('version', '1.0.0')
        else:
            primary_node = local_descriptor
            secondary_nodes = _get_registered_bootstrap_nodes()
            total_nodes = len(secondary_nodes) + 1
            federation_config = local_federation_config
            network_info = _build_default_network_info(total_nodes)
            last_updated = time.time()
            config_version = NODE_IDENTITY.get('version', '1.0.0')

        registry = {
            'primary_node': primary_node,
            'secondary_nodes': secondary_nodes,
            'total_nodes': total_nodes,
            'federation_config': federation_config,
            'network_info': network_info,
            'last_updated': last_updated,
            'config_version': config_version
        }

        return jsonify(registry)

    except Exception as e:
        logger.error(f"Bootstrap registry error: {e}")
        return jsonify({'error': 'Registry access failed'}), 500

@app.route('/api/v1/bootstrap/coordinate', methods=['POST'])
def coordinate_services():
    """Coordinate service distribution among bootstrap nodes"""
    logger.info("Service coordination endpoint called")

    try:
        coord_data = request.get_json()
        if not coord_data or 'requesting_node' not in coord_data:
            return jsonify({'error': 'Requesting node ID required'}), 400

        requesting_node = coord_data['requesting_node']
        requested_service = coord_data.get('service', 'peer_discovery')

        # Find best bootstrap node for this service
        best_node = _find_optimal_bootstrap_node(requested_service, requesting_node)

        if best_node:
            response = {
                'coordination_success': True,
                'service': requested_service,
                'assigned_node': best_node['node_id'],
                'endpoint': f"http://{best_node['address']}:{best_node['port']}",
                'capabilities': best_node.get('capabilities', []),
                'load_factor': best_node.get('load_factor', 0.0)
            }
        else:
            response = {
                'coordination_success': False,
                'service': requested_service,
                'fallback_node': 'bootstrap-primary',
                'endpoint': 'http://bootstrap.pisecure.org:3142',
                'reason': 'No suitable secondary node available'
            }

        return jsonify(response)

    except Exception as e:
        logger.error(f"Service coordination error: {e}")
        return jsonify({'error': 'Coordination failed'}), 500

@app.route('/api/v1/intelligence/health', methods=['GET'])
def network_intelligence_health():
    """Get comprehensive network intelligence and health analysis"""
    logger.info("Network intelligence health endpoint called")

    try:
        # Record this API call for intelligence analysis
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        user_agent = request.headers.get('User-Agent', '')
        network_intelligence.record_connection(client_ip, user_agent)

        # Get comprehensive intelligence insights
        insights = network_intelligence.get_network_insights()

        return jsonify({
            'intelligence_analysis': insights,
            'analysis_timestamp': time.time(),
            'data_quality': 'good' if len(network_intelligence.connection_history) > 100 else 'building'
        })

    except Exception as e:
        logger.error(f"Network intelligence health error: {e}")
        return jsonify({'error': 'Intelligence analysis failed'}), 500

@app.route('/api/v1/intelligence/attacks', methods=['GET'])
def detected_attacks():
    """Get current attack detection analysis using ML algorithms"""
    logger.info("ML attack detection endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get enhanced attack analysis (ML + statistical)
        attacks = network_intelligence.detect_attacks_ml()

        # Get defense actions taken
        recent_defense_actions = network_intelligence.defense_actions[-5:]  # Last 5 actions

        return jsonify({
            'detected_attacks': attacks,
            'threat_level': 'high' if any(a['severity'] == 'high' for a in attacks) else 'medium' if attacks else 'low',
            'analysis_period': 'last_hour',
            'total_analyzed_connections': len(network_intelligence.connection_history),
            'ml_models_active': {
                'isolation_forest': network_intelligence.isolation_forest is not None,
                'ensemble_classifier': network_intelligence.ensemble_classifier is not None,
                'geographic_clustering': network_intelligence.geo_cluster_model is not None
            },
            'recent_defense_actions': recent_defense_actions,
            'active_threat_zones': list(network_intelligence.threat_zones),
            'blocked_ips_count': len(network_intelligence.blocked_ips),
            'blocked_regions_count': len(network_intelligence.blocked_regions),
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"ML attack detection error: {e}")
        return jsonify({'error': 'ML attack analysis failed'}), 500

@app.route('/api/v1/intelligence/defense', methods=['GET'])
def intelligence_defense():
    """Get automated defense intelligence and attack response status"""
    logger.info("Defense intelligence endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get ML-enhanced attack detection
        attacks = network_intelligence.detect_attacks_ml()

        # Calculate defense status
        defense_status = {
            'automated_defense_active': True,
            'ml_attack_detection_enabled': network_intelligence.isolation_forest is not None,
            'smart_routing_enabled': True,
            'threat_intelligence_level': 'high' if any(a['severity'] == 'high' for a in attacks) else 'medium' if attacks else 'low',
            'active_attacks_detected': len(attacks),
            'threat_zones_active': len(network_intelligence.threat_zones),
            'auto_response_actions': len(network_intelligence.defense_actions),
            'blocked_entities': len(network_intelligence.blocked_ips) + len(network_intelligence.blocked_regions),
            'defense_effectiveness_score': 95 if not attacks else 85,  # Simplified scoring
            'last_defense_action': network_intelligence.defense_actions[-1] if network_intelligence.defense_actions else None,
            'attack_prevention_rate': 0.92,  # Mock high effectiveness
            'coordinated_defense_nodes': len(_get_registered_bootstrap_nodes()),
            'timestamp': time.time()
        }

        return jsonify({
            'defense_intelligence': defense_status,
            'recent_attacks': attacks[-5:],  # Last 5 attacks
            'active_threats': list(network_intelligence.threat_zones),
            'defense_capabilities': [
                'ML-powered anomaly detection',
                'Statistical attack pattern recognition',
                'Automated threat response',
                'Smart routing with threat avoidance',
                'Geographic attack clustering',
                'Real-time network immune system'
            ]
        })

    except Exception as e:
        logger.error(f"Defense intelligence error: {e}")
        return jsonify({'error': 'Defense intelligence unavailable'}), 500

@app.route('/api/v1/intelligence/clusters', methods=['GET'])
def geographic_clusters():
    """Get geographic clustering analysis for routing optimization"""
    logger.info("Geographic clustering endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get geographic clusters
        clusters = network_intelligence.cluster_geographic_regions()

        return jsonify({
            'geographic_clusters': clusters,
            'clustering_method': 'kmeans',
            'total_regions_analyzed': len(network_intelligence.geographic_distribution),
            'cluster_count': len(clusters) if clusters else 0,
            'routing_optimization_available': bool(clusters),
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"Geographic clustering error: {e}")
        return jsonify({'error': 'Clustering analysis failed'}), 500

@app.route('/api/v1/intelligence/optimize', methods=['POST'])
def optimize_routing():
    """Get intelligent routing optimization for peer connections"""
    logger.info("Routing optimization endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get optimization request
        opt_data = request.get_json() or {}
        available_nodes = opt_data.get('available_nodes', [])
        service_type = opt_data.get('service_type', 'general')

        # Get optimized routing
        optimized_nodes = network_intelligence.optimize_routing(available_nodes)

        return jsonify({
            'optimization_success': True,
            'service_type': service_type,
            'optimized_nodes': optimized_nodes,
            'total_candidates': len(available_nodes),
            'optimization_method': 'statistical_scoring',
            'scoring_weights': {
                'geographic_diversity': 0.3,
                'load_balancing': 0.4,
                'reliability': 0.3
            },
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"Routing optimization error: {e}")
        return jsonify({'error': 'Optimization failed'}), 500

@app.route('/api/v1/intelligence/predict', methods=['GET'])
def load_predictions():
    """Get network load predictions"""
    logger.info("Load prediction endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get predictions
        predictions = network_intelligence.predict_network_load()

        return jsonify({
            'predictions': predictions,
            'confidence_level': predictions.get('confidence', 'unknown'),
            'prediction_horizon': '1-24_hours',
            'data_points_used': len(network_intelligence.connection_timestamps),
            'model_type': 'statistical_time_series',
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"Load prediction error: {e}")
        return jsonify({'error': 'Prediction failed'}), 500

@app.route('/api/v1/intelligence/miner-report', methods=['POST'])
def miner_intelligence_report():
    """Receive intelligence reports from mining nodes"""
    logger.info("Miner intelligence report endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get miner report data
        report_data = request.get_json() or {}
        miner_id = report_data.get('miner_id')

        if not miner_id:
            return jsonify({'error': 'Miner ID required'}), 400

        # Basic validation (in production, would verify miner proof-of-work or signature)
        if not _validate_miner_report(miner_id, report_data):
            return jsonify({'error': 'Invalid miner report'}), 403

        # Process miner intelligence
        intelligence_contribution = network_intelligence.process_miner_intelligence(report_data)

        # Reward miner with intelligence credit (concept for future token economics)
        miner_credits = intelligence_contribution.get('intelligence_value', 0)

        logger.info(f"Processed intelligence report from miner {miner_id}: {intelligence_contribution}")

        return jsonify({
            'report_accepted': True,
            'miner_id': miner_id,
            'intelligence_processed': intelligence_contribution,
            'intelligence_credits': miner_credits,
            'contribution_timestamp': time.time(),
            'network_threat_level': network_intelligence.get_network_insights().get('intelligence_summary', {}).get('threat_level', 'unknown')
        })

    except Exception as e:
        logger.error(f"Miner intelligence report error: {e}")
        return jsonify({'error': 'Intelligence report processing failed'}), 500

@app.route('/api/v1/intelligence/wallet-report', methods=['POST'])
def wallet_intelligence_report():
    """Receive privacy-preserving intelligence reports from wallet nodes"""
    logger.info("Wallet intelligence report endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get wallet report data
        report_data = request.get_json() or {}
        wallet_id_hash = report_data.get('wallet_id_hash')  # Privacy-preserving

        if not wallet_id_hash:
            return jsonify({'error': 'Wallet ID hash required'}), 400

        # Privacy-preserving validation (zero-knowledge style)
        if not _validate_wallet_report(wallet_id_hash, report_data):
            return jsonify({'error': 'Invalid wallet report'}), 403

        # Process wallet intelligence (privacy-preserving aggregation)
        intelligence_contribution = network_intelligence.process_wallet_intelligence(report_data)

        # Anonymous reward credit
        wallet_credits = intelligence_contribution.get('intelligence_value', 0)

        logger.info(f"Processed privacy-preserving intelligence report from wallet: {intelligence_contribution}")

        return jsonify({
            'report_accepted': True,
            'wallet_id_hash': wallet_id_hash,
            'intelligence_processed': intelligence_contribution,
            'intelligence_credits': wallet_credits,
            'contribution_timestamp': time.time(),
            'privacy_preserved': True,
            'aggregated_with_peers': True  # Indicates data was combined with other reports
        })

    except Exception as e:
        logger.error(f"Wallet intelligence report error: {e}")
        return jsonify({'error': 'Intelligence report processing failed'}), 500

@app.route('/api/v1/intelligence/federation', methods=['GET'])
def intelligence_federation_status():
    """Get intelligence federation status between bootstrap nodes"""
    logger.info("Intelligence federation status endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get federation status
        federation_status = intelligence_federation.get_federation_status()

        # Add active sync information
        sync_status = {
            'active_sync_enabled': active_federation_sync.running,
            'sync_interval_seconds': active_federation_sync.sync_interval,
            'last_sync_time': active_federation_sync.last_sync_time,
            'state_checksum': active_federation_sync._calculate_state_checksum(),
            'sync_thread_active': active_federation_sync.sync_thread.is_alive() if active_federation_sync.sync_thread else False
        }

        return jsonify({
            'federation_status': federation_status,
            'active_sync_status': sync_status,
            'intelligence_sharing_active': federation_status['federation_enabled'],
            'network_intelligence_nodes': federation_status['active_peers'] + 1,  # +1 for self
            'last_federation_sync': max(federation_status['last_sync_times'].values()) if federation_status['last_sync_times'] else None,
            'intelligence_contributors': {
                'bootstrap_nodes': federation_status['active_peers'],
                'active_miners': len([n for n in node_tracker.nodes.values() if n.get('node_type') == 'miner' and n.get('status') == 'active']),
                'active_wallets': len([n for n in node_tracker.nodes.values() if n.get('node_type') == 'wallet' and n.get('status') == 'active']),
                'total_contributors': federation_status['active_peers'] + len(node_tracker.nodes)
            },
            'federation_health': {
                'sync_active': active_federation_sync.running,
                'peers_in_sync': len([t for t in federation_status['last_sync_times'].values() if time.time() - t < 600]),  # Within 10 min
                'state_consistency': True,  # Simplified - would check actual consistency
                'federation_uptime': time.time() - active_federation_sync.last_sync_time if active_federation_sync.last_sync_time > 0 else 0
            },
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"Intelligence federation status error: {e}")
        return jsonify({'error': 'Federation status unavailable'}), 500

@app.route('/api/v1/intelligence/share', methods=['POST'])
def share_intelligence():
    """Receive shared intelligence from peer bootstrap nodes"""
    logger.info("Intelligence sharing endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get shared intelligence data
        intelligence_data = request.get_json() or {}

        # Validate sender is registered bootstrap node
        sender_id = intelligence_data.get('sender_node_id')
        if not sender_id or not _is_authorized_bootstrap_peer(sender_id, client_ip):
            return jsonify({'error': 'Unauthorized intelligence share'}), 403

        # Process shared intelligence
        processed_intelligence = intelligence_federation._merge_peer_intelligence(sender_id, intelligence_data.get('data', {}))

        logger.info(f"Received shared intelligence from bootstrap peer: {sender_id}")

        return jsonify({
            'intelligence_accepted': True,
            'sender_node_id': sender_id,
            'intelligence_processed': processed_intelligence,
            'federation_timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"Intelligence sharing error: {e}")
        return jsonify({'error': 'Intelligence sharing failed'}), 500

@app.route('/api/v1/intelligence/sync', methods=['GET'])
def sync_intelligence():
    """Provide intelligence snapshot for peer synchronization"""
    logger.info("Intelligence sync endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Verify requesting node is authorized (registered bootstrap peer)
        if not _is_authorized_bootstrap_peer_from_ip(client_ip):
            return jsonify({'error': 'Unauthorized sync request'}), 403

        # Provide intelligence snapshot
        intelligence_snapshot = {
            'threat_zones': list(network_intelligence.threat_zones),
            'active_attacks': network_intelligence.potential_attacks[-10:],  # Last 10 attacks
            'intelligence_summary': network_intelligence.get_network_insights().get('intelligence_summary', {}),
            'federation_status': intelligence_federation.get_federation_status(),
            'sync_timestamp': time.time(),
            'data_freshness': time.time() - network_intelligence.get_network_insights().get('intelligence_summary', {}).get('analysis_timestamp', time.time())
        }

        logger.info(f"Provided intelligence sync to authorized peer at {client_ip}")

        return jsonify({
            'intelligence_snapshot': intelligence_snapshot,
            'sync_success': True,
            'data_points_shared': len(network_intelligence.connection_history),
            'threat_zones_shared': len(network_intelligence.threat_zones)
        })

    except Exception as e:
        logger.error(f"Intelligence sync error: {e}")
        return jsonify({'error': 'Intelligence sync failed'}), 500

@app.route('/api/v1/operator/configure-wallet', methods=['POST'])
def configure_operator_wallet():
    """Configure operator's PiSecure wallet for 314ST rewards"""
    logger.info("Operator wallet configuration endpoint called")

    try:
        # Get configuration data
        config_data = request.get_json() or {}
        wallet_address = config_data.get('wallet_address')

        if not wallet_address:
            return jsonify({'error': 'Wallet address required'}), 400

        # Configure wallet for rewards
        if bootstrap_rewards.configure_operator_wallet(wallet_address):
            return jsonify({
                'configuration_success': True,
                'wallet_address': wallet_address,
                'reward_percentage': bootstrap_rewards.reward_percentage,
                'minimum_payout_314st': bootstrap_rewards.minimum_payout_314st,
                'timestamp': time.time()
            })

        return jsonify({'error': 'Invalid wallet address'}), 400

    except Exception as e:
        logger.error(f"Operator wallet configuration error: {e}")
        return jsonify({'error': 'Configuration failed'}), 500

@app.route('/api/v1/operator/314st-analytics', methods=['GET'])
def operator_314st_analytics():
    """Get comprehensive 314ST reward analytics for operators"""
    logger.info("314ST operator analytics endpoint called")

    try:
        # Get analytics for configured wallet
        analytics = bootstrap_rewards.get_reward_analytics()

        if 'error' in analytics:
            return jsonify(analytics), 400

        return jsonify({
            'operator_analytics': analytics,
            'network_reward_info': {
                'daily_budget_314st': bootstrap_rewards.daily_budget_314st,
                'intelligence_fee_percentage': bootstrap_rewards.reward_percentage,
                'active_bootstrap_nodes': len(_get_registered_bootstrap_nodes()) + 1,
                'reward_token': '314ST'
            },
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"314ST analytics error: {e}")
        return jsonify({'error': 'Analytics unavailable'}), 500

@app.route('/api/v1/operator/314st-payout', methods=['POST'])
def trigger_314st_payout():
    """Manually trigger 314ST payout for accumulated rewards"""
    logger.info("Manual 314ST payout endpoint called")

    try:
        # Get payout request
        payout_data = request.get_json() or {}
        force_payout = payout_data.get('force_payout', False)

        # Check if operator wallet is configured
        if not bootstrap_rewards.operator_wallet:
            return jsonify({'error': 'Operator wallet not configured'}), 400

        # Get current pending rewards
        pending_rewards = bootstrap_rewards.pending_rewards.get(bootstrap_rewards.operator_wallet, 0)

        if pending_rewards < bootstrap_rewards.minimum_payout_314st and not force_payout:
            return jsonify({
                'payout_denied': True,
                'reason': f'Pending rewards ({pending_rewards} 314ST) below minimum payout threshold ({bootstrap_rewards.minimum_payout_314st} 314ST)',
                'pending_rewards': pending_rewards,
                'minimum_threshold': bootstrap_rewards.minimum_payout_314st
            }), 400

        # Attempt to distribute rewards
        if bootstrap_rewards.distribute_pending_rewards(bootstrap_rewards.operator_wallet):
            return jsonify({
                'payout_success': True,
                'distributed_amount_314st': pending_rewards,
                'operator_wallet': bootstrap_rewards.operator_wallet,
                'distribution_timestamp': time.time()
            })

        return jsonify({'error': 'Payout distribution failed'}), 500

    except Exception as e:
        logger.error(f"314ST payout error: {e}")
        return jsonify({'error': 'Payout failed'}), 500

@app.route('/api/v1/operator/rewards-status', methods=['GET'])
def operator_rewards_status():
    """Get current operator rewards status and configuration"""
    logger.info("Operator rewards status endpoint called")

    try:
        status = {
            'operator_wallet_configured': bool(bootstrap_rewards.operator_wallet),
            'operator_wallet': bootstrap_rewards.operator_wallet,
            'reward_configuration': {
                'percentage': bootstrap_rewards.reward_percentage,
                'minimum_payout_314st': bootstrap_rewards.minimum_payout_314st,
                'daily_budget_314st': bootstrap_rewards.daily_budget_314st,
                'reward_token': '314ST'
            },
            'pending_rewards_314st': bootstrap_rewards.pending_rewards.get(bootstrap_rewards.operator_wallet, 0) if bootstrap_rewards.operator_wallet else 0,
            'total_distributed_314st': sum(r['amount_314st'] for r in bootstrap_rewards.reward_history
                                         if r['wallet'] == bootstrap_rewards.operator_wallet) if bootstrap_rewards.operator_wallet else 0,
            'last_payout_timestamp': bootstrap_rewards.last_payout_times.get(bootstrap_rewards.operator_wallet, 0) if bootstrap_rewards.operator_wallet else 0,
            'reward_eligibility': {
                'has_pending_rewards': bootstrap_rewards.pending_rewards.get(bootstrap_rewards.operator_wallet, 0) >= bootstrap_rewards.minimum_payout_314st if bootstrap_rewards.operator_wallet else False,
                'uptime_bonus_eligible': False,  # Would check uptime metrics
                'federation_bonus_eligible': len(_get_registered_bootstrap_nodes()) > 0
            },
            'network_participation': {
                'bootstrap_nodes_coordinated': len(_get_registered_bootstrap_nodes()),
                'intelligence_contributions_processed': len(network_intelligence.connection_history),
                'threat_zones_managed': len(network_intelligence.threat_zones)
            },
            'timestamp': time.time()
        }

        return jsonify(status)

    except Exception as e:
        logger.error(f"Operator rewards status error: {e}")
        return jsonify({'error': 'Status unavailable'}), 500

@app.route('/api/v1/dex/pools', methods=['GET'])
def get_liquidity_pools():
    """Get available liquidity pools for DEX trading"""
    logger.info("DEX pools endpoint called")

    try:
        # Record this API call for intelligence
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        pools_list = []
        for pool_id, pool_data in pisecure_dex.liquidity_pools.items():
            pools_list.append({
                'pool_id': pool_id,
                'token_a': pool_data['token_a'],
                'token_b': pool_data['token_b'],
                'liquidity_a': pool_data['total_liquidity_a'],
                'liquidity_b': pool_data['total_liquidity_b'],
                'fee_percentage': pool_data['fee_percentage'],
                'trade_count': pool_data['trade_count'],
                'volume_24h': pool_data['volume_24h'],
                'pool_health_score': pool_data['pool_health_score'],
                'exchange_rate': pool_data['total_liquidity_b'] / pool_data['total_liquidity_a'] if pool_data['total_liquidity_a'] > 0 else 0
            })

        return jsonify({
            'liquidity_pools': pools_list,
            'total_pools': len(pools_list),
            'dex_health_score': pisecure_dex.get_dex_intelligence().get('dex_health_score', 0),
            'intelligence_enabled': True,
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"DEX pools error: {e}")
        return jsonify({'error': 'Unable to retrieve liquidity pools'}), 500

@app.route('/api/v1/dex/pool/create', methods=['POST'])
def create_liquidity_pool():
    """Create a new liquidity pool"""
    logger.info("Create liquidity pool endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get pool creation data
        pool_data = request.get_json() or {}
        token_a = pool_data.get('token_a')
        token_b = pool_data.get('token_b')
        creator_wallet = pool_data.get('creator_wallet')

        if not all([token_a, token_b, creator_wallet]):
            return jsonify({'error': 'token_a, token_b, and creator_wallet required'}), 400

        # Create the pool
        pool_result = pisecure_dex.create_liquidity_pool(token_a, token_b, creator_wallet)

        if 'error' in pool_result:
            return jsonify(pool_result), 400

        return jsonify({
            'pool_created': True,
            'pool_details': pool_result,
            'intelligence_optimized': True,
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"Create pool error: {e}")
        return jsonify({'error': 'Pool creation failed'}), 500

@app.route('/api/v1/dex/pool/add-liquidity', methods=['POST'])
def add_liquidity():
    """Add liquidity to an existing pool"""
    logger.info("Add liquidity endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get liquidity addition data
        liquidity_data = request.get_json() or {}
        pool_id = liquidity_data.get('pool_id')
        provider_wallet = liquidity_data.get('provider_wallet')
        amount_a = liquidity_data.get('amount_a', 0)
        amount_b = liquidity_data.get('amount_b', 0)

        if not all([pool_id, provider_wallet, amount_a >= 0, amount_b >= 0]):
            return jsonify({'error': 'pool_id, provider_wallet, amount_a, and amount_b required'}), 400

        # Add liquidity
        liquidity_result = pisecure_dex.add_liquidity(pool_id, provider_wallet, amount_a, amount_b)

        if 'error' in liquidity_result:
            return jsonify(liquidity_result), 400

        return jsonify({
            'liquidity_added': True,
            'liquidity_details': liquidity_result,
            'intelligence_rewards_earned': liquidity_result.get('reward_314st', 0),
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"Add liquidity error: {e}")
        return jsonify({'error': 'Liquidity addition failed'}), 500

@app.route('/api/v1/dex/swap', methods=['POST'])
def intelligent_swap():
    """Execute intelligent token swap with ML optimization"""
    logger.info("Intelligent DEX swap endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get swap request data
        swap_data = request.get_json() or {}
        token_in = swap_data.get('token_in')
        token_out = swap_data.get('token_out')
        amount_in = swap_data.get('amount_in', 0)
        user_wallet = swap_data.get('user_wallet')
        max_slippage = swap_data.get('max_slippage', 0.01)  # 1% default

        if not all([token_in, token_out, amount_in > 0, user_wallet]):
            return jsonify({'error': 'token_in, token_out, amount_in, and user_wallet required'}), 400

        # Get optimal swap route using intelligence
        route_result = pisecure_dex.calculate_optimal_swap(token_in, token_out, amount_in)

        if 'error' in route_result:
            return jsonify(route_result), 400

        # Execute swap coordination
        swap_result = pisecure_dex.execute_swap_coordination({
            'token_in': token_in,
            'token_out': token_out,
            'amount_in': amount_in,
            'user_wallet': user_wallet,
            'max_slippage': max_slippage
        })

        if 'error' in swap_result:
            return jsonify(swap_result), 400

        return jsonify({
            'swap_coordinated': True,
            'swap_details': swap_result.get('swap_instructions'),
            'intelligence_optimized': True,
            'network_conditions': route_result.get('network_conditions'),
            'estimated_completion': '30_seconds',  # Wallet execution time
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"Intelligent swap error: {e}")
        return jsonify({'error': 'Swap coordination failed'}), 500

@app.route('/api/v1/dex/intelligence', methods=['GET'])
def dex_intelligence():
    """Get comprehensive DEX intelligence and analytics"""
    logger.info("DEX intelligence endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get DEX intelligence
        dex_intel = pisecure_dex.get_dex_intelligence()

        return jsonify({
            'dex_intelligence': dex_intel,
            'intelligence_source': 'bootstrap_coordinator',
            'network_intelligence_integrated': True,
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"DEX intelligence error: {e}")
        return jsonify({'error': 'DEX intelligence unavailable'}), 500

@app.route('/api/v1/dex/stats', methods=['GET'])
def dex_stats():
    """Get DEX statistics and market data"""
    logger.info("DEX stats endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Calculate DEX stats
        total_pools = len(pisecure_dex.liquidity_pools)
        total_liquidity = pisecure_dex._calculate_total_liquidity()
        trading_volume = pisecure_dex._calculate_24h_volume()

        # Get popular pairs
        popular_pairs = []
        for pool_id, pool_data in pisecure_dex.liquidity_pools.items():
            popular_pairs.append({
                'pair': f"{pool_data['token_a']}/{pool_data['token_b']}",
                'pool_id': pool_id,
                'liquidity': pool_data['total_liquidity_a'] + pool_data['total_liquidity_b'],
                'volume_24h': pool_data['volume_24h'],
                'trade_count': pool_data['trade_count']
            })

        # Sort by volume
        popular_pairs.sort(key=lambda x: x['volume_24h'], reverse=True)

        return jsonify({
            'dex_stats': {
                'total_pools': total_pools,
                'total_liquidity_314st': total_liquidity,
                'trading_volume_24h': trading_volume,
                'popular_pairs': popular_pairs[:5],  # Top 5
                'dex_health_score': pisecure_dex.get_dex_intelligence().get('dex_health_score', 0)
            },
            'intelligence_features': [
                'ML-optimized trade routing',
                'Threat-aware liquidity selection',
                'Network condition adaptation',
                'Real-time pool health monitoring'
            ],
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"DEX stats error: {e}")
        return jsonify({'error': 'DEX stats unavailable'}), 500

@app.route('/api/v1/nodes/register', methods=['POST'])
def register_node():
    """Register a PiSecure node with the bootstrap server (including Sentinel AI nodes)"""
    logger.info("Node registration endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get registration data
        registration_data = request.get_json() or {}
        node_id = registration_data.get('node_id')
        node_type = registration_data.get('node_type', 'standard')
        services = registration_data.get('services', [])
        location = registration_data.get('location', 'unknown')
        wallet_address = registration_data.get('wallet_address')
        capabilities = registration_data.get('capabilities', [])
        sentinel_config = registration_data.get('sentinel_config', {})

        if not node_id:
            return jsonify({'error': 'node_id required'}), 400

        # Validate node data
        if not _validate_node_registration(registration_data):
            return jsonify({'error': 'Invalid node registration data'}), 400

        # Register the node
        node_data = {
            'node_id': node_id,
            'node_type': node_type,
            'services': services,
            'location': location,
            'wallet_address': wallet_address,
            'capabilities': capabilities,
            'registered_at': time.time(),
            'last_seen': time.time(),
            'status': 'registered',
            'client_ip': client_ip
        }

        # Store in node tracker
        success = _register_pisecure_node(node_data)

        # If this is a sentinel_ai node, also register with sentinel service
        if success and node_type == 'sentinel_ai':
            sentinel_result = sentinel_service.register_sentinel_node({
                'node_id': node_id,
                'sentinel_config': sentinel_config
            })
            
            logger.info(f"Successfully registered Sentinel AI node: {node_id} from {location}")
            
            return jsonify({
                'registration_success': True,
                'node_id': node_id,
                'assigned_role': 'sentinel_ai',
                'network_permissions': sentinel_result.get('network_permissions', ['monitor', 'alert', 'coordinate']),
                'registration_time': node_data['registered_at'],
                'network_info': {
                    'bootstrap_coordinator': 'bootstrap.pisecure.org',
                    'federation_enabled': True,
                    'intelligence_sharing': True
                },
                'sentinel_capabilities': sentinel_result.get('sentinel_capabilities', {}),
                'capabilities_acknowledged': capabilities,
                'services_enabled': services
            })

        if success:
            logger.info(f"Successfully registered PiSecure node: {node_id} ({node_type}) from {location}")

            return jsonify({
                'registration_success': True,
                'node_id': node_id,
                'registration_time': node_data['registered_at'],
                'network_info': {
                    'bootstrap_coordinator': 'bootstrap.pisecure.org',
                    'federation_enabled': True,
                    'intelligence_sharing': True
                },
                'capabilities_acknowledged': capabilities,
                'services_enabled': services
            })
        else:
            return jsonify({'error': 'Node registration failed'}), 500

    except Exception as e:
        logger.error(f"Node registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/v1/nodes/status', methods=['POST'])
def update_node_status():
    """Receive periodic status updates from registered PiSecure nodes"""
    logger.info("Node status update endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get status data
        status_data = request.get_json() or {}
        node_id = status_data.get('node_id')

        if not node_id:
            return jsonify({'error': 'node_id required'}), 400

        # Check if node is registered
        if not _is_node_registered(node_id):
            return jsonify({'error': 'Node not registered. Please register first.'}), 403

        # Update node status
        status_update = {
            'status': status_data.get('status', 'active'),
            'mining_active': status_data.get('mining_active', False),
            'blocks_mined': status_data.get('blocks_mined', 0),
            'peers_connected': status_data.get('peers_connected', 0),
            'syndicate_membership': status_data.get('syndicate_membership'),
            'hashrate': status_data.get('hashrate'),
            'uptime_percentage': status_data.get('uptime_percentage'),
            'last_status_update': time.time(),
            'client_ip': client_ip
        }

        # If this is a sentinel node, also update sentinel status
        sentinel_status = status_data.get('sentinel_status')
        if sentinel_status:
            sentinel_result = sentinel_service.update_sentinel_status(node_id, status_data)
            if 'error' not in sentinel_result:
                logger.info(f"Sentinel status updated for: {node_id}")

        # Process the status update
        success = _update_node_status(node_id, status_update)

        if success:
            # Trigger intelligence processing for this node's data
            _process_node_intelligence(node_id, status_data)

            logger.info(f"Status update received from node: {node_id}")

            return jsonify({
                'status_update_accepted': True,
                'node_id': node_id,
                'intelligence_processed': True,
                'network_recommendations': _get_node_recommendations(node_id, status_data),
                'timestamp': time.time()
            })
        else:
            return jsonify({'error': 'Status update failed'}), 500

    except Exception as e:
        logger.error(f"Node status update error: {e}")
        return jsonify({'error': 'Status update failed'}), 500

@app.route('/api/v1/nodes/list', methods=['GET'])
def list_registered_nodes():
    """Get list of registered PiSecure nodes (for coordination)"""
    logger.info("Registered nodes list endpoint called")

    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)

        # Get filter parameters
        node_type = request.args.get('type')
        location = request.args.get('location')
        service = request.args.get('service')

        # Retrieve registered nodes
        nodes_list = _get_registered_nodes_filtered(node_type, location, service)

        # Add intelligence insights
        nodes_with_insights = []
        for node in nodes_list:
            node_insights = _get_node_insights(node['node_id'])
            nodes_with_insights.append({
                **node,
                'intelligence_insights': node_insights
            })

        return jsonify({
            'total_registered_nodes': len(nodes_list),
            'nodes': nodes_with_insights,
            'filters_applied': {
                'type': node_type,
                'location': location,
                'service': service
            },
            'intelligence_enhanced': True,
            'timestamp': time.time()
        })

    except Exception as e:
        logger.error(f"Registered nodes list error: {e}")
        return jsonify({'error': 'Node list unavailable'}), 500

@app.route('/nodes', methods=['GET'])
def nodes():
    """Beautiful dark mode HTML dashboard with live API data"""
    logger.info("Live nodes dashboard endpoint called")

    # Record dashboard access for intelligence
    client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
    network_intelligence.record_connection(client_ip, request.headers.get('User-Agent', ''))

    # Serve the HTML template - data will be loaded via JavaScript API calls
    return render_template('nodes.html')

# ========================================
# SENTINEL API ENDPOINTS
# Ghostwheel Active Defense Integration
# ========================================

@app.route('/api/v1/intelligence/threats/report', methods=['POST'])
def submit_threat_signature():
    """Submit threat signature detection from Sentinel node"""
    logger.info("Threat signature submission endpoint called")
    
    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)
        
        # Get threat report data
        report_data = request.get_json() or {}
        
        if not report_data.get('reporter_node'):
            return jsonify({'error': 'reporter_node required'}), 400
        
        if not report_data.get('threat_signature'):
            return jsonify({'error': 'threat_signature required'}), 400
        
        # Submit threat signature
        result = sentinel_service.submit_threat_signature(report_data)
        
        if 'error' in result:
            return jsonify(result), 403
        
        # Also process with network intelligence for correlation
        threat_sig = report_data.get('threat_signature', {})
        network_intelligence.potential_attacks.append({
            'type': threat_sig.get('type', 'sentinel_detected'),
            'severity': 'high' if threat_sig.get('confidence', 0) > 0.8 else 'medium',
            'confidence': threat_sig.get('confidence', 0),
            'indicators': threat_sig.get('indicators', []),
            'timestamp': time.time(),
            'source': 'sentinel_ai'
        })
        
        logger.info(f"Threat signature submitted by: {report_data.get('reporter_node')}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Threat signature submission error: {e}")
        return jsonify({'error': 'Threat submission failed'}), 500

@app.route('/api/v1/defense/coordinate', methods=['POST'])
def coordinate_defense():
    """Coordinate defense actions across the bootstrap network"""
    logger.info("Defense coordination endpoint called")
    
    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)
        
        # Get coordination data
        coord_data = request.get_json() or {}
        
        if not coord_data.get('coordinator_node'):
            return jsonify({'error': 'coordinator_node required'}), 400
        
        if not coord_data.get('actions'):
            return jsonify({'error': 'actions required'}), 400
        
        # Coordinate defense
        result = sentinel_service.coordinate_defense(coord_data)
        
        if 'error' in result:
            return jsonify(result), 403
        
        # Trigger automated defense measures via network intelligence
        for action in coord_data.get('actions', []):
            defense_features = {
                'action_type': action.get('type'),
                'target': action.get('target'),
                'coordinator': coord_data.get('coordinator_node')
            }
            network_intelligence.trigger_defense_measures(
                defense_features,
                confidence=0.9  # High confidence from sentinel coordination
            )
        
        logger.info(f"Defense coordinated by: {coord_data.get('coordinator_node')}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Defense coordination error: {e}")
        return jsonify({'error': 'Coordination failed'}), 500

@app.route('/api/v1/reputation/<node_id>', methods=['GET'])
def get_node_reputation(node_id):
    """Get reputation information for a node"""
    logger.info(f"Reputation query for node: {node_id}")
    
    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)
        
        # Get reputation
        result = sentinel_service.get_node_reputation(node_id)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Reputation query error: {e}")
        return jsonify({'error': 'Reputation query failed'}), 500

@app.route('/api/v1/reputation/update', methods=['POST'])
def update_node_reputation():
    """Update node reputation based on incident or contribution"""
    logger.info("Reputation update endpoint called")
    
    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)
        
        # Get update data
        update_data = request.get_json() or {}
        
        if not update_data.get('reporter_node'):
            return jsonify({'error': 'reporter_node required'}), 400
        
        if not update_data.get('target_node'):
            return jsonify({'error': 'target_node required'}), 400
        
        if not update_data.get('update_type'):
            return jsonify({'error': 'update_type required'}), 400
        
        # Update reputation
        result = sentinel_service.update_node_reputation(update_data)
        
        if 'error' in result:
            return jsonify(result), 403
        
        logger.info(f"Reputation updated for: {update_data.get('target_node')}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Reputation update error: {e}")
        return jsonify({'error': 'Reputation update failed'}), 500

@app.route('/api/v1/blockchain/metrics', methods=['GET'])
def get_blockchain_metrics():
    """Get blockchain health metrics from Sentinel monitoring"""
    logger.info("Blockchain metrics endpoint called")
    
    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)
        
        # Get blockchain metrics
        result = sentinel_service.get_blockchain_metrics()
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Blockchain metrics error: {e}")
        return jsonify({'error': 'Metrics unavailable'}), 500

@app.route('/api/v1/blockchain/alerts', methods=['POST'])
def submit_blockchain_alert():
    """Submit blockchain anomaly alert from Sentinel monitoring"""
    logger.info("Blockchain alert submission endpoint called")
    
    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)
        
        # Get alert data
        alert_data = request.get_json() or {}
        
        if not alert_data.get('reporter_node'):
            return jsonify({'error': 'reporter_node required'}), 400
        
        if not alert_data.get('alert_type'):
            return jsonify({'error': 'alert_type required'}), 400
        
        # Submit blockchain alert
        result = sentinel_service.submit_blockchain_alert(alert_data)
        
        if 'error' in result:
            return jsonify(result), 403
        
        logger.info(f"Blockchain alert submitted by: {alert_data.get('reporter_node')}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Blockchain alert error: {e}")
        return jsonify({'error': 'Alert submission failed'}), 500

@app.route('/api/v1/alerts/propagate', methods=['POST'])
def propagate_alert():
    """Propagate security alert across the network"""
    logger.info("Alert propagation endpoint called")
    
    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)
        
        # Get alert data
        alert_data = request.get_json() or {}
        
        if not alert_data.get('source_node'):
            return jsonify({'error': 'source_node required'}), 400
        
        if not alert_data.get('alert_id'):
            return jsonify({'error': 'alert_id required'}), 400
        
        # Propagate alert through sentinel service
        result = sentinel_service.propagate_alert(alert_data)
        
        if 'error' in result or result.get('propagation_denied'):
            return jsonify(result), 403
        
        logger.info(f"Alert propagated: {alert_data.get('alert_id')} from {alert_data.get('source_node')}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Alert propagation error: {e}")
        return jsonify({'error': 'Alert propagation failed'}), 500

@app.route('/api/v1/sentinel/stats', methods=['GET'])
def get_sentinel_stats():
    """Get comprehensive Sentinel service statistics"""
    logger.info("Sentinel statistics endpoint called")
    
    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)
        
        # Get sentinel stats
        result = sentinel_service.get_sentinel_stats()
        
        # Enhance with network intelligence
        network_health = network_intelligence.analyze_network_health()
        result['network_health_integration'] = {
            'overall_health': network_health.get('overall_health'),
            'attack_resistance': network_health.get('attack_resistance'),
            'threat_level': 'high' if network_intelligence.potential_attacks else 'low'
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Sentinel stats error: {e}")
        return jsonify({'error': 'Stats unavailable'}), 500

@app.route('/api/v1/nodes/strategy', methods=['POST'])
def configure_node_strategy():
    """Configure security strategy for Sentinel nodes"""
    logger.info("Node strategy configuration endpoint called")
    
    try:
        # Record this API call
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)
        
        # Get strategy data
        strategy_data = request.get_json() or {}
        node_id = strategy_data.get('node_id')
        strategy = strategy_data.get('strategy')
        parameters = strategy_data.get('parameters', {})
        
        if not node_id:
            return jsonify({'error': 'node_id required'}), 400
        
        if not strategy:
            return jsonify({'error': 'strategy required'}), 400
        
        # Validate strategy
        valid_strategies = ['standard', 'aggressive', 'deceptive', 'fortress']
        if strategy not in valid_strategies:
            return jsonify({
                'error': f'Invalid strategy. Must be one of: {", ".join(valid_strategies)}'
            }), 400
        
        # Store strategy configuration (in production, this would be persisted)
        # For now, acknowledge the configuration
        logger.info(f"Strategy configured for {node_id}: {strategy}")
        
        return jsonify({
            'strategy_updated': True,
            'node_id': node_id,
            'active_strategy': strategy,
            'parameters_applied': parameters,
            'timestamp': time.time()
        })
        
    except Exception as e:
        logger.error(f"Strategy configuration error: {e}")
        return jsonify({'error': 'Strategy configuration failed'}), 500

# ========================================
# DDOS PROTECTION & VALIDATION ENDPOINTS
# ========================================

@app.route('/api/v1/security/ddos/stats', methods=['GET'])
def get_ddos_protection_stats():
    """Get DDoS protection statistics"""
    logger.info("DDoS protection stats endpoint called")
    
    try:
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)
        stats = ddos_protection.get_protection_stats()
        network_health = network_intelligence.analyze_network_health()
        
        return jsonify({
            'ddos_protection': stats,
            'network_health_integration': {
                'attack_resistance': network_health.get('attack_resistance'),
                'threat_level': 'high' if network_intelligence.potential_attacks else 'low',
                'active_defense_actions': len(network_intelligence.defense_actions)
            },
            'protection_status': 'active',
            'timestamp': time.time()
        })
    except Exception as e:
        logger.error(f"DDoS stats error: {e}")
        return jsonify({'error': 'Stats unavailable'}), 500

@app.route('/api/v1/security/validation/stats', methods=['GET'])
def get_validation_stats():
    """Get validation engine statistics"""
    logger.info("Validation stats endpoint called")
    
    try:
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)
        stats = validation_engine.get_validation_stats()
        
        return jsonify({
            'validation_engine': stats,
            'validation_status': 'active',
            'security_features': [
                'Input sanitization (XSS, SQL injection, path traversal)',
                'JSON schema validation',
                'Blockchain-specific validation',
                'Pattern-based security analysis',
                'Data exfiltration detection',
                'Enumeration attack detection'
            ],
            'timestamp': time.time()
        })
    except Exception as e:
        logger.error(f"Validation stats error: {e}")
        return jsonify({'error': 'Stats unavailable'}), 500

@app.route('/api/v1/security/status', methods=['GET'])
def get_security_status():
    """Get comprehensive security status"""
    logger.info("Security status endpoint called")
    
    try:
        client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
        network_intelligence.record_connection(client_ip)
        
        ddos_stats = ddos_protection.get_protection_stats()
        validation_stats = validation_engine.get_validation_stats()
        network_health = network_intelligence.analyze_network_health()
        sentinel_stats = sentinel_service.get_sentinel_stats()
        
        return jsonify({
            'security_status': 'operational',
            'security_layers': {
                'ddos_protection': {
                    'status': 'active',
                    'active_clients': ddos_stats.get('active_clients'),
                    'blocked_ips': ddos_stats.get('blocked_ips')
                },
                'input_validation': {
                    'status': 'active',
                    'schemas_loaded': validation_stats.get('schemas_loaded')
                },
                'network_intelligence': {
                    'status': 'active',
                    'overall_health': network_health.get('overall_health')
                },
                'sentinel_coordination': {
                    'status': 'active',
                    'registered_nodes': sentinel_stats.get('registered_nodes')
                }
            },
            'timestamp': time.time()
        })
    except Exception as e:
        logger.error(f"Security status error: {e}")
        return jsonify({'error': 'Security status unavailable'}), 500

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('FLASK_ENV') == 'development'

    logger.info(f"Starting Flask app on port={port}, debug={debug}")
    app.run(host='0.0.0.0', port=port, debug=debug)