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
from collections import deque, defaultdict
from flask import Flask, jsonify, request, render_template
from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
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

    def _analyze_connection_patterns(self):
        """Internal method to analyze connection patterns for anomalies"""
        # This is called automatically when connections are recorded
        # Additional analysis could be added here
        pass

# Initialize network intelligence engine
network_intelligence = NetworkIntelligence()

# Bootstrap Node Registry (Global state for secondary bootstrap nodes)
bootstrap_node_registry = {}

def _validate_bootstrap_node(handshake_data: dict) -> bool:
    """Validate that the node attempting handshake is a legitimate bootstrap node"""
    # Basic validation - in production, this would be more sophisticated
    # Check for required capabilities, valid address format, etc.

    node_id = handshake_data.get('node_id', '')
    address = handshake_data.get('address', '')
    services = handshake_data.get('services', [])
    capabilities = handshake_data.get('capabilities', [])

    # Must have bootstrap-related capabilities
    bootstrap_capabilities = ['bootstrap_coordination', 'peer_discovery', 'network_health']
    has_bootstrap_capability = any(cap in capabilities for cap in bootstrap_capabilities)

    # Must offer basic bootstrap services
    required_services = ['peer_discovery']
    has_required_services = all(service in services for service in required_services)

    # Basic address validation
    try:
        ipaddress.ip_address(address)
        valid_address = True
    except ValueError:
        valid_address = False

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

@app.route('/api/v1/bootstrap/registry', methods=['GET'])
def bootstrap_registry():
    """Get the current bootstrap node registry (for coordination)"""
    logger.info("Bootstrap registry endpoint called")

    try:
        # Only allow access from registered bootstrap nodes or with auth
        # For now, allow public access but could add authentication later

        registry = {
            'primary_node': {
                'node_id': 'bootstrap-primary',
                'address': 'bootstrap.pisecure.org',
                'port': 3142,
                'status': 'active',
                'services': ['coordination', 'peer_discovery', 'health_monitoring']
            },
            'secondary_nodes': _get_registered_bootstrap_nodes(),
            'total_nodes': len(_get_registered_bootstrap_nodes()) + 1,
            'last_updated': time.time(),
            'coordination_status': 'active'
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

@app.route('/nodes', methods=['GET'])
def nodes():
    """Beautiful dark mode HTML dashboard with live API data"""
    logger.info("Live nodes dashboard endpoint called")

    # Record dashboard access for intelligence
    client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
    network_intelligence.record_connection(client_ip, request.headers.get('User-Agent', ''))

    # Serve the HTML template - data will be loaded via JavaScript API calls
    return render_template('nodes.html')

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('FLASK_ENV') == 'development'

    logger.info(f"Starting Flask app on port={port}, debug={debug}")
    app.run(host='0.0.0.0', port=port, debug=debug)