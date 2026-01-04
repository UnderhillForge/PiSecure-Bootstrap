#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PiSecure Bootstrap Node Server
==============================

Lightweight Flask API server providing P2P discovery services for the PiSecure network.
Serves as an entry point for new nodes joining the network.
"""

import os
import time
import json
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from typing import Dict, List, Any, Optional
import secrets

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BootstrapNode:
    """
    Lightweight bootstrap node for PiSecure P2P network.

    Provides essential discovery services:
    - Initial peer lists for new nodes
    - Network statistics and health metrics
    - Node registration and heartbeat monitoring
    """

    def __init__(self, host: str = '0.0.0.0', port: Optional[int] = None):
        """
        Initialize the bootstrap node.

        Args:
            host: Host to bind to
            port: Port to listen on (uses RAILWAY_PORT if not specified)
        """
        self.host = host
        # Use Railway's PORT environment variable, fallback to provided port or default
        self.port = port or int(os.environ.get('PORT', '3142'))

        # Initialize Flask app
        self.app = Flask(__name__)
        CORS(self.app)

        # Rate limiting
        rate_limit = os.getenv('RATE_LIMIT', '100 per minute')
        self.limiter = Limiter(
            get_remote_address,
            app=self.app,
            default_limits=[rate_limit]
        )

        # Bootstrap configuration
        self.api_version = "v1"
        self.start_time = time.time()

        # Node registry (in production, use a database)
        self.registered_nodes: Dict[str, Dict] = {}

        # Known bootstrap peers (configurable)
        bootstrap_peers_env = os.getenv('BOOTSTRAP_PEERS', '')
        self.bootstrap_peers = self._parse_bootstrap_peers(bootstrap_peers_env)

        # Setup routes
        self._setup_routes()

        logger.info(f"PiSecure Bootstrap Node initialized on {host}:{port}")

    def _parse_bootstrap_peers(self, peers_str: str) -> List[Dict[str, Any]]:
        """Parse bootstrap peers from environment variable."""
        if not peers_str:
            return []

        peers = []
        for peer_str in peers_str.split(','):
            peer_str = peer_str.strip()
            if ':' in peer_str:
                address, port_str = peer_str.rsplit(':', 1)
                try:
                    port = int(port_str)
                    peers.append({
                        'address': address,
                        'port': port,
                        'capabilities': ['api', 'p2p_sync'],
                        'last_seen': time.time()
                    })
                except ValueError:
                    logger.warning(f"Invalid peer format: {peer_str}")
            else:
                peers.append({
                    'address': peer_str,
                    'port': 3142,
                    'capabilities': ['api', 'p2p_sync'],
                    'last_seen': time.time()
                })

        return peers

    def _setup_routes(self):
        """Setup all API routes."""

        # Root health check (for Railway)
        @self.app.route('/', methods=['GET'])
        def root_health():
            return jsonify({'status': 'healthy'})

        # Health check
        @self.app.route(f'/api/{self.api_version}/health', methods=['GET'])
        def health():
            return jsonify({
                'status': 'healthy',
                'timestamp': time.time(),
                'uptime': time.time() - self.start_time,
                'version': '1.0.0',
                'service': 'bootstrap'
            })

        # Bootstrap peer discovery
        @self.app.route(f'/api/{self.api_version}/bootstrap/peers', methods=['GET'])
        def get_bootstrap_peers():
            """Serve initial peer list for new nodes joining the network."""
            try:
                # Get verified active peers for bootstrapping
                verified_peers = self._get_verified_bootstrap_peers()

                # Add this node as a bootstrap reference
                bootstrap_info = {
                    'peers': verified_peers,
                    'bootstrap_node': {
                        'host': self.host,
                        'port': self.port,
                        'node_id': f"bootstrap_{hashlib.sha256(f'{self.host}:{self.port}'.encode()).hexdigest()[:16]}",
                        'capabilities': ['bootstrap', 'api', 'p2p_sync']
                    },
                    'network_info': {
                        'total_nodes': len(self.registered_nodes),
                        'active_nodes': self._count_active_nodes(),
                        'protocol_version': '1.0',
                        'features': ['p2p_sync', 'mining_teams', 'hardware_verification']
                    },
                    'last_updated': time.time(),
                    'ttl': 300  # Cache for 5 minutes
                }

                return jsonify(bootstrap_info)

            except Exception as e:
                logger.error(f"Bootstrap peers error: {e}")
                return jsonify({'error': str(e)}), 500

        # Network statistics (public dashboard)
        @self.app.route(f'/api/{self.api_version}/network/stats', methods=['GET'])
        def network_statistics():
            """Public network health and statistics dashboard."""
            try:
                stats = self._calculate_network_stats()

                return jsonify({
                    'network_health': stats,
                    'protocol_info': {
                        'version': '1.0',
                        'features': ['p2p_sync', 'mining_teams', 'hardware_verification'],
                        'consensus': 'proof_of_work'
                    },
                    'last_updated': time.time()
                })

            except Exception as e:
                logger.error(f"Network stats error: {e}")
                return jsonify({'error': str(e)}), 500

        # Node registration for enhanced discovery
        @self.app.route(f'/api/{self.api_version}/nodes/register', methods=['POST'])
        def register_node():
            """Allow nodes to register themselves for better network discovery."""
            try:
                node_data = request.get_json()

                if not node_data:
                    return jsonify({'error': 'No node data provided'}), 400

                required_fields = ['address', 'port', 'node_id']
                for field in required_fields:
                    if field not in node_data:
                        return jsonify({'error': f'Missing required field: {field}'}), 400

                # Validate node information
                node_id = node_data['node_id']
                address = node_data['address']
                port = node_data['port']

                # Basic validation
                if not isinstance(port, int) or port < 1 or port > 65535:
                    return jsonify({'error': 'Invalid port number'}), 400

                # Register or update node
                registered_node = {
                    'node_id': node_id,
                    'address': address,
                    'port': port,
                    'capabilities': node_data.get('capabilities', []),
                    'hashrate': node_data.get('hashrate', 0),
                    'location': node_data.get('location', 'unknown'),
                    'is_mining': node_data.get('is_mining', False),
                    'registered_at': time.time(),
                    'last_seen': time.time(),
                    'version': node_data.get('version', 'unknown')
                }

                # Store in registered nodes
                self.registered_nodes[node_id] = registered_node

                logger.info(f"Registered node: {node_id} at {address}:{port}")

                return jsonify({
                    'success': True,
                    'node_id': node_id,
                    'registered_at': registered_node['registered_at'],
                    'bootstrap_peers': len(self._get_verified_bootstrap_peers())
                })

            except Exception as e:
                logger.error(f"Node registration error: {e}")
                return jsonify({'error': str(e)}), 500

        # Node heartbeat/status updates
        @self.app.route(f'/api/{self.api_version}/nodes/heartbeat', methods=['POST'])
        def node_heartbeat():
            """Receive heartbeat from registered nodes."""
            try:
                heartbeat_data = request.get_json()

                if not heartbeat_data or 'node_id' not in heartbeat_data:
                    return jsonify({'error': 'node_id required'}), 400

                node_id = heartbeat_data['node_id']

                if node_id in self.registered_nodes:
                    # Update last seen time and status
                    node_info = self.registered_nodes[node_id]
                    node_info['last_seen'] = time.time()
                    node_info.update(heartbeat_data)  # Update any provided fields

                    return jsonify({'success': True, 'updated': True})
                else:
                    return jsonify({'error': 'Node not registered'}), 404

            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                return jsonify({'error': str(e)}), 500

        # API documentation
        @self.app.route(f'/api/{self.api_version}/docs', methods=['GET'])
        def api_docs():
            docs = {
                'version': self.api_version,
                'base_url': f'http://{self.host}:{self.port}/api/{self.api_version}',
                'service': 'PiSecure Bootstrap Node',
                'description': 'Lightweight P2P discovery service for PiSecure network',
                'endpoints': {
                    'health': {'method': 'GET', 'path': '/health', 'description': 'API health check'},
                    'bootstrap_peers': {'method': 'GET', 'path': '/bootstrap/peers', 'description': 'Get initial peer list'},
                    'network_stats': {'method': 'GET', 'path': '/network/stats', 'description': 'Network statistics and health'},
                    'register_node': {'method': 'POST', 'path': '/nodes/register', 'description': 'Register node for discovery'},
                    'node_heartbeat': {'method': 'POST', 'path': '/nodes/heartbeat', 'description': 'Send node heartbeat'},
                },
                'rate_limiting': os.getenv('RATE_LIMIT', '100 per minute'),
                'contact': 'https://github.com/UnderhillForge/PiSecure'
            }
            return jsonify(docs)

    def _get_verified_bootstrap_peers(self) -> List[Dict[str, Any]]:
        """Get list of verified, active peers for bootstrapping."""
        try:
            verified_peers = []

            # Add configured bootstrap peers
            current_time = time.time()
            for peer in self.bootstrap_peers:
                if current_time - peer.get('last_seen', 0) < 3600:  # Active within 1 hour
                    peer_id = f"{peer['address']}:{peer['port']}"
                    verified_peers.append({
                        'node_id': f"bootstrap_{hashlib.sha256(peer_id.encode()).hexdigest()[:16]}",
                        'address': peer['address'],
                        'port': peer['port'],
                        'capabilities': peer.get('capabilities', []),
                        'last_seen': peer.get('last_seen', current_time)
                    })

            # Add registered nodes that are active and have p2p_sync capability
            for node_id, node_info in self.registered_nodes.items():
                if (current_time - node_info.get('last_seen', 0) < 3600 and  # Active within 1 hour
                    'p2p_sync' in node_info.get('capabilities', [])):
                    verified_peers.append({
                        'node_id': node_id,
                        'address': node_info.get('address'),
                        'port': node_info.get('port'),
                        'capabilities': node_info.get('capabilities', []),
                        'last_seen': node_info.get('last_seen', current_time)
                    })

            # Limit to prevent abuse
            return verified_peers[:50]

        except Exception as e:
            logger.error(f"Verified peers error: {e}")
            return []

    def _calculate_network_stats(self) -> Dict[str, Any]:
        """Calculate comprehensive network statistics."""
        try:
            current_time = time.time()

            # Count active nodes
            active_registered = sum(
                1 for node in self.registered_nodes.values()
                if current_time - node.get('last_seen', 0) < 3600
            )

            # Calculate network hashrate
            total_hashrate = sum(
                node.get('hashrate', 0) for node in self.registered_nodes.values()
                if current_time - node.get('last_seen', 0) < 3600
            )

            # Count mining nodes
            active_miners = sum(
                1 for node in self.registered_nodes.values()
                if node.get('is_mining', False) and current_time - node.get('last_seen', 0) < 3600
            )

            # Network health score
            participation = min(1.0, active_registered / max(1, len(self.registered_nodes))) if self.registered_nodes else 0
            health_score = participation * 100  # Simple health score

            return {
                'active_nodes': active_registered,
                'total_registered_nodes': len(self.registered_nodes),
                'connected_peers': active_registered,  # Simplified
                'estimated_hashrate': total_hashrate,
                'participation_score': participation,
                'health_score': health_score,
                'active_miners': active_miners,
                'total_known_peers': len(self.registered_nodes),
                'uptime': time.time() - self.start_time
            }

        except Exception as e:
            logger.error(f"Network stats calculation error: {e}")
            return {
                'active_nodes': 0,
                'error': str(e)
            }

    def _count_active_nodes(self) -> int:
        """Count currently active nodes."""
        current_time = time.time()
        return sum(
            1 for node in self.registered_nodes.values()
            if current_time - node.get('last_seen', 0) < 3600
        )

    def run(self, debug: bool = False):
        """
        Start the bootstrap node server.

        Args:
            debug: Enable debug mode
        """
        logger.info(f"Starting PiSecure Bootstrap Node on {self.host}:{self.port}")
        logger.info(f"API Documentation: http://{self.host}:{self.port}/api/{self.api_version}/docs")

        try:
            self.app.run(
                host=self.host,
                port=self.port,
                debug=debug,
                threaded=True
            )
        except Exception as e:
            logger.error(f"Failed to start bootstrap server: {e}")
            raise


# Standalone server runner
def run_server():
    """Run the bootstrap server."""
    import argparse

    parser = argparse.ArgumentParser(description='PiSecure Bootstrap Node Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=3142, help='Port to listen on')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    server = BootstrapNode(host=args.host, port=args.port)
    server.run(debug=args.debug)


def _parse_bootstrap_peers_static(peers_str: str) -> List[Dict[str, Any]]:
    """Static version of bootstrap peer parsing."""
    if not peers_str:
        return []

    peers = []
    for peer_str in peers_str.split(','):
        peer_str = peer_str.strip()
        if ':' in peer_str:
            address, port_str = peer_str.rsplit(':', 1)
            try:
                port = int(port_str)
                peers.append({
                    'address': address,
                    'port': port,
                    'capabilities': ['api', 'p2p_sync'],
                    'last_seen': time.time()
                })
            except ValueError:
                logger.warning(f"Invalid peer format: {peer_str}")
        else:
            peers.append({
                'address': peer_str,
                'port': 3142,
                'capabilities': ['api', 'p2p_sync'],
                'last_seen': time.time()
            })

    return peers

def _setup_routes_static(app, api_version, start_time, registered_nodes, bootstrap_peers, port, limiter):
    """Static version of route setup for WSGI compatibility."""

    # Root health check (for Railway)
    @app.route('/', methods=['GET'])
    def root_health():
        return jsonify({'status': 'healthy'})

    # Health check
    @app.route(f'/api/{api_version}/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'healthy',
            'timestamp': time.time(),
            'uptime': time.time() - start_time,
            'version': '1.0.0',
            'service': 'bootstrap'
        })

    # Bootstrap peer discovery
    @app.route(f'/api/{api_version}/bootstrap/peers', methods=['GET'])
    def get_bootstrap_peers():
        """Serve initial peer list for new nodes joining the network."""
        try:
            # Get verified active peers for bootstrapping
            verified_peers = _get_verified_bootstrap_peers_static(bootstrap_peers, registered_nodes)

            # Add this node as a bootstrap reference
            bootstrap_info = {
                'peers': verified_peers,
                'bootstrap_node': {
                    'host': '0.0.0.0',
                    'port': port,
                    'node_id': f"bootstrap_{hashlib.sha256(f'0.0.0.0:{port}'.encode()).hexdigest()[:16]}",
                    'capabilities': ['bootstrap', 'api', 'p2p_sync']
                },
                'network_info': {
                    'total_nodes': len(registered_nodes),
                    'active_nodes': _count_active_nodes_static(registered_nodes),
                    'protocol_version': '1.0',
                    'features': ['p2p_sync', 'mining_teams', 'hardware_verification']
                },
                'last_updated': time.time(),
                'ttl': 300  # Cache for 5 minutes
            }

            return jsonify(bootstrap_info)

        except Exception as e:
            logger.error(f"Bootstrap peers error: {e}")
            return jsonify({'error': str(e)}), 500

    # Network statistics (public dashboard)
    @app.route(f'/api/{api_version}/network/stats', methods=['GET'])
    def network_statistics():
        """Public network health and statistics dashboard."""
        try:
            stats = _calculate_network_stats_static(registered_nodes, start_time)

            return jsonify({
                'network_health': stats,
                'protocol_info': {
                    'version': '1.0',
                    'features': ['p2p_sync', 'mining_teams', 'hardware_verification'],
                    'consensus': 'proof_of_work'
                },
                'last_updated': time.time()
            })

        except Exception as e:
            logger.error(f"Network stats error: {e}")
            return jsonify({'error': str(e)}), 500

    # Node registration for enhanced discovery
    @app.route(f'/api/{api_version}/nodes/register', methods=['POST'])
    def register_node():
        """Allow nodes to register themselves for better network discovery."""
        try:
            node_data = request.get_json()

            if not node_data:
                return jsonify({'error': 'No node data provided'}), 400

            required_fields = ['address', 'port', 'node_id']
            for field in required_fields:
                if field not in node_data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400

            # Validate node information
            node_id = node_data['node_id']
            address = node_data['address']
            port_val = node_data['port']

            # Basic validation
            if not isinstance(port_val, int) or port_val < 1 or port_val > 65535:
                return jsonify({'error': 'Invalid port number'}), 400

            # Register or update node
            registered_node = {
                'node_id': node_id,
                'address': address,
                'port': port_val,
                'capabilities': node_data.get('capabilities', []),
                'hashrate': node_data.get('hashrate', 0),
                'location': node_data.get('location', 'unknown'),
                'is_mining': node_data.get('is_mining', False),
                'registered_at': time.time(),
                'last_seen': time.time(),
                'version': node_data.get('version', 'unknown')
            }

            # Store in registered nodes
            registered_nodes[node_id] = registered_node

            logger.info(f"Registered node: {node_id} at {address}:{port_val}")

            return jsonify({
                'success': True,
                'node_id': node_id,
                'registered_at': registered_node['registered_at'],
                'bootstrap_peers': len(_get_verified_bootstrap_peers_static(bootstrap_peers, registered_nodes))
            })

        except Exception as e:
            logger.error(f"Node registration error: {e}")
            return jsonify({'error': str(e)}), 500

    # Node heartbeat/status updates
    @app.route(f'/api/{api_version}/nodes/heartbeat', methods=['POST'])
    def node_heartbeat():
        """Receive heartbeat from registered nodes."""
        try:
            heartbeat_data = request.get_json()

            if not heartbeat_data or 'node_id' not in heartbeat_data:
                return jsonify({'error': 'node_id required'}), 400

            node_id = heartbeat_data['node_id']

            if node_id in registered_nodes:
                # Update last seen time and status
                node_info = registered_nodes[node_id]
                node_info['last_seen'] = time.time()
                node_info.update(heartbeat_data)  # Update any provided fields

                return jsonify({'success': True, 'updated': True})
            else:
                return jsonify({'error': 'Node not registered'}), 404

        except Exception as e:
            logger.error(f"Heartbeat error: {e}")
            return jsonify({'error': str(e)}), 500

    # API documentation
    @app.route(f'/api/{api_version}/docs', methods=['GET'])
    def api_docs():
        docs = {
            'version': api_version,
            'base_url': f'http://0.0.0.0:{port}/api/{api_version}',
            'service': 'PiSecure Bootstrap Node',
            'description': 'Lightweight P2P discovery service for PiSecure network',
            'endpoints': {
                'health': {'method': 'GET', 'path': '/health', 'description': 'API health check'},
                'bootstrap_peers': {'method': 'GET', 'path': '/bootstrap/peers', 'description': 'Get initial peer list'},
                'network_stats': {'method': 'GET', 'path': '/network/stats', 'description': 'Network statistics and health'},
                'register_node': {'method': 'POST', 'path': '/nodes/register', 'description': 'Register node for discovery'},
                'node_heartbeat': {'method': 'POST', 'path': '/nodes/heartbeat', 'description': 'Send node heartbeat'},
            },
            'rate_limiting': os.getenv('RATE_LIMIT', '100 per minute'),
            'contact': 'https://github.com/UnderhillForge/PiSecure'
        }
        return jsonify(docs)

def _get_verified_bootstrap_peers_static(bootstrap_peers, registered_nodes):
    """Static version for WSGI compatibility."""
    try:
        verified_peers = []

        # Add configured bootstrap peers
        current_time = time.time()
        for peer in bootstrap_peers:
            if current_time - peer.get('last_seen', 0) < 3600:  # Active within 1 hour
                peer_id = f"{peer['address']}:{peer['port']}"
                verified_peers.append({
                    'node_id': f"bootstrap_{hashlib.sha256(peer_id.encode()).hexdigest()[:16]}",
                    'address': peer['address'],
                    'port': peer['port'],
                    'capabilities': peer.get('capabilities', []),
                    'last_seen': peer.get('last_seen', current_time)
                })

        # Add registered nodes that are active and have p2p_sync capability
        for node_id, node_info in registered_nodes.items():
            if (current_time - node_info.get('last_seen', 0) < 3600 and  # Active within 1 hour
                'p2p_sync' in node_info.get('capabilities', [])):
                verified_peers.append({
                    'node_id': node_id,
                    'address': node_info.get('address'),
                    'port': node_info.get('port'),
                    'capabilities': node_info.get('capabilities', []),
                    'last_seen': node_info.get('last_seen', current_time)
                })

        # Limit to prevent abuse
        return verified_peers[:50]

    except Exception as e:
        logger.error(f"Verified peers error: {e}")
        return []

def _calculate_network_stats_static(registered_nodes, start_time):
    """Static version for WSGI compatibility."""
    try:
        current_time = time.time()

        # Count active nodes
        active_registered = sum(
            1 for node in registered_nodes.values()
            if current_time - node.get('last_seen', 0) < 3600
        )

        # Calculate network hashrate
        total_hashrate = sum(
            node.get('hashrate', 0) for node in registered_nodes.values()
            if current_time - node.get('last_seen', 0) < 3600
        )

        # Count mining nodes
        active_miners = sum(
            1 for node in registered_nodes.values()
            if node.get('is_mining', False) and current_time - node.get('last_seen', 0) < 3600
        )

        # Network health score
        participation = min(1.0, active_registered / max(1, len(registered_nodes))) if registered_nodes else 0
        health_score = participation * 100  # Simple health score

        return {
            'active_nodes': active_registered,
            'total_registered_nodes': len(registered_nodes),
            'connected_peers': active_registered,  # Simplified
            'estimated_hashrate': total_hashrate,
            'participation_score': participation,
            'health_score': health_score,
            'active_miners': active_miners,
            'total_known_peers': len(registered_nodes),
            'uptime': time.time() - start_time
        }

    except Exception as e:
        logger.error(f"Network stats calculation error: {e}")
        return {
            'active_nodes': 0,
            'error': str(e)
        }

def _count_active_nodes_static(registered_nodes):
    """Static version for WSGI compatibility."""
    current_time = time.time()
    return sum(
        1 for node in registered_nodes.values()
        if current_time - node.get('last_seen', 0) < 3600
    )

# Create WSGI application for Gunicorn
def create_app():
    """Create and configure the Flask application for WSGI servers."""
    # For Gunicorn/workers, create a single Flask app without BootstrapNode instances
    # Read port from environment (Railway sets PORT)
    port = int(os.environ.get('PORT', '3142'))

    # Initialize Flask app directly
    app = Flask(__name__)
    CORS(app)

    # Temporarily disable rate limiting for debugging
    # rate_limit = os.getenv('RATE_LIMIT', '100 per minute')
    # limiter = Limiter(
    #     get_remote_address,
    #     app=app,
    #     default_limits=[rate_limit]
    # )
    limiter = None  # Disabled for debugging

    # Bootstrap configuration
    api_version = "v1"
    start_time = time.time()

    # Node registry (in production, use a database)
    registered_nodes = {}

    # Known bootstrap peers (configurable)
    bootstrap_peers_env = os.getenv('BOOTSTRAP_PEERS', '')
    bootstrap_peers = _parse_bootstrap_peers_static(bootstrap_peers_env)

    # Setup routes
    _setup_routes_static(app, api_version, start_time, registered_nodes, bootstrap_peers, port, limiter)

    logger.info(f"PiSecure Bootstrap Node Flask app created for port {port}")
    return app

# Global WSGI application object (created once)
app = create_app()

if __name__ == '__main__':
    run_server()