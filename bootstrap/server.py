#!/usr/bin/env python3
"""
Minimal PiSecure Bootstrap Node Server for Testing
"""

import logging
from flask import Flask, jsonify

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create minimal Flask app
app = Flask(__name__)

@app.route('/', methods=['GET'])
def root_health():
    logger.info("Root health check called")
    return jsonify({'status': 'healthy', 'service': 'bootstrap'})

@app.route('/health', methods=['GET'])
def health():
    logger.info("Health check called")
    return jsonify({'status': 'healthy', 'service': 'bootstrap'})

@app.route('/api/v1/health', methods=['GET'])
def api_health():
    logger.info("API health check called")
    return jsonify({
        'status': 'healthy',
        'service': 'bootstrap',
        'version': '1.0.0'
    })

@app.route('/nodes', methods=['GET'])
def nodes():
    logger.info("Network nodes endpoint called")
    return jsonify({
        'total_nodes': 156,
        'active_connections': 89,
        'bootstrap_nodes': [
            {'id': 'bootstrap-primary', 'address': 'bootstrap.pisecure.org:3142', 'status': 'active'},
            {'id': 'bootstrap-backup', 'address': 'backup.pisecure.org:3142', 'status': 'active'}
        ],
        'miners': [
            {'id': 'miner-001', 'hashrate': '250 MH/s', 'status': 'mining', 'blocks_mined': 1247},
            {'id': 'miner-002', 'hashrate': '180 MH/s', 'status': 'mining', 'blocks_mined': 892}
        ],
        'network_health': {'status': 'excellent', 'active_miners': 4}
    })

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('FLASK_ENV') == 'development'

    logger.info(f"Starting Flask app on port={port}, debug={debug}")
    app.run(host='0.0.0.0', port=port, debug=debug)