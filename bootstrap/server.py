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

    # Comprehensive network statistics (mock data for now)
    network_stats = {
        'network_overview': {
            'total_nodes': 1247,
            'active_nodes': 892,
            'total_connections': 3456,
            'network_hashrate': '2.4 TH/s',
            'difficulty': '1,234,567,890',
            'block_height': 456789,
            'avg_block_time': '12.5 seconds',
            'network_status': 'healthy'
        },
        'bootstrap_nodes': [
            {
                'id': 'bootstrap-primary',
                'address': 'bootstrap.pisecure.org:3142',
                'status': 'active',
                'uptime': '99.97%',
                'region': 'US-East',
                'connections': 234,
                'version': '1.0.0'
            },
            {
                'id': 'bootstrap-backup',
                'address': 'backup.pisecure.org:3142',
                'status': 'active',
                'uptime': '99.95%',
                'region': 'EU-West',
                'connections': 189,
                'version': '1.0.0'
            },
            {
                'id': 'bootstrap-asia',
                'address': 'asia.pisecure.org:3142',
                'status': 'active',
                'uptime': '99.92%',
                'region': 'Asia-Pacific',
                'connections': 156,
                'version': '1.0.0'
            }
        ],
        'mining_nodes': {
            'total_miners': 45,
            'active_miners': 38,
            'idle_miners': 7,
            'top_miners': [
                {
                    'id': 'miner-alpha',
                    'hashrate': '450 MH/s',
                    'status': 'mining',
                    'blocks_mined': 2341,
                    'efficiency': '98.5%',
                    'uptime': '99.9%'
                },
                {
                    'id': 'miner-beta',
                    'hashrate': '380 MH/s',
                    'status': 'mining',
                    'blocks_mined': 1987,
                    'efficiency': '97.8%',
                    'uptime': '99.7%'
                },
                {
                    'id': 'miner-gamma',
                    'hashrate': '320 MH/s',
                    'status': 'mining',
                    'blocks_mined': 1654,
                    'efficiency': '99.1%',
                    'uptime': '100%'
                },
                {
                    'id': 'miner-delta',
                    'hashrate': '290 MH/s',
                    'status': 'mining',
                    'blocks_mined': 1432,
                    'efficiency': '96.3%',
                    'uptime': '98.5%'
                },
                {
                    'id': 'miner-epsilon',
                    'hashrate': '250 MH/s',
                    'status': 'idle',
                    'blocks_mined': 987,
                    'efficiency': '94.7%',
                    'uptime': '97.2%'
                }
            ]
        },
        'network_health': {
            'status': 'excellent',
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
                'miner': 'miner-alpha',
                'timestamp': '2026-01-04T12:01:30Z',
                'transactions': 45,
                'size': '1.2 MB',
                'reward': '50 PISC'
            },
            {
                'height': 456788,
                'hash': 'f9e8d7c6b5a498765432109876543210fedcba098765432109876543210fedcba',
                'miner': 'miner-beta',
                'timestamp': '2026-01-04T12:01:18Z',
                'transactions': 38,
                'size': '987 KB',
                'reward': '50 PISC'
            },
            {
                'height': 456787,
                'hash': '0987654321abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
                'miner': 'miner-gamma',
                'timestamp': '2026-01-04T12:01:05Z',
                'transactions': 52,
                'size': '1.5 MB',
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
        'geographic_distribution': {
            'us_east': {'nodes': 345, 'percentage': 27.7},
            'eu_west': {'nodes': 298, 'percentage': 23.9},
            'asia_pacific': {'nodes': 267, 'percentage': 21.4},
            'us_west': {'nodes': 189, 'percentage': 15.2},
            'other': {'nodes': 148, 'percentage': 11.8}
        },
        'last_updated': '2026-01-04T12:01:45Z',
        'api_version': '1.0'
    }

    return jsonify(network_stats)

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('FLASK_ENV') == 'development'

    logger.info(f"Starting Flask app on port={port}, debug={debug}")
    app.run(host='0.0.0.0', port=port, debug=debug)