#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

# Ensure app is accessible at module level for Gunicorn
if __name__ != '__main__':
    logger.info("Flask app initialized for Gunicorn import")

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

    # Mock network data (in a real implementation, this would come from actual network state)
    network_stats = {
        "total_nodes": 156,
        "active_connections": 89,
        "bootstrap_nodes": [
            {
                "id": "bootstrap-primary",
                "address": "bootstrap.pisecure.org:3142",
                "status": "active",
                "uptime": "99.9%",
                "region": "US-East"
            },
            {
                "id": "bootstrap-backup",
                "address": "backup.pisecure.org:3142",
                "status": "active",
                "uptime": "99.7%",
                "region": "EU-West"
            }
        ],
        "miners": [
            {"id": "miner-001", "hashrate": "250 MH/s", "status": "mining", "blocks_mined": 1247},
            {"id": "miner-002", "hashrate": "180 MH/s", "status": "mining", "blocks_mined": 892},
            {"id": "miner-003", "hashrate": "320 MH/s", "status": "mining", "blocks_mined": 2156},
            {"id": "miner-004", "hashrate": "95 MH/s", "status": "idle", "blocks_mined": 456},
            {"id": "miner-005", "hashrate": "410 MH/s", "status": "mining", "blocks_mined": 3421}
        ],
        "network_health": {
            "status": "excellent",
            "avg_block_time": "12.5 seconds",
            "total_hashrate": "1.2 TH/s",
            "active_miners": 4
        },
        "last_updated": "2026-01-04T16:50:39Z"
    }

    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PiSecure Network - Node Status</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: #0a0a0a;
                color: #e0e0e0;
                line-height: 1.6;
                padding: 20px;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
            }

            .header {
                text-align: center;
                margin-bottom: 30px;
                padding: 20px;
                background: linear-gradient(135deg, #1a1a2e, #16213e);
                border-radius: 15px;
                border: 1px solid #333;
            }

            h1 {
                color: #00d4ff;
                font-size: 2.5em;
                margin-bottom: 10px;
                text-shadow: 0 0 20px rgba(0, 212, 255, 0.5);
            }

            .subtitle {
                color: #a0a0a0;
                font-size: 1.1em;
            }

            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }

            .stat-card {
                background: linear-gradient(135deg, #1e1e2f, #2a2a40);
                border-radius: 12px;
                padding: 20px;
                border: 1px solid #444;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            }

            .stat-card h3 {
                color: #00d4ff;
                margin-bottom: 15px;
                font-size: 1.4em;
            }

            .stat-value {
                font-size: 2em;
                font-weight: bold;
                color: #fff;
                margin-bottom: 5px;
            }

            .stat-label {
                color: #a0a0a0;
                font-size: 0.9em;
            }

            .nodes-section {
                margin-bottom: 30px;
            }

            .section-title {
                color: #00d4ff;
                font-size: 1.8em;
                margin-bottom: 20px;
                border-bottom: 2px solid #333;
                padding-bottom: 10px;
            }

            .node-list {
                display: grid;
                gap: 15px;
            }

            .node-item {
                background: #1a1a1a;
                border-radius: 8px;
                padding: 15px;
                border: 1px solid #333;
                transition: all 0.3s ease;
            }

            .node-item:hover {
                border-color: #00d4ff;
                box-shadow: 0 0 15px rgba(0, 212, 255, 0.2);
            }

            .node-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 10px;
            }

            .node-id {
                font-weight: bold;
                color: #fff;
            }

            .node-status {
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 0.8em;
                font-weight: bold;
            }

            .status-active {
                background: #27ae60;
                color: white;
            }

            .status-mining {
                background: #f39c12;
                color: white;
            }

            .status-idle {
                background: #95a5a6;
                color: white;
            }

            .node-details {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 10px;
                font-size: 0.9em;
            }

            .detail-item {
                color: #a0a0a0;
            }

            .detail-label {
                color: #00d4ff;
                font-weight: bold;
            }

            .health-indicator {
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 8px;
            }

            .health-excellent {
                background: #27ae60;
                box-shadow: 0 0 10px rgba(39, 174, 96, 0.5);
            }

            .footer {
                text-align: center;
                margin-top: 40px;
                padding: 20px;
                background: #1a1a1a;
                border-radius: 10px;
                border: 1px solid #333;
            }

            .last-updated {
                color: #a0a0a0;
                font-size: 0.9em;
            }

            @media (max-width: 768px) {
                .stats-grid {
                    grid-template-columns: 1fr;
                }

                .node-details {
                    grid-template-columns: 1fr;
                }

                h1 {
                    font-size: 2em;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>= PiSecure Network</h1>
                <div class="subtitle">Real-time Node Status & Network Statistics</div>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <h3>< Total Nodes</h3>
                    <div class="stat-value">''' + str(network_stats["total_nodes"]) + '''</div>
                    <div class="stat-label">Connected to network</div>
                </div>
                <div class="stat-card">
                    <h3>¡ Active Connections</h3>
                    <div class="stat-value">''' + str(network_stats["active_connections"]) + '''</div>
                    <div class="stat-label">Currently online</div>
                </div>
                <div class="stat-card">
                    <h3>Ï Active Miners</h3>
                    <div class="stat-value">''' + str(network_stats["network_health"]["active_miners"]) + '''</div>
                    <div class="stat-label">Contributing hashrate</div>
                </div>
                <div class="stat-card">
                    <h3><Æ Network Health</h3>
                    <div class="stat-value">
                        <span class="health-indicator health-excellent"></span>
                        ''' + network_stats["network_health"]["status"].title() + '''
                    </div>
                    <div class="stat-label">''' + network_stats["network_health"]["avg_block_time"] + ''' avg block time</div>
                </div>
            </div>

            <div class="nodes-section">
                <h2 class="section-title">=€ Bootstrap Nodes</h2>
                <div class="node-list">
                    ''' + ''.join([f'''
                    <div class="node-item">
                        <div class="node-header">
                            <span class="node-id">{node["id"]}</span>
                            <span class="node-status status-active">{node["status"]}</span>
                        </div>
                        <div class="node-details">
                            <div class="detail-item"><span class="detail-label">Address:</span> {node["address"]}</div>
                            <div class="detail-item"><span class="detail-label">Uptime:</span> {node["uptime"]}</div>
                            <div class="detail-item"><span class="detail-label">Region:</span> {node["region"]}</div>
                        </div>
                    </div>
                    ''' for node in network_stats["bootstrap_nodes"]]) + '''
                </div>
            </div>

            <div class="nodes-section">
                <h2 class="section-title">Ï Mining Nodes</h2>
                <div class="node-list">
                    ''' + ''.join([f'''
                    <div class="node-item">
                        <div class="node-header">
                            <span class="node-id">{miner["id"]}</span>
                            <span class="node-status status-{miner["status"]}">{miner["status"]}</span>
                        </div>
                        <div class="node-details">
                            <div class="detail-item"><span class="detail-label">Hashrate:</span> {miner["hashrate"]}</div>
                            <div class="detail-item"><span class="detail-label">Blocks Mined:</span> {miner["blocks_mined"]:,}</div>
                            <div class="detail-item"><span class="detail-label">Status:</span> {miner["status"].title()}</div>
                        </div>
                    </div>
                    ''' for miner in network_stats["miners"]]) + '''
                </div>
            </div>

            <div class="footer">
                <div class="last-updated">
                    =Ê Last updated: <span id="last-updated">''' + network_stats["last_updated"] + '''</span> |
                    = Auto-refreshes every 30 seconds
                </div>
            </div>
        </div>

        <script>
            function updateLastUpdated() {
                const now = new Date();
                document.getElementById('last-updated').textContent = now.toISOString();
            }

            // Update timestamp every second
            updateLastUpdated();
            setInterval(updateLastUpdated, 1000);

            // Auto-refresh page every 30 seconds
            setTimeout(() => {
                window.location.reload();
            }, 30000);
        </script>
    </body>
    </html>
    '''

# Add debug logging for Railway deployment troubleshooting
if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('FLASK_ENV') == 'development'

    logger.info(f"Starting Flask app on host=0.0.0.0, port={port}, debug={debug}")
    logger.info(f"PORT environment variable: {os.environ.get('PORT', 'NOT SET')}")
    logger.info(f"FLASK_ENV environment variable: {os.environ.get('FLASK_ENV', 'NOT SET')}")

    try:
        app.run(host='0.0.0.0', port=port, debug=debug)
    except Exception as e:
        logger.error(f"Failed to start Flask app: {e}")
        raise