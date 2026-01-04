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

@app.route('/hello', methods=['GET'])
def hello():
    logger.info("Hello World endpoint called")
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>PiSecure Bootstrap - Hello World</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background: #f5f5f5;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                text-align: center;
            }
            h1 {
                color: #2c3e50;
                margin-bottom: 20px;
            }
            .status {
                background: #27ae60;
                color: white;
                padding: 10px 20px;
                border-radius: 5px;
                display: inline-block;
                margin: 20px 0;
            }
            .info {
                background: #3498db;
                color: white;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>=€ PiSecure Bootstrap Node</h1>
            <div class="status"> Service is Running!</div>
            <div class="info">
                <strong>Domain:</strong> bootstrap.pisecure.org<br>
                <strong>Status:</strong> Active and Online<br>
                <strong>Time:</strong> <span id="time"></span>
            </div>
            <p>If you can see this page, DNS and Railway routing are working correctly!</p>
        </div>
        <script>
            function updateTime() {
                document.getElementById('time').textContent = new Date().toLocaleString();
            }
            updateTime();
            setInterval(updateTime, 1000);
        </script>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)