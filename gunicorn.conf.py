# Gunicorn configuration for PiSecure Bootstrap Node
# Production-ready configuration for Railway deployment

import multiprocessing
import os

# Server socket
bind = "0.0.0.0:8080"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50

# Timeout settings
timeout = 30
keepalive = 2
graceful_timeout = 30

# Logging
loglevel = os.getenv('LOG_LEVEL', 'info').lower()
accesslog = "-"
errorlog = "-"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'pisecure_bootstrap'

# Server mechanics
preload_app = True
pidfile = '/tmp/gunicorn.pid'
user = None
group = None
tmp_upload_dir = None

# SSL (if needed in future)
# keyfile = "/path/to/ssl/key.pem"
# certfile = "/path/to/ssl/cert.pem"

# Development overrides
if os.getenv('FLASK_ENV') == 'development':
    workers = 2
    loglevel = 'debug'
    reload = True
    preload_app = False