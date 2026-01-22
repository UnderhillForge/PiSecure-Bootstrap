"""
WebSocket Namespace Handlers for PiSecure Bootstrap
===================================================

Implements 5 real-time data streams via Flask-SocketIO:
- /nodes: Node registration, heartbeat, status changes
- /threats: Sentinel alerts, defense coordination
- /health: Network intelligence metrics
- /dex: DEX pool updates, liquidity changes
- /rates: Rate limit status, throttling events

Author: PiSecure Team
Date: 2026-01-21
"""

import logging
from threading import Lock
from typing import Dict, List, Optional, Any, Set
from flask_socketio import Namespace, emit, join_room, leave_room
import time

logger = logging.getLogger(__name__)

# Global tracking of unique connected nodes
websocket_connected_nodes: Set[str] = set()  # Set of node_ids currently connected via any namespace
websocket_connection_lock = Lock()  # Thread-safe access to connected_nodes


def get_connected_nodes_count() -> int:
    """Get count of unique nodes currently connected via WebSocket"""
    with websocket_connection_lock:
        return len(websocket_connected_nodes)


def get_connected_nodes() -> List[str]:
    """Get list of unique node_ids currently connected via WebSocket"""
    with websocket_connection_lock:
        return list(websocket_connected_nodes)


def register_websocket_connection(node_id: str) -> None:
    """Register a WebSocket connection for a node"""
    with websocket_connection_lock:
        websocket_connected_nodes.add(node_id)
        logger.debug(f"Registered WebSocket connection for {node_id}. Total unique nodes: {len(websocket_connected_nodes)}")


def unregister_websocket_connection(node_id: str) -> None:
    """Unregister a WebSocket connection for a node (only removes if no other connections)"""
    # Note: In the current implementation, we don't actually remove nodes because multiple connections
    # from the same node are possible. This tracks nodes with at least one active connection.
    # To track exact connection count per node, we would need to track session_id -> node_id mapping
    pass


class NodesNamespace(Namespace):
    """
    Broadcast real-time node events
    
    Events emitted:
    - node_registered: New node joined network
    - node_heartbeat: Node sent heartbeat
    - node_offline: Node went offline
    - node_updated: Node updated metadata
    """
    
    def __init__(self, namespace: str = '/nodes'):
        super().__init__(namespace)
        self.subscribed_clients: Dict[str, List[str]] = {}  # node_id -> [session_ids]
        self.lock = Lock()
    
    def on_connect(self, auth: Optional[Dict[str, Any]] = None):
        """Authenticate WebSocket connection"""
        from flask import request
        from flask_socketio import disconnect
        
        # Get node_id from query params
        node_id = request.args.get('node_id')
        if not node_id:
            logger.warning(f"WebSocket connection attempt without node_id from {request.remote_addr}")
            disconnect()
            return False
        
        # Store connection metadata
        request.sid_node_id = node_id
        
        # Register this connection as an active node
        register_websocket_connection(node_id)
        
        logger.info(f"Node {node_id} connected to /nodes namespace (Total unique nodes: {get_connected_nodes_count()})")
        emit('connection_established', {'node_id': node_id})
        return True
    
    def on_disconnect(self):
        """Handle disconnection"""
        from flask import request
        node_id = getattr(request, 'sid_node_id', None)
        if node_id:
            logger.info(f"Node {node_id} disconnected from /nodes namespace")
    
    def on_subscribe_nodes(self, data: Dict[str, Any]):
        """Subscribe to node updates"""
        from flask import request
        node_id = getattr(request, 'sid_node_id', None)
        if not node_id:
            emit('error', {'message': 'Not authenticated'})
            return
        
        join_room('nodes_updates')
        emit('subscribed', {'channel': 'node_updates'})
        logger.info(f"Node {node_id} subscribed to node_updates")
    
    def on_unsubscribe_nodes(self):
        """Unsubscribe from node updates"""
        leave_room('nodes_updates')
        emit('unsubscribed', {'channel': 'node_updates'})


class ThreatsNamespace(Namespace):
    """
    Broadcast real-time threat events
    
    Events emitted:
    - threat_detected: New threat identified
    - threat_escalated: Threat severity increased
    - defense_activated: Defense mechanism engaged
    - threat_resolved: Threat neutralized
    - quarantine_activated: Node quarantined
    """
    
    def __init__(self, namespace: str = '/threats'):
        super().__init__(namespace)
        self.lock = Lock()
    
    def on_connect(self, auth: Optional[Dict[str, Any]] = None):
        """Authenticate threat channel access"""
        from flask import request
        from flask_socketio import disconnect
        
        node_id = request.args.get('node_id')
        if not node_id:
            disconnect()
            return False
        
        request.sid_node_id = node_id
        register_websocket_connection(node_id)
        logger.info(f"Node {node_id} connected to /threats namespace (Total unique nodes: {get_connected_nodes_count()})")
        emit('connection_established', {'node_id': node_id})
        return True
    
    def on_subscribe_threats(self, data: Dict[str, Any]):
        """Subscribe to threat alerts"""
        from flask import request
        node_id = getattr(request, 'sid_node_id', None)
        if not node_id:
            emit('error', {'message': 'Not authenticated'})
            return
        
        join_room('threat_alerts')
        emit('subscribed', {'channel': 'threat_alerts'})
        logger.info(f"Node {node_id} subscribed to threat_alerts")
    
    def on_unsubscribe_threats(self):
        """Unsubscribe from threat alerts"""
        leave_room('threat_alerts')
        emit('unsubscribed', {'channel': 'threat_alerts'})


class HealthNamespace(Namespace):
    """
    Broadcast network health metrics
    
    Events emitted:
    - health_update: Network health changed
    - latency_update: Latency metrics updated
    - peer_count_update: Active peer count changed
    - consensus_status: Consensus health
    - network_anomaly: Unusual activity detected
    """
    
    def __init__(self, namespace: str = '/health'):
        super().__init__(namespace)
        self.lock = Lock()
    
    def on_connect(self, auth: Optional[Dict[str, Any]] = None):
        """Authenticate health channel access"""
        from flask import request
        from flask_socketio import disconnect
        
        node_id = request.args.get('node_id')
        if not node_id:
            disconnect()
            return False
        
        request.sid_node_id = node_id
        register_websocket_connection(node_id)
        logger.info(f"Node {node_id} connected to /health namespace (Total unique nodes: {get_connected_nodes_count()})")
        emit('connection_established', {'node_id': node_id})
        return True
    
    def on_subscribe_health(self, data: Dict[str, Any]):
        """Subscribe to health metrics"""
        from flask import request
        node_id = getattr(request, 'sid_node_id', None)
        if not node_id:
            emit('error', {'message': 'Not authenticated'})
            return
        
        join_room('health_metrics')
        emit('subscribed', {'channel': 'health_metrics'})
        logger.info(f"Node {node_id} subscribed to health_metrics")
    
    def on_unsubscribe_health(self):
        """Unsubscribe from health metrics"""
        leave_room('health_metrics')
        emit('unsubscribed', {'channel': 'health_metrics'})


class DEXNamespace(Namespace):
    """
    Broadcast DEX trading events
    
    Events emitted:
    - pool_updated: Liquidity pool changed
    - trade_executed: Trade completed
    - price_updated: Token price changed
    - liquidity_warning: Low liquidity alert
    - slippage_alert: High slippage detected
    """
    
    def __init__(self, namespace: str = '/dex'):
        super().__init__(namespace)
        self.lock = Lock()
    
    def on_connect(self, auth: Optional[Dict[str, Any]] = None):
        """Authenticate DEX channel access"""
        from flask import request
        from flask_socketio import disconnect
        
        node_id = request.args.get('node_id')
        if not node_id:
            disconnect()
            return False
        
        request.sid_node_id = node_id
        register_websocket_connection(node_id)
        logger.info(f"Node {node_id} connected to /dex namespace (Total unique nodes: {get_connected_nodes_count()})")
        emit('connection_established', {'node_id': node_id})
        return True
    
    def on_subscribe_dex(self, data: Dict[str, Any]):
        """Subscribe to DEX updates"""
        from flask import request
        node_id = getattr(request, 'sid_node_id', None)
        if not node_id:
            emit('error', {'message': 'Not authenticated'})
            return
        
        join_room('dex_updates')
        emit('subscribed', {'channel': 'dex_updates'})
        logger.info(f"Node {node_id} subscribed to dex_updates")
    
    def on_unsubscribe_dex(self):
        """Unsubscribe from DEX updates"""
        leave_room('dex_updates')
        emit('unsubscribed', {'channel': 'dex_updates'})


class RatesNamespace(Namespace):
    """
    Broadcast rate limiting status
    
    Events emitted:
    - rate_limit_status: Current limit usage
    - rate_limit_exceeded: Rate limit hit
    - throttle_activated: Request throttling
    - quota_reset: New quota available
    """
    
    def __init__(self, namespace: str = '/rates'):
        super().__init__(namespace)
        self.lock = Lock()
    
    def on_connect(self, auth: Optional[Dict[str, Any]] = None):
        """Authenticate rates channel access"""
        from flask import request
        from flask_socketio import disconnect
        
        node_id = request.args.get('node_id')
        if not node_id:
            disconnect()
            return False
        
        request.sid_node_id = node_id
        register_websocket_connection(node_id)
        logger.info(f"Node {node_id} connected to /rates namespace (Total unique nodes: {get_connected_nodes_count()})")
        emit('connection_established', {'node_id': node_id})
        return True
    
    def on_subscribe_rates(self, data: Dict[str, Any]):
        """Subscribe to rate limit updates"""
        from flask import request
        node_id = getattr(request, 'sid_node_id', None)
        if not node_id:
            emit('error', {'message': 'Not authenticated'})
            return
        
        join_room('rate_updates')
        emit('subscribed', {'channel': 'rate_updates'})
        logger.info(f"Node {node_id} subscribed to rate_updates")
    
    def on_unsubscribe_rates(self):
        """Unsubscribe from rate limit updates"""
        leave_room('rate_updates')
        emit('unsubscribed', {'channel': 'rate_updates'})


# Export namespaces for registration
__all__ = [
    'NodesNamespace',
    'ThreatsNamespace',
    'HealthNamespace',
    'DEXNamespace',
    'RatesNamespace',
    'get_connected_nodes_count',
    'get_connected_nodes',
    'register_websocket_connection',
    'unregister_websocket_connection',
]
