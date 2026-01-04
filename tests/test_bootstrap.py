#!/usr/bin/env python3
"""
Tests for PiSecure Bootstrap Node
"""

import pytest
import json
import time
from bootstrap.server import BootstrapNode


class TestBootstrapNode:
    """Test cases for the bootstrap node functionality"""

    def setup_method(self):
        """Setup test fixtures"""
        self.node = BootstrapNode(host='127.0.0.1', port=3143)  # Use different port for testing

    def test_initialization(self):
        """Test bootstrap node initialization"""
        assert self.node.host == '127.0.0.1'
        assert self.node.port == 3143
        assert self.node.api_version == "v1"
        assert isinstance(self.node.registered_nodes, dict)
        assert isinstance(self.node.bootstrap_peers, list)

    def test_parse_bootstrap_peers(self):
        """Test parsing bootstrap peers from environment"""
        # Test empty string
        peers = self.node._parse_bootstrap_peers("")
        assert peers == []

        # Test single peer
        peers = self.node._parse_bootstrap_peers("bootstrap.pisecure.org:3142")
        assert len(peers) == 1
        assert peers[0]['address'] == 'bootstrap.pisecure.org'
        assert peers[0]['port'] == 3142

        # Test multiple peers
        peers = self.node._parse_bootstrap_peers("peer1:3142,peer2:3143")
        assert len(peers) == 2
        assert peers[0]['address'] == 'peer1'
        assert peers[1]['address'] == 'peer2'

    def test_get_verified_bootstrap_peers(self):
        """Test getting verified bootstrap peers"""
        peers = self.node._get_verified_bootstrap_peers()
        assert isinstance(peers, list)
        # Should not exceed limit
        assert len(peers) <= 50

    def test_calculate_network_stats(self):
        """Test network statistics calculation"""
        stats = self.node._calculate_network_stats()
        assert isinstance(stats, dict)
        required_keys = ['active_nodes', 'total_registered_nodes', 'connected_peers']
        for key in required_keys:
            assert key in stats

    def test_count_active_nodes(self):
        """Test counting active nodes"""
        count = self.node._count_active_nodes()
        assert isinstance(count, int)
        assert count >= 0

    def test_node_registration(self):
        """Test node registration functionality"""
        # Test successful registration
        node_data = {
            'node_id': 'test_node_123',
            'address': '192.168.1.100',
            'port': 3142,
            'capabilities': ['p2p_sync', 'mining'],
            'hashrate': 2.5,
            'location': 'test_location'
        }

        # Simulate registration (normally done via HTTP)
        self.node.registered_nodes[node_data['node_id']] = {
            **node_data,
            'registered_at': time.time(),
            'last_seen': time.time(),
            'version': '1.0.0'
        }

        # Verify registration
        assert node_data['node_id'] in self.node.registered_nodes
        registered = self.node.registered_nodes[node_data['node_id']]
        assert registered['address'] == node_data['address']
        assert registered['capabilities'] == node_data['capabilities']

    def test_verified_peers_includes_registered(self):
        """Test that verified peers includes registered nodes"""
        # Register a test node
        node_id = 'test_node_verified'
        self.node.registered_nodes[node_id] = {
            'node_id': node_id,
            'address': '192.168.1.200',
            'port': 3142,
            'capabilities': ['p2p_sync'],
            'last_seen': time.time(),
            'registered_at': time.time()
        }

        # Get verified peers
        verified_peers = self.node._get_verified_bootstrap_peers()

        # Should include our registered node
        node_ids = [peer['node_id'] for peer in verified_peers]
        assert node_id in node_ids


if __name__ == '__main__':
    pytest.main([__file__, '-v'])