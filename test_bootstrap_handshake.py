#!/usr/bin/env python3
"""
Test script for bootstrap node handshake functionality
Simulates a secondary bootstrap node connecting to the primary node
"""

import requests
import json
import time

# Primary bootstrap node endpoint
PRIMARY_BOOTSTRAP_URL = "http://127.0.0.1:8080"

def test_bootstrap_handshake():
    """Test the bootstrap handshake process"""

    # Secondary bootstrap node data
    secondary_node = {
        "node_id": "bootstrap-secondary-001",
        "address": "192.168.1.100",
        "port": 8081,
        "services": ["peer_discovery", "mining_teams", "hardware_verification"],
        "capabilities": ["bootstrap_coordination", "peer_discovery", "network_health"],
        "region": "US-West",
        "version": "1.0.0",
        "reliability_score": 0.95,
        "load_factor": 0.2,
        "supported_protocols": ["p2p_sync", "mining_coordination"]
    }

    print("🚀 Testing Bootstrap Handshake...")
    print(f"Secondary Node: {secondary_node['node_id']}")
    print(f"Services: {', '.join(secondary_node['services'])}")
    print(f"Capabilities: {', '.join(secondary_node['capabilities'])}")
    print()

    try:
        # Step 1: Perform handshake
        handshake_url = f"{PRIMARY_BOOTSTRAP_URL}/api/v1/bootstrap/handshake"
        print(f"📡 Sending handshake to: {handshake_url}")

        response = requests.post(handshake_url, json=secondary_node, timeout=10)

        if response.status_code == 200:
            result = response.json()
            print("✅ Handshake successful!")
            print(f"Primary Node: {result['primary_node']}")
            print(f"Registration Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result['registration_time']))}")
            print(f"Network Info: {result['network_info']}")
            print()
        else:
            print(f"❌ Handshake failed with status {response.status_code}")
            print(f"Error: {response.json()}")
            return

        # Step 2: Test service advertisement
        print("📢 Testing Service Advertisement...")

        advert_data = {
            "node_id": secondary_node["node_id"],
            "services": ["peer_discovery", "mining_teams", "hardware_verification"],
            "status": "active",
            "load_factor": 0.15,
            "current_connections": 45,
            "health_metrics": {
                "cpu_usage": 0.3,
                "memory_usage": 0.6,
                "network_latency": 25
            },
            "service_endpoints": {
                "peer_discovery": "/api/v1/peers",
                "mining_teams": "/api/v1/mining/teams",
                "hardware_verification": "/api/v1/hardware/verify"
            }
        }

        advert_url = f"{PRIMARY_BOOTSTRAP_URL}/api/v1/bootstrap/advertise"
        advert_response = requests.post(advert_url, json=advert_data, timeout=10)

        if advert_response.status_code == 200:
            advert_result = advert_response.json()
            print("✅ Service advertisement successful!")
            print(f"Services acknowledged: {advert_result['services_acknowledged']}")
            print()
        else:
            print(f"❌ Service advertisement failed with status {advert_response.status_code}")
            print(f"Error: {advert_response.json()}")

        # Step 3: Check bootstrap registry
        print("📋 Checking Bootstrap Registry...")

        registry_url = f"{PRIMARY_BOOTSTRAP_URL}/api/v1/bootstrap/registry"
        registry_response = requests.get(registry_url, timeout=10)

        if registry_response.status_code == 200:
            registry = registry_response.json()
            print("✅ Registry access successful!")
            print(f"Primary Node: {registry['primary_node']['node_id']}")
            print(f"Secondary Nodes: {len(registry['secondary_nodes'])}")
            print(f"Total Bootstrap Nodes: {registry['total_nodes']}")
            print(f"Coordination Status: {registry['coordination_status']}")
            print()
        else:
            print(f"❌ Registry access failed with status {registry_response.status_code}")

        # Step 4: Test service coordination
        print("🔄 Testing Service Coordination...")

        coord_data = {
            "requesting_node": "test-client-node",
            "service": "peer_discovery"
        }

        coord_url = f"{PRIMARY_BOOTSTRAP_URL}/api/v1/bootstrap/coordinate"
        coord_response = requests.post(coord_url, json=coord_data, timeout=10)

        if coord_response.status_code == 200:
            coord_result = coord_response.json()
            if coord_result['coordination_success']:
                print("✅ Service coordination successful!")
                print(f"Assigned Node: {coord_result['assigned_node']}")
                print(f"Service: {coord_result['service']}")
                print(f"Endpoint: {coord_result['endpoint']}")
            else:
                print("⚠️  Coordination fallback to primary node")
                print(f"Reason: {coord_result['reason']}")
            print()
        else:
            print(f"❌ Service coordination failed with status {coord_response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"❌ Network error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def test_invalid_handshake():
    """Test invalid handshake attempts"""
    print("\n🛡️  Testing Invalid Handshake Attempts...")

    # Test 1: Missing required fields
    invalid_data = {
        "node_id": "test-node",
        "address": "192.168.1.100"
        # Missing port, services, capabilities
    }

    try:
        response = requests.post(f"{PRIMARY_BOOTSTRAP_URL}/api/v1/bootstrap/handshake",
                               json=invalid_data, timeout=10)
        if response.status_code == 400:
            print("✅ Correctly rejected missing required fields")
        else:
            print(f"❌ Unexpected response: {response.status_code}")
    except Exception as e:
        print(f"❌ Test failed: {e}")

    # Test 2: Invalid bootstrap node
    invalid_bootstrap = {
        "node_id": "not-a-bootstrap",
        "address": "192.168.1.100",
        "port": 8081,
        "services": ["some_service"],
        "capabilities": ["not_bootstrap"]
    }

    try:
        response = requests.post(f"{PRIMARY_BOOTSTRAP_URL}/api/v1/bootstrap/handshake",
                               json=invalid_bootstrap, timeout=10)
        if response.status_code == 403:
            print("✅ Correctly rejected invalid bootstrap credentials")
        else:
            print(f"❌ Unexpected response: {response.status_code}")
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    print("🔗 PiSecure Bootstrap Node Handshake Test")
    print("=" * 50)

    # Test successful handshake
    test_bootstrap_handshake()

    # Test invalid handshakes
    test_invalid_handshake()

    print("\n🏁 Bootstrap handshake testing complete!")