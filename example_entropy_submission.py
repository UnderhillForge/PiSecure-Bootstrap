#!/usr/bin/env python3
"""
Example: Submit hardware entropy to PiSecure Bootstrap
Demonstrates proper usage of /api/v1/hardware/entropy endpoint
"""

import requests
import secrets
import json

# Bootstrap endpoint
BOOTSTRAP_URL = "http://localhost:8080"  # Change to https://bootstrap.pisecure.org in production

def generate_hardware_entropy():
    """
    Generate 32 bytes of entropy from hardware RNG
    In production, this should read from /dev/hwrng on Raspberry Pi
    """
    # Example using Python's secrets module (cryptographically strong)
    entropy_bytes = secrets.token_bytes(32)
    
    # In production on Raspberry Pi, use:
    # with open('/dev/hwrng', 'rb') as hwrng:
    #     entropy_bytes = hwrng.read(32)
    
    return entropy_bytes

def submit_entropy(node_id, entropy_bytes):
    """Submit entropy sample to bootstrap for validation"""
    
    # Convert bytes to hex string
    entropy_hex = entropy_bytes.hex()
    
    # Prepare request
    payload = {
        "node_id": node_id,
        "entropy_hex": entropy_hex
    }
    
    try:
        # Submit to bootstrap
        response = requests.post(
            f"{BOOTSTRAP_URL}/api/v1/hardware/entropy",
            json=payload,
            timeout=10
        )
        
        result = response.json()
        
        if response.status_code == 200:
            print(f"✓ Entropy validation PASSED")
            print(f"  Quality Score: {result['quality_score']:.2f}/100")
            print(f"  Entropy: {result['entropy_estimate_bits_per_byte']:.2f} bits/byte")
            print(f"  Pass Rate: {result['node_entropy_history']['pass_rate']:.1%}")
        else:
            print(f"✗ Entropy validation FAILED")
            print(f"  Quality Score: {result['quality_score']:.2f}/100")
            print(f"  Entropy: {result['entropy_estimate_bits_per_byte']:.2f} bits/byte")
            print(f"  Penalty: {result.get('penalty_applied', 0.0)}")
            print(f"  Recommendation: {result.get('recommendation', 'N/A')}")
            
            # Show which tests failed
            if 'tests' in result:
                print(f"  Failed Tests:")
                for test_name, test_result in result['tests'].items():
                    if not test_result.get('pass', False):
                        print(f"    - {test_name}")
        
        return result
        
    except requests.exceptions.RequestException as e:
        print(f"✗ Network error: {e}")
        return None

def main():
    print("=" * 60)
    print("PiSecure Hardware RNG Entropy Submission Example")
    print("=" * 60)
    print()
    
    # Your node ID
    node_id = "my-miner-node-001"
    
    # Generate and submit entropy samples
    print(f"Submitting entropy samples for node: {node_id}")
    print()
    
    for i in range(3):
        print(f"Sample {i+1}:")
        entropy = generate_hardware_entropy()
        result = submit_entropy(node_id, entropy)
        print()
    
    print("=" * 60)
    print("Note: In production, miners should submit entropy samples")
    print("periodically (e.g., every hour) to maintain verified status.")
    print("=" * 60)

if __name__ == "__main__":
    main()
