#!/usr/bin/env python3
"""
Test script for EntropyValidator
Validates the NIST SP 800-90B implementation
"""

import secrets
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Import from bootstrap server
from bootstrap.server import EntropyValidator

def test_good_entropy():
    """Test with high-quality random entropy"""
    print("\n=== Testing Good Entropy (from secrets module) ===")
    
    validator = EntropyValidator()
    
    # Generate 32 bytes of cryptographically strong random data
    good_entropy = secrets.token_bytes(32)
    
    result = validator.validate_entropy_sample("test-node-good", good_entropy)
    
    print(f"Valid: {result['valid']}")
    print(f"Quality Score: {result['quality_score']:.2f}/100")
    print(f"Entropy: {result['entropy_estimate_bits_per_byte']:.2f} bits/byte")
    print(f"Chi-Square Test: {'PASS' if result['tests']['chi_square']['pass'] else 'FAIL'}")
    print(f"Runs Test: {'PASS' if result['tests']['runs_test']['pass'] else 'FAIL'}")
    print(f"Longest Run Test: {'PASS' if result['tests']['longest_run']['pass'] else 'FAIL'}")
    
    return result['valid']

def test_bad_entropy_zeros():
    """Test with all zeros (no entropy)"""
    print("\n=== Testing Bad Entropy (All Zeros) ===")
    
    validator = EntropyValidator()
    
    # 32 bytes of zeros - terrible entropy
    bad_entropy = bytes([0] * 32)
    
    result = validator.validate_entropy_sample("test-node-bad", bad_entropy)
    
    print(f"Valid: {result['valid']}")
    print(f"Quality Score: {result['quality_score']:.2f}/100")
    print(f"Entropy: {result['entropy_estimate_bits_per_byte']:.2f} bits/byte")
    print(f"Chi-Square Test: {'PASS' if result['tests']['chi_square']['pass'] else 'FAIL'}")
    print(f"Runs Test: {'PASS' if result['tests']['runs_test']['pass'] else 'FAIL'}")
    print(f"Longest Run Test: {'PASS' if result['tests']['longest_run']['pass'] else 'FAIL'}")
    print(f"Penalty Applied: {result['penalty']}")
    
    return not result['valid']  # Should fail

def test_bad_entropy_pattern():
    """Test with repeating pattern (low entropy)"""
    print("\n=== Testing Bad Entropy (Repeating Pattern) ===")
    
    validator = EntropyValidator()
    
    # Repeating pattern: 0x01, 0x02, 0x03, 0x04 repeated
    bad_entropy = bytes([1, 2, 3, 4] * 8)
    
    result = validator.validate_entropy_sample("test-node-pattern", bad_entropy)
    
    print(f"Valid: {result['valid']}")
    print(f"Quality Score: {result['quality_score']:.2f}/100")
    print(f"Entropy: {result['entropy_estimate_bits_per_byte']:.2f} bits/byte")
    print(f"Chi-Square Test: {'PASS' if result['tests']['chi_square']['pass'] else 'FAIL'}")
    print(f"Runs Test: {'PASS' if result['tests']['runs_test']['pass'] else 'FAIL'}")
    print(f"Longest Run Test: {'PASS' if result['tests']['longest_run']['pass'] else 'FAIL'}")
    print(f"Penalty Applied: {result['penalty']}")
    
    return not result['valid']  # Should fail

def test_node_history():
    """Test that node history tracking works"""
    print("\n=== Testing Node History Tracking ===")
    
    validator = EntropyValidator()
    node_id = "test-node-history"
    
    # Submit 5 samples
    for i in range(5):
        entropy = secrets.token_bytes(32)
        result = validator.validate_entropy_sample(node_id, entropy)
    
    # Check history
    stats = validator.get_node_entropy_stats(node_id)
    
    print(f"Total Samples: {stats['samples_submitted']}")
    print(f"Samples Passed: {stats['samples_passed']}")
    print(f"Samples Failed: {stats['samples_failed']}")
    print(f"Average Quality: {stats['avg_quality']:.2f}")
    
    return stats['samples_submitted'] == 5

def main():
    print("=" * 60)
    print("PiSecure Hardware RNG Entropy Validator Test Suite")
    print("=" * 60)
    
    tests_passed = 0
    tests_total = 4
    
    try:
        if test_good_entropy():
            print("✓ Good entropy test PASSED")
            tests_passed += 1
        else:
            print("✗ Good entropy test FAILED")
    except Exception as e:
        print(f"✗ Good entropy test ERROR: {e}")
    
    try:
        if test_bad_entropy_zeros():
            print("✓ Bad entropy (zeros) test PASSED")
            tests_passed += 1
        else:
            print("✗ Bad entropy (zeros) test FAILED")
    except Exception as e:
        print(f"✗ Bad entropy (zeros) test ERROR: {e}")
    
    try:
        if test_bad_entropy_pattern():
            print("✓ Bad entropy (pattern) test PASSED")
            tests_passed += 1
        else:
            print("✗ Bad entropy (pattern) test FAILED")
    except Exception as e:
        print(f"✗ Bad entropy (pattern) test ERROR: {e}")
    
    try:
        if test_node_history():
            print("✓ Node history tracking test PASSED")
            tests_passed += 1
        else:
            print("✗ Node history tracking test FAILED")
    except Exception as e:
        print(f"✗ Node history tracking test ERROR: {e}")
    
    print("\n" + "=" * 60)
    print(f"Test Results: {tests_passed}/{tests_total} passed")
    print("=" * 60)
    
    return tests_passed == tests_total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
