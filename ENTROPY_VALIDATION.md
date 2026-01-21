# RNG Entropy Validation Implementation

## Overview
Implemented hardware RNG entropy validation for PiSecure mining nodes using NIST SP 800-90B statistical tests. This ensures miners submit genuine hardware randomness rather than pseudo-random or low-entropy data.

## Implementation Details

### 1. EntropyValidator Class
**Location:** `bootstrap/server.py` (lines ~1150-1430)

**Features:**
- **NIST SP 800-90B Statistical Tests:**
  - Chi-Square Test: Validates uniform byte distribution
  - Runs Test: Detects non-random patterns in bit sequences
  - Longest Run Test: Identifies abnormal consecutive bit runs
  - Shannon Entropy: Measures bits of entropy per byte

- **Quality Scoring (0-100):**
  - Chi-square contribution: 30 points
  - Runs test contribution: 25 points
  - Longest run contribution: 20 points
  - Entropy estimate contribution: 25 points

- **Thresholds:**
  - Minimum entropy: 4.5 bits/byte (realistic for 32-byte samples)
  - Low entropy penalty: -10.0 reputation points
  - Failed tests penalty: -5.0 reputation points

### 2. API Endpoint
**Route:** `POST /api/v1/hardware/entropy`

**Request Format:**
```json
{
  "node_id": "miner-node-123",
  "entropy_hex": "a1b2c3d4e5f6..."  // 32 bytes as hex (64 chars)
}
```

**Success Response (200):**
```json
{
  "validation_result": true,
  "quality_score": 87.5,
  "entropy_estimate_bits_per_byte": 5.2,
  "node_id": "miner-node-123",
  "timestamp": 1234567890.0,
  "node_entropy_history": {
    "total_samples": 15,
    "pass_rate": 0.93,
    "avg_quality": 85.2
  }
}
```

**Failure Response (400):**
```json
{
  "validation_result": false,
  "quality_score": 32.1,
  "entropy_estimate_bits_per_byte": 2.1,
  "tests": {
    "chi_square": { "pass": false, "chi_square_statistic": 450.2, ... },
    "runs_test": { "pass": true, ... },
    "longest_run": { "pass": true, ... }
  },
  "penalty_applied": -10.0,
  "recommendation": "Improve hardware RNG quality or verify /dev/hwrng is properly configured",
  "node_entropy_history": { ... }
}
```

### 3. Node Tracking Integration
**Location:** `bootstrap/server.py` NodeTracker class

**Added Fields:**
- `entropy_quality_score`: Tracks latest quality score per node
- `entropy_verified`: Boolean flag for verified RNG status
- `entropy_quality` dict: Separate tracking structure

**Methods:**
- `update_entropy_quality(node_id, quality_score, verified)`: Updates tracking
- `get_entropy_quality(node_id)`: Retrieves entropy stats

### 4. Sentinel Integration
**Location:** `pisecure/api/sentinel.py`

**New Method:** `record_incident(incident_data)`
- Records low-entropy incidents
- Applies reputation penalties automatically
- Updates network standing (quarantine/blacklist)
- Tracks incident history per node

**Incident Type:** `low_entropy_rng`
- Severity levels: `high` (< 3.0 bits/byte), `medium` (3.0-4.5 bits/byte)
- Automatic reputation adjustments
- Evidence tracking for audit trail

## Usage Examples

### For Mining Nodes

**Reading from /dev/hwrng (Raspberry Pi):**
```python
import requests

# Read 32 bytes from hardware RNG
with open('/dev/hwrng', 'rb') as hwrng:
    entropy_bytes = hwrng.read(32)

# Submit to bootstrap
response = requests.post(
    "https://bootstrap.pisecure.org/api/v1/hardware/entropy",
    json={
        "node_id": "my-miner-node",
        "entropy_hex": entropy_bytes.hex()
    }
)

result = response.json()
print(f"Valid: {result['validation_result']}")
print(f"Quality: {result['quality_score']:.2f}")
```

### For Bootstrap Operators

**Check node entropy status:**
```python
entropy_stats = node_tracker.get_entropy_quality("miner-node-123")
print(f"Verified: {entropy_stats['verified']}")
print(f"Quality: {entropy_stats['quality_score']:.2f}")
```

**Check Sentinel reputation impact:**
```python
rep = sentinel_service.get_node_reputation("miner-node-123")
print(f"Reputation: {rep['reputation_score']}")
print(f"Incidents: {rep['incident_count']}")
```

## Testing

**Test Suite:** `test_entropy_validator.py`

Run tests:
```bash
python3 test_entropy_validator.py
```

Expected results:
- Good entropy (from secrets): PASS
- Bad entropy (all zeros): Correctly rejected
- Bad entropy (pattern): Correctly rejected  
- Node history tracking: PASS

**Example Usage:** `example_entropy_submission.py`

## Security Benefits

1. **Prevents Pseudo-Random Attacks:** Miners cannot fake entropy using PRNGs
2. **Detects Hardware Failures:** Identifies failing/misconfigured RNG devices
3. **Reputation-Based Trust:** Low-quality submissions damage node reputation
4. **Network Protection:** Quarantines nodes with consistently poor entropy
5. **Audit Trail:** Full history of entropy submissions per node

## Configuration

**Environment Variables:**
None required - uses default thresholds optimized for 32-byte samples.

**Adjustable Parameters** (in code):
- `MIN_ENTROPY_BITS_PER_BYTE`: Minimum acceptable entropy (default: 4.5)
- `PENALTY_LOW_ENTROPY`: Reputation penalty for low entropy (default: -10.0)
- `PENALTY_FAILED_TESTS`: Penalty for failing tests (default: -5.0)

## Future Enhancements

1. **Adaptive Thresholds:** Adjust based on hardware capabilities
2. **Periodic Re-validation:** Require entropy submissions every N hours
3. **Hardware Fingerprinting:** Detect specific RNG device signatures
4. **Cross-Node Correlation:** Detect miners sharing/copying entropy
5. **Blockchain Anchoring:** Store entropy hashes on-chain for proof

## References

- NIST SP 800-90B: Recommendation for the Entropy Sources Used for Random Bit Generation
- Chi-Square Test: Statistical uniformity validation
- Runs Test (Wald-Wolfowitz): Independence testing
- Shannon Entropy: Information theory measure of randomness

## Files Modified

1. `bootstrap/server.py`: Added EntropyValidator class and API endpoint
2. `pisecure/api/sentinel.py`: Added record_incident() method
3. `README.md`: Documented new endpoint and requirements
4. `test_entropy_validator.py`: Comprehensive test suite (new file)
5. `example_entropy_submission.py`: Usage example (new file)

## Backward Compatibility

✓ Fully backward compatible - existing nodes continue to function
✓ New endpoint is optional - does not affect node registration
✓ Entropy validation is additive - enhances security without breaking changes
