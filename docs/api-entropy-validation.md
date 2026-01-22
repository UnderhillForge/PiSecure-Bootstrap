# Hardware Entropy Validation API Specification

## Overview
PiSecure Bootstrap nodes validate hardware RNG entropy using NIST SP 800-90B statistical tests. This document provides complete API specifications for production deployment.

---

## 1. Endpoint Specifications

### POST /api/v1/hardware/entropy

**Purpose:** Submit 32-byte hardware RNG samples for validation

**URL:** 
- Production: `https://bootstrap.pisecure.org/api/v1/hardware/entropy`
- Testnet: `https://bootstrap-testnet.pisecure.org/api/v1/hardware/entropy`

**Authentication:** Node must be registered (checked via `node_id`)

**Rate Limiting:** 
- **Per Node:** 100 requests/hour (recommended: 1 per hour)
- **Global:** 10,000 requests/hour across all nodes
- **Exceeded:** HTTP 429 with `Retry-After` header

**Required Headers:**
```http
Content-Type: application/json
User-Agent: PiSecure-Miner/1.0 (Platform; Hardware)
```

**Optional Headers:**
```http
X-Node-Signature: <ECDSA signature of request body>
X-API-Version: 1.0
X-Network: mainnet|testnet
```

---

## 2. Request Format

### Complete Schema

```json
{
  "node_id": "string (required, 8-64 chars)",
  "entropy_hex": "string (required, exactly 64 hex chars = 32 bytes)",
  "network": "string (optional, default: mainnet)",
  "timestamp": "number (optional, unix timestamp)",
  "metadata": {
    "hardware_source": "string (optional, e.g., '/dev/hwrng')",
    "collection_method": "string (optional)"
  }
}
```

### Example Request

```bash
curl -X POST https://bootstrap.pisecure.org/api/v1/hardware/entropy \
  -H "Content-Type: application/json" \
  -H "User-Agent: PiSecure-Miner/1.0" \
  -d '{
    "node_id": "miner-rpi5-001",
    "entropy_hex": "a7f3c2d8e1b49056f8e3a2c7d1b84920e5f6a8c3d2b71043f9e2a7c8d3b61928",
    "network": "mainnet"
  }'
```

### Validation Rules

| Field | Type | Constraints |
|-------|------|-------------|
| `node_id` | string | Must be registered, 8-64 chars, alphanumeric + hyphens |
| `entropy_hex` | string | Exactly 64 hex chars (32 bytes), lowercase a-f0-9 |
| `network` | string | One of: `mainnet`, `testnet` (default: mainnet) |

---

## 3. Response Formats

### Success Response (HTTP 200)

```json
{
  "validation_result": true,
  "quality_score": 87.5,
  "entropy_estimate_bits_per_byte": 5.2,
  "node_id": "miner-rpi5-001",
  "timestamp": 1737475200.0,
  "node_entropy_history": {
    "total_samples": 24,
    "pass_rate": 0.958,
    "avg_quality": 85.3,
    "samples_passed": 23,
    "samples_failed": 1,
    "last_submission": 1737475200.0
  },
  "reputation_impact": 0.0,
  "next_submission_recommended": 1737478800.0
}
```

### Failure Response (HTTP 400)

```json
{
  "validation_result": false,
  "quality_score": 32.1,
  "entropy_estimate_bits_per_byte": 2.1,
  "node_id": "miner-rpi5-001",
  "timestamp": 1737475200.0,
  "tests": {
    "chi_square": {
      "pass": false,
      "chi_square_statistic": 450.23,
      "critical_value": 293.25,
      "p_value": 0.0001,
      "description": "Tests uniform byte distribution"
    },
    "runs_test": {
      "pass": true,
      "runs": 128,
      "expected_runs": 129.5,
      "z_score": -0.15,
      "threshold": 1.96,
      "description": "Tests independence of bit sequences"
    },
    "longest_run": {
      "pass": true,
      "longest_run": 8,
      "threshold": 12.0,
      "total_bits": 256,
      "description": "Tests for abnormal consecutive runs"
    }
  },
  "penalty_applied": -10.0,
  "recommendation": "Improve hardware RNG quality or verify /dev/hwrng is properly configured",
  "node_entropy_history": {
    "total_samples": 10,
    "pass_rate": 0.60,
    "avg_quality": 58.2,
    "samples_passed": 6,
    "samples_failed": 4,
    "last_submission": 1737475200.0
  },
  "reputation_impact": -10.0,
  "severity": "high"
}
```

### Error Responses

#### Invalid Format (HTTP 400)
```json
{
  "error": "Invalid hex format for entropy_hex",
  "error_code": "INVALID_FORMAT",
  "details": "Expected 64 hex characters, got 62"
}
```

#### Node Not Registered (HTTP 403)
```json
{
  "error": "Node not registered. Please register first.",
  "error_code": "NODE_NOT_REGISTERED",
  "registration_endpoint": "/api/v1/nodes/register"
}
```

#### Rate Limited (HTTP 429)
```json
{
  "error": "Rate limit exceeded",
  "error_code": "RATE_LIMIT_EXCEEDED",
  "retry_after": 3600,
  "limit": "100 requests per hour",
  "current_usage": 101
}
```

#### Server Error (HTTP 500)
```json
{
  "error": "Entropy validation failed",
  "error_code": "INTERNAL_ERROR",
  "timestamp": 1737475200.0
}
```

---

## 4. HTTP Status Codes

| Code | Meaning | Usage |
|------|---------|-------|
| 200 | Success | Entropy validation passed |
| 400 | Bad Request | Invalid entropy, failed validation, or malformed request |
| 403 | Forbidden | Node not registered |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server-side validation error |
| 503 | Service Unavailable | Bootstrap server maintenance |

---

## 5. Reputation System Integration

### Quality Score Thresholds

| Quality Score | Action | Reputation Impact |
|---------------|--------|-------------------|
| 80-100 | ✅ Excellent | +0.0 (neutral) |
| 50-79 | ✅ Acceptable | +0.0 (neutral) |
| 30-49 | ⚠️ Warning | -5.0 points |
| 0-29 | ❌ Failed | -10.0 points |

### Entropy Estimate Thresholds

| Bits/Byte | Severity | Action |
|-----------|----------|--------|
| ≥ 4.5 | Normal | Pass |
| 3.0-4.4 | Medium | Warn + -5.0 reputation |
| < 3.0 | High | Fail + -10.0 reputation |

### Progressive Penalties

```
Consecutive Failures → Action
1-2 failures       → Warning logged
3-5 failures       → -5.0 reputation each
6-10 failures      → -10.0 reputation each  
11+ failures       → Quarantine (90 days)
20+ failures       → Blacklist (permanent)
```

### Reputation Recovery

Nodes can recover reputation through:
- **Consistent Good Submissions:** +0.5 per passing submission after 10 consecutive passes
- **Time-Based Recovery:** +1.0 per week of zero incidents (max +10/month)
- **Manual Appeal:** Contact bootstrap operator for review

### Reputation Query Endpoint

**GET /api/v1/nodes/{node_id}/reputation**

Response:
```json
{
  "node_id": "miner-rpi5-001",
  "reputation_score": 45.0,
  "trust_level": "neutral",
  "network_standing": "active",
  "incident_count": 5,
  "last_incident": 1737400000.0,
  "positive_contributions": 18,
  "entropy_quality": {
    "verified": false,
    "quality_score": 32.1,
    "last_updated": 1737475200.0
  }
}
```

---

## 6. Test Results Schema

### Complete Test Object Structure

```typescript
interface TestResult {
  pass: boolean;
  description: string;
  [key: string]: any;  // Test-specific fields
}

interface ChiSquareTest extends TestResult {
  chi_square_statistic: number;
  critical_value: number;
  p_value: number;
  degrees_of_freedom: number;
}

interface RunsTest extends TestResult {
  runs: number;
  expected_runs: number;
  z_score: number;
  threshold: number;
  n_ones: number;
  n_zeros: number;
}

interface LongestRunTest extends TestResult {
  longest_run: number;
  threshold: number;
  total_bits: number;
  expected_max: number;
}
```

### Pass/Fail Thresholds

| Test | Pass Criteria | Typical Range |
|------|---------------|---------------|
| Chi-Square | χ² < 293.25 (α=0.05, df=255) | 200-300 |
| Runs Test | \|z-score\| < 1.96 | -1.5 to +1.5 |
| Longest Run | max_run ≤ 12 (for 256 bits) | 6-10 |
| Entropy | ≥ 4.5 bits/byte | 4.5-6.5 |

### Detailed Test Breakdown Endpoint

**GET /api/v1/hardware/entropy/{submission_id}/details**

Returns full test breakdown with additional diagnostic info.

---

## 7. Operational Guidelines

### Submission Frequency

**Recommended Schedule:**
```
Initial Registration → Submit immediately (required within 1 hour)
Active Mining        → Every 1-2 hours
Idle Node           → Every 24 hours (keep alive)
After RNG Change    → Immediate re-validation required
```

**Rate Limits:**
- Minimum interval: 5 minutes (to avoid spam)
- Maximum interval: 24 hours (to maintain verified status)
- Recommended: 1 hour intervals during active mining

### Testnet vs Mainnet

**Network Isolation:**
- Separate bootstrap servers with independent databases
- Use `X-Network` header or `network` field to specify
- Testnet allows more lenient thresholds for development

**Endpoints:**
```
Mainnet:  https://bootstrap.pisecure.org/api/v1/hardware/entropy
Testnet:  https://bootstrap-testnet.pisecure.org/api/v1/hardware/entropy
```

**Query Parameter Alternative:**
```bash
# Also supported:
curl https://bootstrap.pisecure.org/api/v1/hardware/entropy?network=testnet
```

### Fallback & Resilience

**Bootstrap Server Unreachable:**
```python
try:
    response = requests.post(entropy_endpoint, json=payload, timeout=10)
except requests.exceptions.RequestException:
    # Fallback behavior:
    # 1. Log warning (don't block mining)
    # 2. Cache entropy sample for later submission
    # 3. Continue mining with local validation
    # 4. Retry with exponential backoff
    pass
```

**Retry Logic (Recommended):**
```python
import time
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

retry_strategy = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    backoff_factor=2,  # 2s, 4s, 8s
    allowed_methods=["POST"]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.Session()
session.mount("https://", adapter)
```

**Failed Validation Behavior:**
- **During Mining:** Log warning, continue mining (don't block)
- **During Validation:** Flag node, reduce validator weight
- **Persistent Failures:** After 10+ consecutive failures, recommend hardware check

### Historical Data Access

**GET /api/v1/nodes/{node_id}/entropy-history**

Query Parameters:
- `limit` (default: 100, max: 1000)
- `offset` (for pagination)
- `since` (unix timestamp)
- `until` (unix timestamp)

Response:
```json
{
  "node_id": "miner-rpi5-001",
  "total_submissions": 500,
  "entries": [
    {
      "submission_id": "entropy-abc123",
      "timestamp": 1737475200.0,
      "validation_result": true,
      "quality_score": 87.5,
      "entropy_estimate": 5.2,
      "reputation_impact": 0.0
    }
  ],
  "pagination": {
    "limit": 100,
    "offset": 0,
    "total": 500,
    "next": "/api/v1/nodes/miner-rpi5-001/entropy-history?limit=100&offset=100"
  },
  "summary": {
    "pass_rate": 0.94,
    "avg_quality": 85.2,
    "trend": "stable"
  }
}
```

---

## 8. Security Considerations

### Request Signing (Optional but Recommended)

```python
import hashlib
import hmac
from ecdsa import SigningKey

# Generate signature
signing_key = SigningKey.from_pem(node_private_key)
message = json.dumps(payload, sort_keys=True).encode()
signature = signing_key.sign(message).hex()

headers = {
    "X-Node-Signature": signature,
    "X-Node-Public-Key": node_public_key.hex()
}
```

Bootstrap server validates signature against registered public key.

### Anti-Replay Protection

- Include `timestamp` field (must be within ±5 minutes of server time)
- Server tracks recent submission IDs to prevent replay attacks

### DDoS Protection

- Rate limiting per IP and per node_id
- Entropy validation bypasses some DDoS checks (whitelisted endpoint)
- Large-scale attacks trigger circuit breaker (temp disable new registrations)

---

## 9. Error Handling Best Practices

### Client-Side Implementation

```python
def submit_entropy(node_id, entropy_bytes):
    payload = {
        "node_id": node_id,
        "entropy_hex": entropy_bytes.hex(),
        "timestamp": time.time()
    }
    
    try:
        response = requests.post(
            ENTROPY_ENDPOINT,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            # Success - cache result
            return handle_success(response.json())
        
        elif response.status_code == 400:
            # Validation failed - log and retry with new sample
            result = response.json()
            log_validation_failure(result)
            return retry_with_new_sample()
        
        elif response.status_code == 429:
            # Rate limited - wait and retry
            retry_after = int(response.headers.get('Retry-After', 3600))
            time.sleep(retry_after)
            return submit_entropy(node_id, entropy_bytes)
        
        elif response.status_code == 503:
            # Server maintenance - cache for later
            cache_for_later_submission(payload)
            return None
            
        else:
            # Unexpected error
            log_error(response.status_code, response.text)
            return None
            
    except requests.exceptions.Timeout:
        # Network timeout - retry with backoff
        return retry_with_backoff()
        
    except requests.exceptions.ConnectionError:
        # Server unreachable - fallback mode
        return fallback_local_validation()
```

---

## 10. Monitoring & Observability

### Metrics to Track

**Node-Side:**
- Entropy submission success rate
- Average quality scores over time
- Validation response times
- Reputation score trend

**Bootstrap-Side:**
- Submissions per minute (by network)
- Average quality scores across network
- Failure rates by severity
- Geographic distribution of entropy quality

### Logging Recommendations

```python
import logging

logger.info(f"Entropy submitted: quality={quality_score:.2f}, "
            f"entropy={entropy_estimate:.2f} bits/byte")

if not validation_result:
    logger.warning(f"Entropy validation failed: {failed_tests}, "
                   f"penalty={penalty}, recommendation={recommendation}")

if reputation_score < 30:
    logger.error(f"Low reputation: {reputation_score}, "
                 f"consecutive_failures={consecutive_failures}")
```

---

## 11. Integration Examples

### Complete Python Implementation

```python
#!/usr/bin/env python3
import requests
import time
import logging

class EntropySubmitter:
    def __init__(self, node_id, bootstrap_url, network="mainnet"):
        self.node_id = node_id
        self.bootstrap_url = bootstrap_url
        self.network = network
        self.endpoint = f"{bootstrap_url}/api/v1/hardware/entropy"
        self.logger = logging.getLogger(__name__)
        
    def read_hardware_entropy(self, num_bytes=32):
        """Read from /dev/hwrng on Raspberry Pi"""
        try:
            with open('/dev/hwrng', 'rb') as hwrng:
                return hwrng.read(num_bytes)
        except IOError as e:
            self.logger.error(f"Failed to read /dev/hwrng: {e}")
            return None
    
    def submit(self):
        """Submit entropy sample to bootstrap"""
        entropy = self.read_hardware_entropy()
        if not entropy:
            return None
        
        payload = {
            "node_id": self.node_id,
            "entropy_hex": entropy.hex(),
            "network": self.network,
            "timestamp": time.time()
        }
        
        try:
            response = requests.post(
                self.endpoint,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            result = response.json()
            
            if response.status_code == 200:
                self.logger.info(
                    f"✓ Entropy validated: quality={result['quality_score']:.2f}"
                )
            else:
                self.logger.warning(
                    f"✗ Entropy failed: quality={result['quality_score']:.2f}, "
                    f"penalty={result.get('penalty_applied', 0)}"
                )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Entropy submission error: {e}")
            return None
    
    def run_periodic(self, interval_seconds=3600):
        """Run periodic entropy submissions"""
        while True:
            self.submit()
            time.sleep(interval_seconds)

# Usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    submitter = EntropySubmitter(
        node_id="my-miner-001",
        bootstrap_url="https://bootstrap.pisecure.org",
        network="mainnet"
    )
    
    # Submit every hour
    submitter.run_periodic(interval_seconds=3600)
```

---

## 12. FAQ

**Q: What happens if I don't submit entropy?**  
A: Your node remains functional but won't have verified RNG status. Future validator selection may prioritize verified nodes.

**Q: Can I submit entropy more frequently than hourly?**  
A: Yes, but rate limits apply (100/hour max). Recommended: 1-2 hour intervals.

**Q: What if my hardware RNG is slow?**  
A: 32 bytes should generate instantly. If slower, check `/dev/hwrng` configuration or consider hardware upgrade.

**Q: Do validation failures affect block mining immediately?**  
A: No. Currently logs warnings only. Future phases may reduce validator weights.

**Q: Can I appeal a quarantine/blacklist?**  
A: Yes. Contact bootstrap operator with evidence of fixed hardware. Manual review required.

**Q: Are there penalties for good entropy submissions?**  
A: No. Passing submissions have neutral impact (0.0). Future: bonus rewards for consistently high quality.

---

## Version History

- **v1.0** (2026-01-21): Initial API specification
- Future: Rate limit adjustments, bonus rewards, automatic quarantine recovery

---

For implementation details, see [ENTROPY_VALIDATION.md](../ENTROPY_VALIDATION.md)
