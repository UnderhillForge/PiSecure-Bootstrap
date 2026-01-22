# PiSecure Team Q&A: Entropy Validation Implementation

## Comprehensive Answers to Integration Questions

Date: January 21, 2026  
Implementation Status: ✅ Complete with full API specification

---

## 1. API Specifications & Integration

### Entropy Submission Endpoint Details

**Q: Is POST /api/v1/hardware/entropy the complete endpoint?**

✅ Yes, complete endpoint specification:
- **Production**: `https://bootstrap.pisecure.org/api/v1/hardware/entropy`
- **Testnet**: `https://bootstrap-testnet.pisecure.org/api/v1/hardware/entropy`

**Q: Required headers?**

```http
Content-Type: application/json (required)
User-Agent: PiSecure-Miner/1.0 (recommended)
X-Network: mainnet|testnet (optional, default: mainnet)
X-API-Version: 1.0 (optional, for future versioning)
X-Node-Signature: <ECDSA signature> (optional, recommended for security)
```

**Q: Authentication required?**

- **Current**: Node registration check only (via `node_id` validation)
- **Future (recommended)**: ECDSA signature verification using registered public key
- **API Keys**: Not currently required
- **JWT**: Not implemented (consider for Phase 3)

**Q: Rate limiting per node?**

Yes, multi-level rate limiting:
```
Per Node:    100 requests/hour (avg: 1 per hour recommended)
Per IP:      200 requests/hour (allows multiple nodes per IP)
Global:      10,000 requests/hour (network-wide)
Exceeded:    HTTP 429 with Retry-After header
```

**Q: Maximum entropy sample size?**

✅ **Exactly 32 bytes** (64 hex characters)
- Smaller samples rejected (HTTP 400)
- Larger samples rejected (HTTP 400)
- Format: lowercase hex string (a-f0-9)

---

## 2. Response Formats

### Complete Response Schema

**Success (HTTP 200):**
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

**Additional Fields Beyond Documented:**
- ✅ `reputation_impact`: Shows reputation change (-10.0 to 0.0)
- ✅ `next_submission_recommended`: Unix timestamp for next submission
- ✅ `severity`: Included on failures ("high", "medium", "low")
- ✅ `node_entropy_history.last_submission`: Track last successful submission

**Error Response Format:**
```json
{
  "error": "Detailed error message",
  "error_code": "ENUM_ERROR_CODE",
  "details": "Additional context",
  "timestamp": 1737475200.0,
  "retry_after": 3600  // Seconds (for 429 only)
}
```

### HTTP Status Codes

| Code | Usage | Response Body |
|------|-------|---------------|
| 200 | Validation passed | Full validation result |
| 400 | Invalid entropy/failed tests | Result + test details |
| 403 | Node not registered | Error with registration link |
| 429 | Rate limited | Error + retry_after |
| 500 | Server error | Error + timestamp |
| 503 | Maintenance | Error + estimated_downtime |

---

## 3. Reputation System Integration

### Quality Score Thresholds

**Q: At what quality_score threshold does reputation penalty trigger?**

```
Score Range  → Reputation Impact → Action
80-100       → +0.0 (neutral)    → ✅ Excellent
50-79        → +0.0 (neutral)    → ✅ Acceptable  
30-49        → -5.0 points       → ⚠️  Warning
0-29         → -10.0 points      → ❌ Failed
```

Additionally, entropy estimate triggers:
```
Entropy (bits/byte) → Severity → Penalty
≥ 4.5               → Normal   → 0.0
3.0-4.4             → Medium   → -5.0
< 3.0               → High     → -10.0
```

### Progressive Penalty System

**Q: How many consecutive failures before quarantine/blacklist?**

```
Consecutive Failures → Action
1-2                  → Warning logged (no penalty)
3-5                  → -5.0 reputation each
6-10                 → -10.0 reputation each
11-20                → Quarantine (90 days, can appeal)
21+                  → Blacklist (permanent, requires manual review)
```

### Reputation Recovery

**Q: Can nodes recover reputation after improvement?**

✅ **Yes, multiple recovery mechanisms:**

1. **Consistent Good Submissions**:
   - After 10 consecutive passing submissions: +0.5 per additional pass
   - Maximum recovery rate: +5.0 per week

2. **Time-Based Recovery**:
   - No incidents for 7 days: +1.0 reputation
   - Maximum: +4.0 per month via time-based recovery

3. **Quarantine Appeal**:
   - Node provides evidence of hardware fix
   - Manual review by bootstrap operator
   - If approved: quarantine lifted + reputation reset to 50.0

4. **Automatic Recovery from Quarantine**:
   - After 90 days with zero incidents: automatic review
   - 5 consecutive passing submissions required to exit quarantine

### Reputation Query Endpoint

**Q: Is there an endpoint to query current reputation?**

✅ **Yes**: `GET /api/v1/nodes/{node_id}/reputation`

**Response:**
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
    "last_updated": 1737475200.0,
    "consecutive_passes": 0,
    "consecutive_failures": 3
  },
  "quarantine_info": {
    "is_quarantined": false,
    "quarantine_until": null,
    "reason": null
  }
}
```

---

## 4. Test Results Details

### Complete Test Schema

**Q: What's the complete schema for each test?**

```typescript
interface ChiSquareTest {
  pass: boolean;
  chi_square_statistic: number;      // Actual χ² value
  critical_value: number;            // Threshold (293.25 for α=0.05)
  p_value: number;                   // Probability value
  degrees_of_freedom: number;        // 255 (256 categories - 1)
  description: string;               // "Tests uniform byte distribution"
}

interface RunsTest {
  pass: boolean;
  runs: number;                      // Observed runs
  expected_runs: number;             // Theoretical expected value
  z_score: number;                   // Standardized score
  threshold: number;                 // 1.96 (95% confidence)
  n_ones: number;                    // Count of 1 bits
  n_zeros: number;                   // Count of 0 bits
  description: string;               // "Tests independence of bit sequences"
}

interface LongestRunTest {
  pass: boolean;
  longest_run: number;               // Max consecutive 1s found
  threshold: number;                 // Maximum allowed (12 for 256 bits)
  total_bits: number;                // 256
  expected_max: number;              // Theoretical expectation
  description: string;               // "Tests for abnormal consecutive runs"
}
```

### Pass/Fail Thresholds

**Q: Are there pass/fail thresholds documented for each test?**

✅ **Yes:**

| Test | Pass Criteria | Typical Good Range | Failure Indicator |
|------|---------------|-------------------|-------------------|
| Chi-Square | χ² < 293.25 | 200-300 | > 400 (very non-uniform) |
| Runs Test | \|z\| < 1.96 | -1.5 to +1.5 | > 3.0 (clear pattern) |
| Longest Run | max ≤ 12 | 6-10 | > 15 (long sequences) |
| Entropy | ≥ 4.5 bits/byte | 4.8-6.0 | < 3.0 (low randomness) |

### Detailed Test Breakdown

**Q: Can nodes request detailed test breakdowns for debugging?**

✅ **Two ways:**

1. **Automatic on failure**: Full test details included in 400 response
2. **Historical query**: `GET /api/v1/hardware/entropy/{submission_id}/details`

**Detailed breakdown response:**
```json
{
  "submission_id": "entropy-abc123",
  "timestamp": 1737475200.0,
  "validation_result": false,
  "quality_score": 32.1,
  "tests": {
    "chi_square": {
      "pass": false,
      "chi_square_statistic": 450.23,
      "critical_value": 293.25,
      "p_value": 0.0001,
      "degrees_of_freedom": 255,
      "byte_distribution": [12, 8, 15, ...],  // Frequency of each byte
      "expected_frequency": 0.125,
      "description": "Distribution is highly non-uniform"
    }
  },
  "raw_entropy_hex": "a7f3c2d8...",  // Only in detailed view
  "diagnostic_info": {
    "hardware_source": "/dev/hwrng",
    "collection_method": "direct_read",
    "possible_issues": [
      "RNG device may be unconfigured",
      "Consider installing rng-tools package"
    ]
  }
}
```

---

## 5. Operational Questions

### Submission Frequency

**Q: How often should nodes submit entropy samples?**

**Recommended Schedule:**
```
Registration Phase:
  → Submit within 1 hour of registration (required)

Active Mining:
  → Every 1-2 hours (recommended)
  → Minimum interval: 5 minutes (rate limit protection)
  → Maximum interval: 24 hours (to maintain verified status)

Idle Node:
  → Every 24 hours (keep-alive)

After Hardware Change:
  → Immediate re-validation required
```

**Per Block Mining?**
- ❌ **No** - Too frequent, would hit rate limits
- Use hourly submission instead

**On-Demand During Mining?**
- ✅ **Yes** - Allowed but count toward rate limits
- Better to use periodic submission strategy

---

### Testnet Support

**Q: Separate bootstrap server for testnet?**

✅ **Yes, network isolation:**

```
Production:
  - URL: https://bootstrap.pisecure.org
  - Database: Separate from testnet
  - Stricter thresholds

Testnet:
  - URL: https://bootstrap-testnet.pisecure.org
  - Database: Isolated testnet DB
  - More lenient thresholds (e.g., 4.0 bits/byte minimum)
```

**Q: Same API endpoints but different data isolation?**

✅ **Yes, two ways to specify network:**

1. **Different servers** (recommended):
```bash
curl https://bootstrap.pisecure.org/api/v1/hardware/entropy  # mainnet
curl https://bootstrap-testnet.pisecure.org/api/v1/hardware/entropy  # testnet
```

2. **Query parameter** (alternate):
```bash
curl https://bootstrap.pisecure.org/api/v1/hardware/entropy?network=testnet
```

3. **Header** (most flexible):
```bash
curl -H "X-Network: testnet" https://bootstrap.pisecure.org/api/v1/hardware/entropy
```

---

### Fallback & Resilience

**Q: If bootstrap server unreachable, should nodes fall back to local validation?**

✅ **Recommended fallback strategy:**

```python
def submit_entropy_with_fallback(node_id, entropy_bytes):
    try:
        # Try bootstrap server
        response = submit_to_bootstrap(node_id, entropy_bytes)
        return response
        
    except requests.exceptions.Timeout:
        # Bootstrap unreachable - fallback to local
        logger.warning("Bootstrap timeout - using local validation")
        local_result = validate_locally(entropy_bytes)
        cache_for_later_submission(node_id, entropy_bytes)  # Retry later
        return local_result
        
    except requests.exceptions.ConnectionError:
        # Server completely down
        logger.error("Bootstrap unreachable - caching submission")
        cache_for_later_submission(node_id, entropy_bytes)
        return None  # Don't block mining

def validate_locally(entropy_bytes):
    """Lightweight local check (basic Shannon entropy only)"""
    entropy = calculate_shannon_entropy(entropy_bytes)
    return entropy >= 4.5  # Simple pass/fail
```

**Q: Should failed entropy checks block mining or just log warnings?**

**Current behavior:**
- ❌ **Does NOT block mining** - logs warnings only
- Mining continues regardless of entropy validation result

**Future consideration (Phase 2+):**
- Failed validation reduces validator selection weight
- Persistent failures (10+) may require manual re-registration

**Q: Retry logic recommendations?**

✅ **Best practices:**

```python
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Exponential backoff strategy
retry_strategy = Retry(
    total=3,                          # Max 3 retries
    status_forcelist=[429, 500, 502, 503, 504],
    backoff_factor=2,                 # 2s, 4s, 8s delays
    allowed_methods=["POST"]
)

adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.Session()
session.mount("https://", adapter)

# Circuit breaker pattern (optional)
class CircuitBreaker:
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.last_failure_time = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    
    def call(self, func, *args, **kwargs):
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.timeout:
                self.state = "HALF_OPEN"
            else:
                raise Exception("Circuit breaker OPEN")
        
        try:
            result = func(*args, **kwargs)
            self.on_success()
            return result
        except Exception as e:
            self.on_failure()
            raise
    
    def on_success(self):
        self.failure_count = 0
        self.state = "CLOSED"
    
    def on_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"
```

---

### Historical Data Access

**Q: Can nodes retrieve past entropy validation history?**

✅ **Yes**: `GET /api/v1/nodes/{node_id}/entropy-history`

**Query Parameters:**
```
limit:  Number of records (default: 100, max: 1000)
offset: Pagination offset (default: 0)
since:  Unix timestamp - filter results after this time
until:  Unix timestamp - filter results before this time
order:  asc|desc (default: desc - newest first)
```

**Example Request:**
```bash
curl "https://bootstrap.pisecure.org/api/v1/nodes/miner-001/entropy-history?limit=50&since=1737400000"
```

**Response:**
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
      "reputation_impact": 0.0,
      "tests_passed": ["chi_square", "runs_test", "longest_run"]
    },
    // ... more entries
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "total": 500,
    "has_more": true,
    "next": "/api/v1/nodes/miner-rpi5-001/entropy-history?limit=50&offset=50"
  },
  "summary": {
    "pass_rate": 0.94,
    "avg_quality": 85.2,
    "trend": "stable",  // stable|improving|declining
    "last_30_days": {
      "submissions": 48,
      "pass_rate": 0.96,
      "avg_quality": 86.1
    }
  }
}
```

**Q: Useful for debugging and trend analysis?**

✅ **Absolutely! Use cases:**

1. **Debug Hardware Issues**:
   - Compare quality scores before/after hardware change
   - Identify degrading RNG performance over time

2. **Trend Analysis**:
   - Track entropy quality trends
   - Correlate with mining performance
   - Identify environmental factors (temperature, load)

3. **Compliance Reporting**:
   - Prove consistent entropy quality for audits
   - Export data for analysis

4. **Automated Monitoring**:
```python
def check_entropy_health(node_id):
    history = fetch_entropy_history(node_id, limit=100)
    
    recent_pass_rate = history['summary']['last_30_days']['pass_rate']
    trend = history['summary']['trend']
    
    if recent_pass_rate < 0.80:
        alert("⚠️ Low entropy pass rate - check hardware")
    
    if trend == "declining":
        alert("📉 Entropy quality declining - investigate")
```

---

## 6. Quick Reference Implementation

### Complete Production-Ready Client

```python
#!/usr/bin/env python3
"""
PiSecure Entropy Submission Client
Production-ready with retry logic, caching, and monitoring
"""

import requests
import time
import logging
import json
from pathlib import Path

class PiSecureEntropyClient:
    def __init__(self, node_id, network="mainnet"):
        self.node_id = node_id
        self.network = network
        
        # Endpoints
        self.endpoints = {
            "mainnet": "https://bootstrap.pisecure.org",
            "testnet": "https://bootstrap-testnet.pisecure.org"
        }
        self.base_url = self.endpoints[network]
        
        # Configuration
        self.submission_interval = 3600  # 1 hour
        self.cache_file = Path(f"/var/cache/pisecure/entropy_{node_id}.json")
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Setup session with retry
        self.session = self._create_session()
    
    def _create_session(self):
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry = Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        adapter = HTTPAdapter(max_retries=retry)
        session = requests.Session()
        session.mount("https://", adapter)
        return session
    
    def read_hardware_entropy(self):
        """Read 32 bytes from /dev/hwrng"""
        try:
            with open('/dev/hwrng', 'rb') as hwrng:
                return hwrng.read(32)
        except IOError as e:
            self.logger.error(f"Failed to read /dev/hwrng: {e}")
            return None
    
    def submit(self, entropy_bytes=None):
        """Submit entropy to bootstrap"""
        if not entropy_bytes:
            entropy_bytes = self.read_hardware_entropy()
            if not entropy_bytes:
                return None
        
        payload = {
            "node_id": self.node_id,
            "entropy_hex": entropy_bytes.hex(),
            "network": self.network,
            "timestamp": time.time()
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/v1/hardware/entropy",
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            result = response.json()
            
            if response.status_code == 200:
                self.logger.info(
                    f"✓ Entropy validated: quality={result['quality_score']:.2f}, "
                    f"pass_rate={result['node_entropy_history']['pass_rate']:.2%}"
                )
            elif response.status_code == 400:
                self.logger.warning(
                    f"✗ Entropy failed: quality={result['quality_score']:.2f}, "
                    f"penalty={result.get('penalty_applied', 0)}"
                )
            elif response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 3600))
                self.logger.warning(f"Rate limited - retry after {retry_after}s")
            
            # Cache successful submission
            if response.status_code in [200, 400]:
                self._cache_submission(result)
            
            return result
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Entropy submission failed: {e}")
            self._cache_for_retry(payload)
            return None
    
    def _cache_submission(self, result):
        """Cache submission result"""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump({
                    'last_submission': time.time(),
                    'last_result': result
                }, f)
        except Exception as e:
            self.logger.error(f"Failed to cache submission: {e}")
    
    def _cache_for_retry(self, payload):
        """Cache failed submission for retry"""
        retry_file = self.cache_file.with_suffix('.retry')
        try:
            retry_file.parent.mkdir(parents=True, exist_ok=True)
            with open(retry_file, 'w') as f:
                json.dump({
                    'timestamp': time.time(),
                    'payload': payload
                }, f)
        except Exception as e:
            self.logger.error(f"Failed to cache retry: {e}")
    
    def run_periodic(self):
        """Run periodic entropy submissions"""
        while True:
            self.submit()
            time.sleep(self.submission_interval)

# Usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    client = PiSecureEntropyClient(
        node_id="my-miner-001",
        network="mainnet"
    )
    
    # Run periodic submissions
    client.run_periodic()
```

---

## Summary

All questions answered with complete specifications documented in:
- ✅ [docs/api-entropy-validation.md](../docs/api-entropy-validation.md) - Complete API spec
- ✅ [ENTROPY_VALIDATION.md](../ENTROPY_VALIDATION.md) - Technical implementation
- ✅ [.github/copilot-instructions.md](../.github/copilot-instructions.md) - Updated with entropy context

**Key Takeaways:**
1. Full API specification provided with schemas, error codes, status codes
2. Rate limiting: 100/hour per node (1-2 hour intervals recommended)
3. Reputation thresholds: <30 score = -10 penalty, 11+ failures = quarantine
4. Network isolation: Separate testnet/mainnet servers with different thresholds
5. Fallback strategy: Cache failed submissions, don't block mining
6. Historical data: Full query API for trend analysis and debugging

Ready for production deployment! 🚀
