# PiSecure ↔ Bootstrap Integration Guide

**For PiSecure Node Operators & Core Team**

This document describes how `pisecured` can integrate with the bootstrap node to leverage blockchain metrics, mining templates, transaction tracking, and wallet validation. Integration uses **WebSocket-first** approach with HTTP fallback.

---

## 🎯 Overview: 5 Integration Channels

The bootstrap node now provides 5 new data feeds for `pisecured`:

| Channel | Type | Purpose | Real-time |
|---------|------|---------|-----------|
| **Blockchain Health** | WebSocket + HTTP | Chain metrics, difficulty, hashrate | ✅ WS, ⏱️ polling |
| **Mining Templates** | WebSocket + HTTP | Current block templates, coinbase rewards | ✅ WS, ⏱️ polling |
| **Transaction Monitoring** | WebSocket + HTTP | Mempool health, tx volume, propagation | ✅ WS, ⏱️ polling |
| **Wallet Validation** | HTTP only | Balance verification, fraud detection | ⏱️ on-demand |
| **Peer Intelligence** | WebSocket + HTTP | Cross-validation of peer networks | ✅ WS, ⏱️ polling |

---

## 1️⃣ Blockchain Health Monitoring

### Purpose
Bootstrap tracks blockchain health metrics from the PiSecure network and feeds them into network intelligence scoring. `pisecured` can subscribe to these metrics for:
- Difficulty trend detection
- Network hashrate estimation
- Block production rate analysis
- Fee estimation

### WebSocket Integration (Recommended)
**Namespace:** `/health`  
**Event:** `blockchain_metrics`

```javascript
// JavaScript example
const socket = io('wss://bootstrap.pisecure.org', {
  path: '/socket.io',
  transports: ['websocket', 'polling']
});

socket.on('connect', () => {
  console.log('Connected to bootstrap health channel');
});

socket.on('blockchain_metrics', (data) => {
  console.log('Blockchain update:', {
    height: data.height,
    difficulty: data.difficulty,
    network_hashrate: data.network_hashrate,
    block_time_avg: data.average_block_time,
    pending_txs: data.pending_transactions,
    threat_level: data.threat_level
  });
  
  // Use metrics to adjust mining strategy, fee predictions, etc.
  updateMiningDifficulty(data.difficulty);
  updateNetworkHealthScore(data.health_score);
});
```

```python
# Python example using python-socketio
from socketio import Client
import asyncio

class BootstrapHealthClient:
    def __init__(self, bootstrap_url='wss://bootstrap.pisecure.org'):
        self.sio = Client(ssl_verify=False)
        self.bootstrap_url = bootstrap_url
        
    def setup_handlers(self):
        @self.sio.on('blockchain_metrics', namespace='/health')
        def on_blockchain_metrics(data):
            print(f"Blockchain height: {data['height']}")
            print(f"Network hashrate: {data['network_hashrate']}")
            print(f"Difficulty: {data['difficulty']}")
            # Update local node state
            self.update_node_metrics(data)
    
    async def connect(self):
        self.setup_handlers()
        await self.sio.connect(self.bootstrap_url)

# Usage
client = BootstrapHealthClient()
await client.connect()
```

### HTTP Fallback
**Endpoint:** `GET /api/v1/blockchain/metrics`

```bash
curl https://bootstrap.pisecure.org/api/v1/blockchain/metrics

# Response
{
  "height": 12345,
  "blocks": 12346,
  "difficulty": 20,
  "block_time_target": 60,
  "average_block_time": 59.8,
  "network_hashrate": "4.2 GH/s",
  "total_transactions": 123456,
  "pending_transactions": 5,
  "total_supply": "25,000,000 314ST",
  "threat_level": "low",
  "health_score": 98.5,
  "timestamp": 1705427400
}
```

### Response Fields

| Field | Type | Meaning |
|-------|------|---------|
| `height` | int | Current block height |
| `difficulty` | int | Current PoW difficulty |
| `average_block_time` | float | Average seconds between blocks |
| `network_hashrate` | string | Total network mining power |
| `pending_transactions` | int | Mempool transaction count |
| `threat_level` | string | `low`, `medium`, `high` |
| `health_score` | float | 0-100 network health metric |

### Use Cases for `pisecured`
- **Fee Estimation**: Adjust recommended transaction fees based on pending tx count
- **Mining Difficulty Prediction**: Anticipate next difficulty adjustment
- **Network Health Alerting**: Alert node operators when threat level rises
- **Consensus Monitoring**: Verify local blockchain is in sync with network consensus

---

## 2️⃣ Mining Template Caching & Distribution

### Purpose
Bootstrap caches mining templates from the network and distributes them to miners with minimal latency. This enables:
- Reduced mining pool latency
- Faster template updates (sub-second)
- Load balancing across multiple miners
- Intelligent pool selection

### WebSocket Integration (Recommended)
**Namespace:** `/dex` (reused for mining events)  
**Event:** `mining_template`

```javascript
// JavaScript - Subscribe to mining templates
const socket = io('wss://bootstrap.pisecure.org', {
  transports: ['websocket', 'polling']
});

socket.on('mining_template', (template) => {
  console.log('New mining template received:', {
    height: template.height,
    previous_hash: template.previous_hash,
    difficulty: template.difficulty,
    coinbase_reward: template.coinbase_reward,
    timestamp: template.timestamp,
    latency_ms: Date.now() - template.bootstrap_timestamp
  });
  
  // Update miner workers with new template
  updateMinerTemplate(template);
});
```

```python
# Python - Mining template consumer
@sio.on('mining_template', namespace='/dex')
def on_mining_template(data):
    """Handle new mining templates from bootstrap"""
    template = {
        'height': data['height'],
        'previous_hash': data['previous_hash'],
        'difficulty': data['difficulty'],
        'target_zero_bits': data['target_zero_bits'],
        'transactions': data['transactions'],
        'coinbase_reward': data['coinbase_reward'],
        'pool_address': data.get('pool_address'),
        'timestamp': data['timestamp']
    }
    
    # Distribute to stratum workers
    broadcast_to_miners(template)
```

### HTTP Fallback - Mining Relay
**Endpoint:** `GET /api/v1/mining/relay`

```bash
curl https://bootstrap.pisecure.org/api/v1/mining/relay

# Response
{
  "template": {
    "height": 12345,
    "previous_hash": "00000def456ghi...",
    "difficulty": 20,
    "target_zero_bits": 20,
    "transactions": [
      {
        "id": "tx_abc123...",
        "from": "wallet_a",
        "to": "wallet_b",
        "amount": 10.0,
        "fee": 0.01
      }
    ],
    "coinbase_reward": 6.0,
    "pool_address": "bootstrap-mining-pool",
    "pool_fee": 0.0,
    "timestamp": 1705427400
  },
  "relay_latency_ms": 12,
  "source": "pisecure_primary_node",
  "bootstrap_cache_age_seconds": 2
}
```

### Polling Strategy
For HTTP fallback, recommend:
- **Poll every 2-5 seconds** (or when local template is stale)
- **Cache comparison**: Only update miners if `previous_hash` differs
- **Backoff on failures**: Use exponential backoff if bootstrap unavailable

### Use Cases for Miners
- **Pool Operators**: Relay bootstrap templates to stratum workers
- **Solo Miners**: Get latest templates with minimal processing delay
- **Mining Farms**: Load balance across multiple bootstrap instances
- **Template Validation**: Verify templates against local mempool

---

## 3️⃣ Transaction Monitoring & Mempool Health

### Purpose
Bootstrap monitors transaction volume and mempool health to provide:
- Real-time mempool state
- Transaction propagation metrics
- Fee recommendation data
- Attack detection on mempool

### WebSocket Integration (Recommended)
**Namespace:** `/health`  
**Event:** `mempool_update`

```javascript
socket.on('mempool_update', (data) => {
  console.log('Mempool snapshot:', {
    pending_count: data.pending_transactions,
    total_bytes: data.total_bytes,
    avg_fee_rate: data.avg_fee_rate,
    min_fee_rate: data.min_fee_rate,
    max_fee_rate: data.max_fee_rate,
    propagation_time_ms: data.propagation_time_ms,
    threat_detected: data.threat_detected
  });
  
  // Update fee recommendation engine
  recommendedFee = data.avg_fee_rate * 1.1; // 10% above average
});
```

```python
@sio.on('mempool_update', namespace='/health')
def on_mempool_update(data):
    """Monitor mempool health from bootstrap"""
    mempool_health = {
        'pending_txs': data['pending_transactions'],
        'total_bytes': data['total_bytes'],
        'avg_fee_rate': data['avg_fee_rate'],
        'propagation_latency_ms': data['propagation_time_ms'],
        'anomalies_detected': data.get('anomalies_detected', [])
    }
    
    # Alert if mempool is congested or under attack
    if data['threat_detected']:
        log_alert(f"Mempool threat detected: {data['threat_reason']}")
    
    # Update local fee estimation
    update_fee_recommendation(mempool_health)
```

### HTTP Fallback
**Endpoint:** `GET /api/v1/mempool`

```bash
curl https://bootstrap.pisecure.org/api/v1/mempool

# Response
{
  "pending_transactions": 5,
  "total_bytes": 1245,
  "transaction_count_by_fee": {
    "0.001": 2,
    "0.005": 1,
    "0.01": 2
  },
  "avg_fee_rate": 0.0058,
  "min_fee_rate": 0.001,
  "max_fee_rate": 0.01,
  "median_fee_rate": 0.005,
  "propagation_time_ms": 45,
  "threat_detected": false,
  "threat_details": null,
  "timestamp": 1705427400,
  "network_health_score": 98.5
}
```

### Transaction Propagation Tracking

When your node broadcasts a transaction, bootstrap tracks how it propagates:

```
POST /api/v1/blockchain/metrics
Content-Type: application/json

{
  "event": "transaction_broadcast",
  "transaction_id": "tx_abc123...",
  "node_id": "your_node_id",
  "timestamp": 1705427400
}

# Bootstrap responds with propagation tracking
{
  "transaction_id": "tx_abc123...",
  "propagation_tracking_id": "prop_xyz789...",
  "status": "tracking",
  "nodes_seen": 8,
  "propagation_latency_ms": 45,
  "prediction": {
    "expected_mempool_inclusion": 0.95,
    "expected_block_inclusion": 0.80,
    "estimated_blocks_to_confirmation": 2
  }
}
```

### Use Cases for `pisecured`
- **Fee Estimation**: Get accurate fee rates from network consensus
- **Transaction Monitoring**: Track own transaction propagation
- **Mempool Analysis**: Detect spam/attack patterns
- **User Notifications**: Alert wallets of fee/congestion changes

---

## 4️⃣ Wallet Balance Validation

### Purpose
Bootstrap validates reward claim integrity by checking wallet balances on-chain:
- Verify operators have claimed 314ST rewards
- Detect reward fraud/double-claiming
- Track node operator wealth distribution

### HTTP Endpoint (On-Demand)
**Endpoint:** `GET /api/v1/wallet/balance?wallet_id=<wallet_id>`

```bash
curl "https://bootstrap.pisecure.org/api/v1/wallet/balance?wallet_id=pisecure_wallet_abc123"

# Response
{
  "wallet_id": "pisecure_wallet_abc123",
  "balance": 1250.50,
  "currency": "314ST",
  "unconfirmed_balance": 100.0,
  "pending_transactions": 2,
  "last_updated": "2024-01-16T14:30:00Z",
  "reputation_score": 92.5,
  "is_bootstrap_operator": true,
  "bootstrap_rewards_claimed": 1500.0,
  "bootstrap_rewards_pending": 250.50
}
```

### Integration Points

**1. Node Registration Validation** (Called during registration)
```python
def validate_node_registration(node_data):
    """Verify operator wallet has balance before accepting node"""
    wallet_id = node_data['operator_wallet']
    
    response = requests.get(
        f"https://bootstrap.pisecure.org/api/v1/wallet/balance",
        params={'wallet_id': wallet_id},
        timeout=5
    )
    
    if response.status_code == 200:
        wallet_info = response.json()
        # Reject if balance too low (operator collateral)
        if wallet_info['balance'] < MINIMUM_OPERATOR_BALANCE:
            return False, f"Insufficient balance: {wallet_info['balance']}"
        return True, wallet_info
    else:
        return False, "Could not verify wallet"
```

**2. Reward Payout Validation** (Called before distributing rewards)
```python
def validate_reward_payout(operator_wallet_id, reward_amount):
    """Ensure wallet is valid before sending rewards"""
    try:
        response = requests.get(
            f"https://bootstrap.pisecure.org/api/v1/wallet/balance",
            params={'wallet_id': operator_wallet_id},
            timeout=5
        )
        
        if response.status_code == 200:
            wallet = response.json()
            
            # Check if wallet is active (has transactions recently)
            if not wallet.get('is_bootstrap_operator'):
                logger.warning(f"Wallet {operator_wallet_id} is not recognized as operator")
            
            # Proceed with payout
            return True
        else:
            logger.error(f"Failed to validate wallet {operator_wallet_id}")
            return False
    
    except requests.Timeout:
        logger.error("Bootstrap wallet validation timeout - retrying...")
        return True  # Allow retry rather than blocking
```

**3. Fraud Detection** (Periodic audit)
```python
async def audit_operator_wallets():
    """Periodically verify operator wallet integrity"""
    for operator_id, operator_data in OPERATOR_REGISTRY.items():
        wallet_id = operator_data['wallet']
        
        response = await fetch_wallet_balance(wallet_id)
        if response:
            actual_balance = response['balance']
            claimed_balance = operator_data['claimed_balance']
            
            # Flag discrepancies > 10%
            if abs(actual_balance - claimed_balance) / claimed_balance > 0.1:
                logger.warning(
                    f"Balance mismatch for operator {operator_id}: "
                    f"claimed={claimed_balance}, actual={actual_balance}"
                )
                # Investigate/suspend operator
```

### Response Fields

| Field | Type | Meaning |
|-------|------|---------|
| `balance` | float | Current wallet balance (314ST) |
| `unconfirmed_balance` | float | Pending transactions balance |
| `reputation_score` | float | 0-100 operator reputation |
| `is_bootstrap_operator` | bool | Registered bootstrap operator |
| `bootstrap_rewards_claimed` | float | Total 314ST received |
| `bootstrap_rewards_pending` | float | Queued rewards awaiting payout |

---

## 5️⃣ Peer Network Intelligence Validation

### Purpose
Bootstrap discovers and tracks peer nodes. `pisecured` can cross-validate its peer list:
- Detect sybil attacks
- Verify peer health
- Optimize peer selection
- Detect network partitions

### WebSocket Integration (Recommended)
**Namespace:** `/nodes`  
**Event:** `peer_network_snapshot`

```javascript
socket.on('peer_network_snapshot', (data) => {
  console.log('Peer network health from bootstrap:', {
    total_peers: data.connected_peers,
    bootstrap_view: data.peers.map(p => ({
      address: p.address,
      type: p.type,
      latency_ms: p.latency_ms,
      uptime_hours: p.uptime_hours
    }))
  });
  
  // Cross-validate against your peer list
  validateLocalPeerList(data.peers);
});
```

```python
@sio.on('peer_network_snapshot', namespace='/nodes')
def on_peer_network_snapshot(data):
    """Compare bootstrap's peer view with local peer list"""
    bootstrap_peers = {
        p['peer_id']: {
            'address': p['address'],
            'latency_ms': p['latency_ms'],
            'uptime_hours': p['uptime_hours'],
            'blocks_received': p['blocks_received']
        }
        for p in data['peers']
    }
    
    # Find peers bootstrap sees that we don't (possible sybil nodes)
    unknown_peers = set(bootstrap_peers.keys()) - set(LOCAL_PEERS.keys())
    if unknown_peers:
        logger.info(f"New peers from bootstrap: {unknown_peers}")
        # Attempt connection to new peers
        for peer_id in unknown_peers:
            connect_to_peer(bootstrap_peers[peer_id])
    
    # Find peers we see that bootstrap doesn't (possible isolated nodes)
    isolated_peers = set(LOCAL_PEERS.keys()) - set(bootstrap_peers.keys())
    if isolated_peers:
        logger.warning(f"Isolated peers (not in bootstrap view): {isolated_peers}")
```

### HTTP Fallback
**Endpoint:** `GET /api/v1/network/peers`

```bash
curl https://bootstrap.pisecure.org/api/v1/network/peers

# Response
{
  "connected_peers": 8,
  "peers": [
    {
      "address": "192.168.1.100:3142",
      "type": "outbound",
      "peer_id": "peer_abc123...",
      "protocol_version": "1.0.0",
      "last_seen": 1705427350,
      "uptime_hours": 48,
      "blocks_received": 234,
      "transactions_received": 1234,
      "latency_ms": 25,
      "location": "US",
      "reputation_score": 98.5
    },
    {
      "address": "peer.example.com:3142",
      "type": "inbound",
      "peer_id": "peer_def456...",
      "protocol_version": "1.0.0",
      "last_seen": 1705427395,
      "uptime_hours": 72,
      "blocks_received": 456,
      "transactions_received": 2345,
      "latency_ms": 45,
      "location": "EU",
      "reputation_score": 95.2
    }
  ]
}
```

### Peer Validation Algorithm

```python
def validate_peer_network():
    """Use bootstrap peer view to detect anomalies"""
    
    # Get bootstrap's peer view
    bootstrap_peers = fetch_bootstrap_peers()
    
    # Step 1: Verify peer diversity
    bootstrap_locations = [p['location'] for p in bootstrap_peers['peers']]
    if len(set(bootstrap_locations)) < 3:
        logger.warning("Network lacks geographic diversity")
    
    # Step 2: Check for low-reputation peers
    suspicious_peers = [
        p for p in bootstrap_peers['peers']
        if p['reputation_score'] < 70
    ]
    if suspicious_peers:
        logger.warning(f"Suspicious peers detected: {suspicious_peers}")
        # Increase monitoring or disconnect from these peers
    
    # Step 3: Detect network partitions
    disconnected_peers = [
        p for p in bootstrap_peers['peers']
        if time.time() - p['last_seen'] > 300  # 5 minutes
    ]
    if len(disconnected_peers) > len(bootstrap_peers['peers']) * 0.3:
        logger.critical("Network partition detected - >30% peers offline")
```

### Use Cases for `pisecured`
- **Network Health Monitoring**: Detect partitions and sybil attacks
- **Peer Selection**: Prefer high-reputation peers from bootstrap ranking
- **Network Optimization**: Geographic load balancing
- **Anomaly Detection**: Find isolated/suspicious nodes

---

## 🔌 Implementation Guide

### Step 1: Establish WebSocket Connection

```python
# Python with python-socketio
import socketio

class BootstrapClient:
    def __init__(self, bootstrap_url='wss://bootstrap.pisecure.org'):
        self.sio = socketio.Client(
            ssl_verify=False,
            reconnection=True,
            reconnection_attempts=10,
            reconnection_delay=2
        )
        self.setup_handlers()
    
    def setup_handlers(self):
        @self.sio.on('connect')
        def on_connect():
            print('Connected to bootstrap')
        
        @self.sio.on('blockchain_metrics', namespace='/health')
        def on_blockchain_metrics(data):
            self.handle_blockchain_metrics(data)
        
        @self.sio.on('mining_template', namespace='/dex')
        def on_mining_template(data):
            self.handle_mining_template(data)
    
    async def connect(self):
        await self.sio.connect(
            'wss://bootstrap.pisecure.org',
            headers={'User-Agent': 'PiSecured/1.0.0'}
        )
    
    def handle_blockchain_metrics(self, data):
        # Your implementation
        pass
    
    def handle_mining_template(self, data):
        # Your implementation
        pass
```

### Step 2: Implement HTTP Fallback

```python
class BootstrapHTTPFallback:
    def __init__(self, bootstrap_base_url='https://bootstrap.pisecure.org'):
        self.base_url = bootstrap_base_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'PiSecured/1.0.0'})
    
    async def poll_blockchain_metrics(self, interval=5):
        """Poll blockchain metrics every N seconds"""
        while True:
            try:
                response = self.session.get(
                    f'{self.base_url}/api/v1/blockchain/metrics',
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    await self.handle_metrics(data)
            except Exception as e:
                logger.error(f"Failed to poll metrics: {e}")
            
            await asyncio.sleep(interval)
    
    async def handle_metrics(self, data):
        # Process metrics
        pass
```

### Step 3: Error Handling & Resilience

```python
class ResilientBootstrapClient:
    def __init__(self):
        self.ws_connected = False
        self.http_fallback_active = False
        self.last_metrics = None
        self.cache_ttl = 10  # seconds
    
    async def get_blockchain_metrics(self):
        """Get metrics from WS if connected, else HTTP"""
        
        # Try WebSocket first
        if self.ws_connected and self.last_metrics:
            age = time.time() - self.last_metrics['timestamp']
            if age < self.cache_ttl:
                return self.last_metrics
        
        # Fall back to HTTP
        try:
            response = await self.session.get(
                f'{self.bootstrap_url}/api/v1/blockchain/metrics',
                timeout=5
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"Metrics fetch failed: {e}")
        
        # Return last cached value if available
        return self.last_metrics or {'height': 0, 'health_score': 0}
```

---

## 📊 Integration Checklist

- [ ] **WebSocket Connection**: Implement primary WebSocket client with reconnection logic
- [ ] **HTTP Fallback**: Implement polling as backup (2-5s intervals)
- [ ] **Error Handling**: Graceful degradation when bootstrap unavailable
- [ ] **Caching**: Cache recent metrics to reduce bootstrap load
- [ ] **Logging**: Log all bootstrap interactions for debugging
- [ ] **Testing**: Unit tests for each integration point
- [ ] **Monitoring**: Alert on bootstrap disconnection/timeouts
- [ ] **Documentation**: Update your API docs with bootstrap dependencies

---

## 🔐 Security Considerations

### 1. **Validate All Data**
```python
def validate_mining_template(template):
    """Validate template before using"""
    assert isinstance(template['height'], int)
    assert isinstance(template['difficulty'], int)
    assert 0 < template['difficulty'] <= 2**32
    assert len(template['previous_hash']) == 64
    assert len(template['transactions']) <= 1000
    # Additional validation...
```

### 2. **Rate Limiting**
Bootstrap enforces:
- **1000 requests/minute** per IP address
- **WebSocket**: No per-message rate limit (but server-side fairness)

```python
# Implement local client-side rate limiting
class RateLimiter:
    def __init__(self, max_requests=900, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = deque()
    
    def allow_request(self):
        now = time.time()
        # Remove old requests outside window
        while self.requests and self.requests[0] < now - self.window_seconds:
            self.requests.popleft()
        
        if len(self.requests) < self.max_requests:
            self.requests.append(now)
            return True
        return False
```

### 3. **SSL/TLS Verification**
```python
# Always verify certificates in production
import certifi

session = requests.Session()
session.verify = certifi.where()  # Use system CA bundle
```

### 4. **Authentication** (Optional)
If you require authenticated access:
```bash
# Bootstrap can issue API keys
curl -X POST https://bootstrap.pisecure.org/api/v1/auth/issue-key \
  -H "Content-Type: application/json" \
  -d '{"node_id": "your_node_id"}'

# Use in requests
curl -H "Authorization: Bearer <api_key>" \
  https://bootstrap.pisecure.org/api/v1/blockchain/metrics
```

---

## 📈 Monitoring & Observability

### Key Metrics to Track

1. **WebSocket Health**
   ```python
   bootstrap.ws_connection_uptime_percent
   bootstrap.ws_reconnection_count
   bootstrap.ws_message_latency_ms
   ```

2. **Data Quality**
   ```python
   bootstrap.metrics_cache_age_seconds
   bootstrap.http_fallback_activations
   bootstrap.data_validation_errors
   ```

3. **Usage Patterns**
   ```python
   bootstrap.api_requests_per_minute
   bootstrap.websocket_subscriptions_active
   bootstrap.polling_interval_seconds
   ```

### Sample Prometheus Metrics

```
# Bootstrap integration metrics
pisecure_bootstrap_ws_connected{bootstrap="primary"} 1
pisecure_bootstrap_http_requests_total{bootstrap="primary",endpoint="/api/v1/blockchain/metrics"} 15234
pisecure_bootstrap_metrics_latency_ms{bootstrap="primary",metric="blockchain"} 45
pisecure_bootstrap_fallback_activations_total{reason="ws_disconnect"} 3
```

---

## 🆘 Troubleshooting

### WebSocket Connection Fails
1. Check firewall rules for `wss://` (WebSocket Secure)
2. Verify SSL certificates are valid
3. Check bootstrap availability: `curl https://bootstrap.pisecure.org/health`
4. Review bootstrap logs for connection errors

### HTTP Fallback Timeout
1. Increase timeout from 5s to 10s
2. Implement exponential backoff for retries
3. Check network latency: `ping bootstrap.pisecure.org`

### Stale Data in Cache
1. Reduce cache TTL (e.g., 5s → 2s)
2. Implement push notifications instead of polling
3. Add validation to detect stale data

### Rate Limit Errors (429)
1. Implement backoff strategy
2. Batch requests where possible
3. Use WebSocket instead of HTTP (no per-message limits)

---

## 📚 References

- [Bootstrap Whitepaper](../../README.md)
- [WebSocket Specification](./WEBSOCKET_SPECIFICATION.md)
- [PiSecure REST API](./rest-api.md)
- [API Node Registration](./api-node-registration.md)
- [API Entropy Validation](./api-entropy-validation.md)

---

**Last Updated:** January 25, 2026  
**Bootstrap Version:** 2.0+  
**Status:** Production Ready
