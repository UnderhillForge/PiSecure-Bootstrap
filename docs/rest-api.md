# REST API Reference

Complete HTTP API documentation for PiSecure blockchain.

## 🚀 Getting Started

### Enable REST API

```bash
# Start API server (default port 3142)
pisecured --api

# Or explicitly
pisecured --api --api-host 0.0.0.0 --api-port 3142

# From another machine
curl http://pi.local:3142/api/v1/chain
```

### API Endpoints Summary

| Category | Endpoint | Method | Purpose |
|----------|----------|--------|---------|
| **Chain** | `/api/v1/chain` | GET | Blockchain status |
| | `/api/v1/block/:height` | GET | Get block by height |
| | `/api/v1/block/:hash` | GET | Get block by hash |
| **Wallet** | `/api/v1/wallet/balance` | GET | Get wallet balance |
| | `/api/v1/wallet/transactions` | GET | Get transaction history |
| | `/api/v1/transactions` | POST | Submit transaction |
| **Mining** | `/api/v1/mining/template` | GET | Get mining template |
| | `/api/v1/mining/stats` | GET | Get mining statistics |
| **Network** | `/api/v1/network/peers` | GET | List connected peers |
| | `/api/v1/network/health` | GET | Network health status |

## 🔗 Blockchain Endpoints

### Get Chain Status

```
GET /api/v1/chain
```

**Response:**
```json
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
  "latest_block": {
    "hash": "00000abc123def...",
    "height": 12345,
    "timestamp": 1705427400,
    "miner": "pisecure_wallet_xyz...",
    "transactions": 15,
    "difficulty": 20
  },
  "network": "mainnet"
}
```

### Get Block by Height

```
GET /api/v1/block/12345
```

**Response:**
```json
{
  "height": 12345,
  "hash": "00000abc123def...",
  "previous_hash": "00000def456ghi...",
  "timestamp": 1705427400,
  "difficulty": 20,
  "nonce": 23456789,
  "miner": "pisecure_wallet_xyz...",
  "miner_reward": 6.2,
  "merkle_root": "abc123def456...",
  "transaction_count": 15,
  "transactions": [
    {
      "id": "tx_abc123...",
      "from": "pisecure_wallet_abc...",
      "to": "pisecure_wallet_xyz...",
      "amount": 50.0,
      "fee": 0.05,
      "timestamp": 1705427390,
      "signature": "304502210086a..."
    },
    // ... more transactions
  ]
}
```

### Get Block by Hash

```
GET /api/v1/block/00000abc123def...
```

Same response as height endpoint, but query by block hash.

## 💰 Wallet Endpoints

### Get Wallet Balance

```
GET /api/v1/wallet/balance?wallet_id=pisecure_wallet_abc123...
```

**Query Parameters:**
- `wallet_id` (required): Wallet address

**Response:**
```json
{
  "wallet_id": "pisecure_wallet_abc123...",
  "balance": 1250.50,
  "currency": "314ST",
  "unconfirmed_balance": 100.0,
  "pending_transactions": 2,
  "last_updated": "2024-01-16T14:30:00Z"
}
```

### Get Wallet Transactions

```
GET /api/v1/wallet/transactions?wallet_id=pisecure_wallet_abc&limit=20&offset=0
```

**Query Parameters:**
- `wallet_id` (required): Wallet address
- `limit` (optional): Max results, default 20, max 100
- `offset` (optional): Pagination offset, default 0
- `type` (optional): Filter by 'incoming' or 'outgoing'

**Response:**
```json
{
  "wallet_id": "pisecure_wallet_abc123...",
  "total": 150,
  "limit": 20,
  "offset": 0,
  "transactions": [
    {
      "id": "tx_abc123...",
      "block_height": 12345,
      "block_hash": "00000abc...",
      "from": "pisecure_wallet_abc...",
      "to": "pisecure_wallet_xyz...",
      "amount": 50.0,
      "fee": 0.05,
      "total": 50.05,
      "timestamp": 1705427390,
      "type": "outgoing",
      "status": "confirmed",
      "confirmations": 5
    },
    // ... more transactions
  ]
}
```

### Submit Transaction

```
POST /api/v1/transactions
Content-Type: application/json
```

**Request Body:**
```json
{
  "from": "pisecure_wallet_abc...",
  "to": "pisecure_wallet_xyz...",
  "amount": 50.0,
  "fee": 0.05,
  "nonce": 123,
  "signature": "304502210086a9f..."
}
```

**Response (Success):**
```json
{
  "transaction_id": "tx_abc123def456...",
  "status": "pending",
  "block_height": null,
  "message": "Transaction submitted successfully",
  "timestamp": "2024-01-16T14:30:00Z"
}
```

**Response (Error):**
```json
{
  "error": "insufficient_balance",
  "message": "Wallet balance 50 314ST is less than required 100.05 314ST",
  "timestamp": "2024-01-16T14:30:00Z"
}
```

## ⛏️ Mining Endpoints

### Get Mining Template

Used by miners to get the current block to work on.

```
GET /api/v1/mining/template
```

**Response:**
```json
{
  "height": 12345,
  "previous_hash": "00000def456ghi...",
  "merkle_root": "abc123def456...",
  "timestamp": 1705427400,
  "difficulty": 20,
  "target_zero_bits": 20,
  "transactions": [
    {
      "id": "tx_1",
      "from": "wallet_a",
      "to": "wallet_b",
      "amount": 10.0,
      "fee": 0.01
    },
    // ... more transactions
  ],
  "coinbase_reward": 6.0,
  "pool_address": null,
  "pool_fee": 0.0
}
```

### Get Mining Statistics

```
GET /api/v1/mining/stats
```

**Response:**
```json
{
  "network_hashrate": "4.2 GH/s",
  "difficulty": 20,
  "average_block_time": 59.8,
  "blocks_per_day": 1440,
  "estimated_daily_mining_reward": 8640,
  "last_block_time": 60,
  "next_difficulty_adjustment": {
    "blocks_remaining": 5,
    "estimated_adjustment": "+1 (from 20 to 21)"
  },
  "active_miners": 342,
  "pool_statistics": {
    "mining_pools": 3,
    "pool_hashrate_percentage": 35.0
  }
}
```

## 🌐 Network Endpoints

### List Connected Peers

```
GET /api/v1/network/peers
```

**Response:**
```json
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
      "latency_ms": 25
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
      "latency_ms": 45
    },
    // ... more peers
  ]
}
```

### Network Health Status

```
GET /api/v1/network/health
```

**Response:**
```json
{
  "status": "healthy",
  "uptime_percentage": 99.8,
  "connected_peers": 8,
  "peer_connectivity": "good",
  "block_sync_status": "in_sync",
  "last_block_received": "30s ago",
  "pending_transactions": 5,
  "memory_usage_mb": 234,
  "disk_usage_gb": 12.5,
  "network_latency_ms": {
    "min": 15,
    "max": 120,
    "average": 45
  },
  "recommendations": []
}
```

## 🔑 Authentication

### API Key Authentication

```bash
# Set API key in config
pisecure config set api_key "your-secret-key-here"

# Use in requests
curl -H "Authorization: Bearer your-secret-key-here" \
  http://localhost:3142/api/v1/chain
```

### Rate Limiting

```
Default: 1000 requests per minute per IP address

Response Headers:
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1705427460

If rate limited:
HTTP 429 Too Many Requests
```

## 📊 Error Responses

### Error Format

All errors return JSON:

```json
{
  "error": "error_code",
  "message": "Human readable error message",
  "details": "Optional technical details",
  "timestamp": "2024-01-16T14:30:00Z"
}
```

### Common Errors

| Code | Status | Meaning | Solution |
|------|--------|---------|----------|
| `invalid_request` | 400 | Missing/invalid parameters | Check request format |
| `not_found` | 404 | Wallet/block not found | Verify wallet_id/hash |
| `insufficient_balance` | 400 | Not enough tokens | Add more tokens |
| `invalid_signature` | 400 | Transaction signature invalid | Re-sign transaction |
| `server_error` | 500 | Internal server error | Retry or contact support |
| `rate_limited` | 429 | Too many requests | Wait before retrying |

## 🔗 Example Usage (Python)

```python
import requests
import json

BASE_URL = "http://localhost:3142/api/v1"

# Get chain status
response = requests.get(f"{BASE_URL}/chain")
chain_info = response.json()
print(f"Height: {chain_info['height']}")
print(f"Difficulty: {chain_info['difficulty']}")

# Get wallet balance
wallet_id = "pisecure_wallet_abc123..."
response = requests.get(
    f"{BASE_URL}/wallet/balance",
    params={"wallet_id": wallet_id}
)
balance = response.json()
print(f"Balance: {balance['balance']} 314ST")

# Submit transaction
tx_data = {
    "from": "wallet_a",
    "to": "wallet_b",
    "amount": 50.0,
    "fee": 0.05,
    "nonce": 123,
    "signature": "304502210086a9f..."
}
response = requests.post(
    f"{BASE_URL}/transactions",
    json=tx_data
)
result = response.json()
print(f"TX ID: {result['transaction_id']}")

# Get wallet transactions
response = requests.get(
    f"{BASE_URL}/wallet/transactions",
    params={
        "wallet_id": wallet_id,
        "limit": 20,
        "offset": 0
    }
)
transactions = response.json()
for tx in transactions['transactions']:
    print(f"{tx['type']}: {tx['amount']} 314ST")
```

## 🔗 Example Usage (JavaScript)

```javascript
const BASE_URL = "http://localhost:3142/api/v1";

// Get chain status
fetch(`${BASE_URL}/chain`)
  .then(r => r.json())
  .then(data => {
    console.log(`Height: ${data.height}`);
    console.log(`Difficulty: ${data.difficulty}`);
  });

// Get wallet balance
const walletId = "pisecure_wallet_abc123...";
fetch(`${BASE_URL}/wallet/balance?wallet_id=${walletId}`)
  .then(r => r.json())
  .then(data => {
    console.log(`Balance: ${data.balance} 314ST`);
  });

// Submit transaction
const txData = {
  from: "wallet_a",
  to: "wallet_b",
  amount: 50.0,
  fee: 0.05,
  nonce: 123,
  signature: "304502210086a9f..."
};
fetch(`${BASE_URL}/transactions`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(txData)
})
.then(r => r.json())
.then(data => {
  console.log(`TX ID: ${data.transaction_id}`);
});
```

## 📱 WebSocket API

See [WebSocket API Reference](02-websocket-api.md) for real-time updates.

## 💾 Storage Backend

See [Storage Reference](../technical/05-storage.md) for data persistence details.

---

**See also:**
- [Quick Reference](../02-quick-reference.md) - API commands
- [Python SDK](04-python-sdk.md) - High-level library
- [Getting Started](../01-getting-started.md) - First steps
