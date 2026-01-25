# Code Implementation: PiSecure Integration Classes

This file contains the complete Python code for all 5 integration classes that should be inserted into `bootstrap/server.py` at line 1851 (right before the `class NetworkIntelligence:` definition).

## Insertion Point

Insert this code block after line 1850:
```python
# P2P sync manager (from api-update.txt)
p2p_sync_manager = None  # Will be P2PSyncManager() instance

# [INSERT CODE BELOW THIS COMMENT]
```

## Complete Code Block

```python
# ============================================================================
# PISECURE BLOCKCHAIN INTEGRATION - Chain Monitoring, Mining, Transactions
# ============================================================================

class BlockchainHealthMonitor:
    """Monitor PiSecure blockchain health metrics for network intelligence"""
    
    def __init__(self, api_base_url: str = 'http://localhost:3142'):
        self.api_base_url = api_base_url
        self.last_metrics = None
        self.metrics_timestamp = 0
        self.cache_ttl = 5  # Cache metrics for 5 seconds
        self.failure_count = 0
        self.max_failures = 3
        self.metrics_lock = threading.RLock()
        
        logger.info(f"BlockchainHealthMonitor initialized for {api_base_url}")
    
    def poll_blockchain_metrics(self):
        """Background thread to poll blockchain metrics from PiSecure network"""
        while True:
            try:
                response = requests.get(
                    f"{self.api_base_url}/api/v1/chain",
                    timeout=5
                )
                
                if response.status_code == 200:
                    metrics = response.json()
                    with self.metrics_lock:
                        self.last_metrics = {
                            'height': metrics.get('height', 0),
                            'difficulty': metrics.get('difficulty', 0),
                            'network_hashrate': metrics.get('network_hashrate', '0'),
                            'average_block_time': metrics.get('average_block_time', 0),
                            'pending_transactions': metrics.get('pending_transactions', 0),
                            'total_supply': metrics.get('total_supply', '0'),
                            'timestamp': time.time(),
                            'health_score': self._calculate_health_score(metrics),
                            'threat_level': self._determine_threat_level(metrics)
                        }
                        self.metrics_timestamp = time.time()
                        self.failure_count = 0
                
                elif response.status_code >= 500:
                    self.failure_count += 1
                    logger.warning(f"Blockchain metrics fetch failed (attempt {self.failure_count})")
            
            except requests.Timeout:
                self.failure_count += 1
                logger.debug(f"Blockchain metrics timeout (attempt {self.failure_count})")
            except Exception as e:
                self.failure_count += 1
                logger.debug(f"Blockchain metrics error: {e}")
            
            time.sleep(5)  # Poll every 5 seconds
    
    def get_metrics(self) -> dict:
        """Get cached blockchain metrics"""
        with self.metrics_lock:
            if self.last_metrics:
                return self.last_metrics.copy()
            return {
                'height': 0,
                'difficulty': 0,
                'network_hashrate': '0',
                'average_block_time': 0,
                'pending_transactions': 0,
                'health_score': 0,
                'threat_level': 'unknown'
            }
    
    def _calculate_health_score(self, metrics: dict) -> float:
        """Calculate blockchain health score (0-100)"""
        score = 100.0
        
        # Check block time (target 60s)
        block_time = metrics.get('average_block_time', 60)
        if block_time < 30 or block_time > 120:
            score -= 15  # -15 for off-target block time
        
        # Check pending transactions (should be low)
        pending_txs = metrics.get('pending_transactions', 0)
        if pending_txs > 100:
            score -= 10  # -10 for high mempool
        
        return max(0.0, min(100.0, score))
    
    def _determine_threat_level(self, metrics: dict) -> str:
        """Determine network threat level from metrics"""
        block_time = metrics.get('average_block_time', 60)
        pending_txs = metrics.get('pending_transactions', 0)
        
        # High threat if block time >120s or mempool >500
        if block_time > 120 or pending_txs > 500:
            return 'high'
        # Medium threat if block time >90s or mempool >100
        elif block_time > 90 or pending_txs > 100:
            return 'medium'
        else:
            return 'low'


class MiningTemplateCache:
    """Cache and distribute mining templates from PiSecure network"""
    
    def __init__(self, api_base_url: str = 'http://localhost:3142'):
        self.api_base_url = api_base_url
        self.current_template = None
        self.template_timestamp = 0
        self.cache_ttl = 2  # Templates expire after 2 seconds
        self.template_lock = threading.RLock()
        self.subscribers = []  # List of callbacks to notify on new template
        
        logger.info(f"MiningTemplateCache initialized for {api_base_url}")
    
    def poll_mining_templates(self):
        """Background thread to poll and cache mining templates"""
        last_height = None
        
        while True:
            try:
                response = requests.get(
                    f"{self.api_base_url}/api/v1/mining/template",
                    timeout=5
                )
                
                if response.status_code == 200:
                    template = response.json()
                    height = template.get('height')
                    
                    # Only update if height changed (new block)
                    if height != last_height:
                        with self.template_lock:
                            self.current_template = {
                                'height': height,
                                'previous_hash': template.get('previous_hash', ''),
                                'merkle_root': template.get('merkle_root', ''),
                                'timestamp': template.get('timestamp', int(time.time())),
                                'difficulty': template.get('difficulty', 0),
                                'target_zero_bits': template.get('target_zero_bits', 0),
                                'transactions': template.get('transactions', []),
                                'coinbase_reward': template.get('coinbase_reward', 0),
                                'pool_address': template.get('pool_address'),
                                'pool_fee': template.get('pool_fee', 0),
                                'received_at': time.time(),
                                'bootstrap_timestamp': time.time()
                            }
                            self.template_timestamp = time.time()
                            last_height = height
                        
                        # Notify subscribers (WebSocket, etc.)
                        self._notify_subscribers(self.current_template)
            
            except Exception as e:
                logger.debug(f"Mining template fetch error: {e}")
            
            time.sleep(1)  # Poll every second
    
    def get_template(self) -> dict:
        """Get current mining template"""
        with self.template_lock:
            if self.current_template:
                return self.current_template.copy()
            return None
    
    def subscribe(self, callback):
        """Subscribe to template updates"""
        self.subscribers.append(callback)
    
    def _notify_subscribers(self, template: dict):
        """Notify all subscribers of new template"""
        for callback in self.subscribers:
            try:
                callback(template)
            except Exception as e:
                logger.warning(f"Subscriber callback failed: {e}")


class TransactionMonitor:
    """Monitor transaction volume and mempool health"""
    
    def __init__(self, api_base_url: str = 'http://localhost:3142'):
        self.api_base_url = api_base_url
        self.mempool_state = None
        self.mempool_timestamp = 0
        self.mempool_lock = threading.RLock()
        self.tx_volume_history = deque(maxlen=60)  # Track 60 minutes of data
        
        logger.info(f"TransactionMonitor initialized for {api_base_url}")
    
    def poll_mempool(self):
        """Background thread to monitor mempool health"""
        while True:
            try:
                response = requests.get(
                    f"{self.api_base_url}/api/v1/transactions",
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    with self.mempool_lock:
                        self.mempool_state = {
                            'pending_transactions': data.get('pending_transactions', 0),
                            'total_bytes': data.get('total_size_bytes', 0),
                            'transaction_count_by_fee': data.get('transactions_by_fee', {}),
                            'avg_fee_rate': self._calculate_avg_fee(data),
                            'min_fee_rate': data.get('min_fee', 0),
                            'max_fee_rate': data.get('max_fee', 0),
                            'median_fee_rate': data.get('median_fee', 0),
                            'propagation_time_ms': data.get('propagation_latency_ms', 0),
                            'threat_detected': data.get('under_attack', False),
                            'threat_reason': data.get('attack_signature', ''),
                            'timestamp': time.time(),
                            'network_health_score': self._calculate_mempool_health(data)
                        }
                        self.mempool_timestamp = time.time()
                        self.tx_volume_history.append(data.get('pending_transactions', 0))
            
            except Exception as e:
                logger.debug(f"Mempool monitoring error: {e}")
            
            time.sleep(5)  # Poll every 5 seconds
    
    def get_mempool(self) -> dict:
        """Get current mempool state"""
        with self.mempool_lock:
            if self.mempool_state:
                return self.mempool_state.copy()
            return {
                'pending_transactions': 0,
                'threat_detected': False,
                'network_health_score': 0
            }
    
    def _calculate_avg_fee(self, data: dict) -> float:
        """Calculate average fee from transaction distribution"""
        total_fee = 0
        total_count = 0
        for fee_str, count in data.get('transactions_by_fee', {}).items():
            try:
                fee = float(fee_str)
                total_fee += fee * count
                total_count += count
            except (ValueError, TypeError):
                pass
        return (total_fee / total_count) if total_count > 0 else 0.0
    
    def _calculate_mempool_health(self, data: dict) -> float:
        """Calculate mempool health score (0-100)"""
        score = 100.0
        pending = data.get('pending_transactions', 0)
        
        if pending > 500:
            score -= 30
        elif pending > 100:
            score -= 15
        
        if data.get('under_attack'):
            score -= 40
        
        return max(0.0, min(100.0, score))
    
    def track_transaction(self, tx_id: str, node_id: str):
        """Track propagation of a specific transaction"""
        # This could be extended to call /api/v1/transactions/{tx_id} endpoint
        pass


class WalletValidator:
    """Validate wallet balances for reward fraud detection"""
    
    def __init__(self, api_base_url: str = 'http://localhost:3142'):
        self.api_base_url = api_base_url
        self.wallet_cache = {}  # wallet_id -> cached_balance
        self.cache_ttl = 300  # Cache wallet balance for 5 minutes
        self.wallet_lock = threading.RLock()
        
        logger.info(f"WalletValidator initialized for {api_base_url}")
    
    def validate_wallet_balance(self, wallet_id: str, required_balance: float = 0) -> dict:
        """Validate wallet balance - returns balance info or error"""
        with self.wallet_lock:
            # Check cache first
            if wallet_id in self.wallet_cache:
                cached = self.wallet_cache[wallet_id]
                if time.time() - cached['cached_at'] < self.cache_ttl:
                    cached_copy = cached['data'].copy()
                    cached_copy['cached'] = True
                    return cached_copy
        
        try:
            response = requests.get(
                f"{self.api_base_url}/api/v1/wallet/balance",
                params={'wallet_id': wallet_id},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                result = {
                    'wallet_id': wallet_id,
                    'balance': data.get('balance', 0),
                    'currency': data.get('currency', '314ST'),
                    'unconfirmed_balance': data.get('unconfirmed_balance', 0),
                    'pending_transactions': data.get('pending_transactions', 0),
                    'timestamp': data.get('last_updated', time.time()),
                    'valid': True,
                    'sufficient_balance': data.get('balance', 0) >= required_balance,
                    'cached': False
                }
                
                # Cache the result
                with self.wallet_lock:
                    self.wallet_cache[wallet_id] = {
                        'data': result,
                        'cached_at': time.time()
                    }
                
                return result
            else:
                return {
                    'wallet_id': wallet_id,
                    'valid': False,
                    'error': f"HTTP {response.status_code}",
                    'sufficient_balance': False
                }
        
        except requests.Timeout:
            return {
                'wallet_id': wallet_id,
                'valid': False,
                'error': 'Timeout validating wallet',
                'sufficient_balance': False
            }
        except Exception as e:
            return {
                'wallet_id': wallet_id,
                'valid': False,
                'error': str(e),
                'sufficient_balance': False
            }
    
    def batch_validate_wallets(self, wallet_ids: list) -> dict:
        """Validate multiple wallets concurrently"""
        results = {}
        for wallet_id in wallet_ids:
            results[wallet_id] = self.validate_wallet_balance(wallet_id)
        return results


class PeerNetworkValidator:
    """Cross-validate peer networks between bootstrap and PiSecure nodes"""
    
    def __init__(self, api_base_url: str = 'http://localhost:3142'):
        self.api_base_url = api_base_url
        self.peer_snapshot = None
        self.snapshot_timestamp = 0
        self.peer_lock = threading.RLock()
        
        logger.info(f"PeerNetworkValidator initialized for {api_base_url}")
    
    def poll_peer_network(self):
        """Background thread to monitor peer network health"""
        while True:
            try:
                response = requests.get(
                    f"{self.api_base_url}/api/v1/network/peers",
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    with self.peer_lock:
                        self.peer_snapshot = {
                            'connected_peers': data.get('connected_peers', 0),
                            'peers': data.get('peers', []),
                            'timestamp': time.time(),
                            'health_score': self._calculate_peer_health(data)
                        }
                        self.snapshot_timestamp = time.time()
            
            except Exception as e:
                logger.debug(f"Peer network monitoring error: {e}")
            
            time.sleep(10)  # Poll every 10 seconds
    
    def get_peer_snapshot(self) -> dict:
        """Get current peer network snapshot"""
        with self.peer_lock:
            if self.peer_snapshot:
                return self.peer_snapshot.copy()
            return {'connected_peers': 0, 'peers': [], 'health_score': 0}
    
    def validate_peer_diversity(self) -> dict:
        """Analyze peer diversity and detect network issues"""
        snapshot = self.get_peer_snapshot()
        peers = snapshot.get('peers', [])
        
        # Extract locations
        locations = [p.get('location', 'unknown') for p in peers]
        unique_locations = set(locations)
        
        # Check reputation distribution
        low_reputation = [p for p in peers if p.get('reputation_score', 100) < 70]
        
        return {
            'total_peers': len(peers),
            'unique_locations': len(unique_locations),
            'low_reputation_peers': len(low_reputation),
            'recommendations': self._generate_peer_recommendations(peers, unique_locations)
        }
    
    def _calculate_peer_health(self, data: dict) -> float:
        """Calculate peer network health score"""
        peers = data.get('peers', [])
        if not peers:
            return 0.0
        
        score = 100.0
        
        # Penalize for low uptime peers
        low_uptime = [p for p in peers if p.get('uptime_hours', 0) < 1]
        if low_uptime:
            score -= len(low_uptime) * 5
        
        # Penalize for low reputation
        low_rep = [p for p in peers if p.get('reputation_score', 100) < 70]
        if low_rep:
            score -= len(low_rep) * 10
        
        return max(0.0, min(100.0, score))
    
    def _generate_peer_recommendations(self, peers: list, unique_locations: set) -> list:
        """Generate recommendations for peer network optimization"""
        recommendations = []
        
        if len(unique_locations) < 3:
            recommendations.append("Increase geographic diversity - connect to peers in other regions")
        
        low_rep = [p for p in peers if p.get('reputation_score', 100) < 70]
        if low_rep:
            recommendations.append(f"Reduce connections to low-reputation peers: {len(low_rep)}")
        
        disconnected = [p for p in peers if time.time() - p.get('last_seen', 0) > 300]
        if len(disconnected) > len(peers) * 0.3:
            recommendations.append("Network connectivity issues - >30% of peers offline")
        
        return recommendations
```

## Integration with Existing Code

### 1. Add Lazy Initialization (around line ~3500)
```python
# Global integration instances
blockchain_monitor = None
mining_cache = None
tx_monitor = None
wallet_validator = None
peer_validator = None

def get_blockchain_monitor():
    global blockchain_monitor
    if not blockchain_monitor:
        api_url = os.getenv('PISECURE_API_URL', 'http://localhost:3142')
        blockchain_monitor = BlockchainHealthMonitor(api_url)
        threading.Thread(
            target=blockchain_monitor.poll_blockchain_metrics,
            daemon=True,
            name='blockchain-monitor'
        ).start()
    return blockchain_monitor

def get_mining_template_cache():
    global mining_cache
    if not mining_cache:
        api_url = os.getenv('PISECURE_API_URL', 'http://localhost:3142')
        mining_cache = MiningTemplateCache(api_url)
        threading.Thread(
            target=mining_cache.poll_mining_templates,
            daemon=True,
            name='mining-cache'
        ).start()
    return mining_cache

def get_tx_monitor():
    global tx_monitor
    if not tx_monitor:
        api_url = os.getenv('PISECURE_API_URL', 'http://localhost:3142')
        tx_monitor = TransactionMonitor(api_url)
        threading.Thread(
            target=tx_monitor.poll_mempool,
            daemon=True,
            name='tx-monitor'
        ).start()
    return tx_monitor

def get_wallet_validator():
    global wallet_validator
    if not wallet_validator:
        api_url = os.getenv('PISECURE_API_URL', 'http://localhost:3142')
        wallet_validator = WalletValidator(api_url)
    return wallet_validator

def get_peer_validator():
    global peer_validator
    if not peer_validator:
        api_url = os.getenv('PISECURE_API_URL', 'http://localhost:3142')
        peer_validator = PeerNetworkValidator(api_url)
        threading.Thread(
            target=peer_validator.poll_peer_network,
            daemon=True,
            name='peer-validator'
        ).start()
    return peer_validator
```

### 2. Add API Endpoints (around line ~6500)
```python
@app.route('/api/v1/blockchain/metrics', methods=['GET'])
def get_blockchain_metrics():
    """Get cached blockchain health metrics from PiSecure"""
    monitor = get_blockchain_monitor()
    return jsonify(monitor.get_metrics())

@app.route('/api/v1/mining/relay', methods=['GET'])
def get_mining_template_relay():
    """Get current mining template cached from PiSecure"""
    cache = get_mining_template_cache()
    template = cache.get_template()
    if template:
        template['source'] = 'bootstrap_cache'
        return jsonify(template)
    return jsonify({'error': 'No template available'}), 503

@app.route('/api/v1/mempool', methods=['GET'])
def get_mempool_status():
    """Get current mempool health from PiSecure"""
    monitor = get_tx_monitor()
    return jsonify(monitor.get_mempool())

@app.route('/api/v1/wallet/validate', methods=['POST'])
def validate_wallet():
    """Validate wallet balance (proxy to PiSecure)"""
    data = request.get_json() or {}
    wallet_id = data.get('wallet_id')
    required_balance = data.get('required_balance', 0)
    
    if not wallet_id:
        return jsonify({'error': 'wallet_id required'}), 400
    
    validator = get_wallet_validator()
    result = validator.validate_wallet_balance(wallet_id, required_balance)
    return jsonify(result)

@app.route('/api/v1/network/peer-health', methods=['GET'])
def get_peer_network_health():
    """Get peer network health and recommendations"""
    validator = get_peer_validator()
    health = validator.validate_peer_diversity()
    return jsonify(health)
```

## Testing

```python
# Test the integrations
def test_integrations():
    blockchain = get_blockchain_monitor()
    print(f"Blockchain metrics: {blockchain.get_metrics()}")
    
    mining = get_mining_template_cache()
    print(f"Mining template: {mining.get_template()}")
    
    tx = get_tx_monitor()
    print(f"Mempool: {tx.get_mempool()}")
    
    wallet = get_wallet_validator()
    print(f"Wallet validation: {wallet.validate_wallet_balance('test_wallet')}")
    
    peers = get_peer_validator()
    print(f"Peer health: {peers.validate_peer_diversity()}")
```

---

## Environment Variables

Add to your `.env` or deployment config:

```bash
# PiSecure API Integration
PISECURE_API_URL=https://pi.local:3142

# Polling intervals (optional)
BLOCKCHAIN_MONITOR_POLL_INTERVAL=5
MINING_TEMPLATE_POLL_INTERVAL=1
TX_MONITOR_POLL_INTERVAL=5
PEER_VALIDATOR_POLL_INTERVAL=10

# Wallet validation cache
WALLET_VALIDATOR_CACHE_TTL=300
```
