"""
PiSecure Sentinel Service - Active Defense & Reputation Management
Ghostwheel Sentinel integration for proactive monitoring and coordinated defense
"""

import time
import hashlib
import json
import threading
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class NodeReputation:
    """Node reputation profile"""
    node_id: str
    reputation_score: float = 50.0  # 0-100 scale
    trust_level: str = 'neutral'  # low, neutral, high, trusted
    incident_count: int = 0
    last_incident: float = 0.0
    positive_contributions: int = 0
    network_standing: str = 'active'  # active, monitored, quarantined, blacklisted
    first_seen: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    incident_history: List[Dict] = field(default_factory=list)


@dataclass
class ThreatSignature:
    """Threat signature for pattern matching"""
    signature_id: str
    threat_type: str
    confidence: float
    indicators: List[str]
    affected_nodes: List[str]
    recommended_action: str
    evidence: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)


@dataclass
class DefenseAction:
    """Coordinated defense action"""
    action_id: str
    action_type: str  # isolate_node, increase_monitoring, blacklist, etc.
    target: str
    duration_minutes: int
    reason: str
    coordinator_node: str
    participants: List[str]
    status: str = 'pending'  # pending, active, completed
    timestamp: float = field(default_factory=time.time)


class SentinelService:
    """
    Ghostwheel Sentinel Service for active defense coordination
    
    Features:
    - Node reputation management
    - Threat signature detection and reporting
    - Defense coordination across bootstrap network
    - Blockchain intelligence monitoring
    - Alert propagation system
    """
    
    def __init__(self):
        self.node_reputations = {}  # node_id -> NodeReputation
        self.threat_signatures = deque(maxlen=1000)
        self.active_defense_actions = {}  # action_id -> DefenseAction
        self.blockchain_metrics_cache = {}
        self.alert_history = deque(maxlen=500)
        
        # Configuration
        self.reputation_thresholds = {
            'trusted': 80,
            'high': 60,
            'neutral': 40,
            'low': 20
        }
        
        self.quarantine_threshold = 30
        self.blacklist_threshold = 10
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Initialize cleanup thread
        self.cleanup_thread = threading.Thread(target=self._periodic_cleanup, daemon=True)
        self.cleanup_thread.start()
    
    def register_sentinel_node(self, node_data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a sentinel AI node"""
        node_id = node_data.get('node_id')
        sentinel_config = node_data.get('sentinel_config', {})
        
        with self.lock:
            # Create or update reputation
            if node_id not in self.node_reputations:
                self.node_reputations[node_id] = NodeReputation(
                    node_id=node_id,
                    reputation_score=50.0,  # Start neutral
                    trust_level='neutral'
                )
            
            return {
                'registration_success': True,
                'node_id': node_id,
                'assigned_role': 'sentinel_ai',
                'network_permissions': ['monitor', 'alert', 'coordinate'],
                'initial_reputation': self.node_reputations[node_id].reputation_score,
                'sentinel_capabilities': {
                    'threat_detection': True,
                    'defense_coordination': True,
                    'reputation_management': True,
                    'blockchain_monitoring': sentinel_config.get('monitoring_enabled', True)
                }
            }
    
    def update_sentinel_status(self, node_id: str, status_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process sentinel node status update"""
        with self.lock:
            if node_id not in self.node_reputations:
                return {'error': 'Node not registered'}
            
            reputation = self.node_reputations[node_id]
            reputation.last_updated = time.time()
            
            sentinel_status = status_data.get('sentinel_status', {})
            
            # Update reputation based on activity
            if sentinel_status.get('monitoring_active'):
                self._adjust_reputation(node_id, 0.1)  # Small positive contribution
            
            # Process detected threats
            threats_detected = sentinel_status.get('threats_detected', 0)
            if threats_detected > 0:
                self._adjust_reputation(node_id, threats_detected * 0.5)  # Reward threat detection
            
            return {
                'status_updated': True,
                'current_reputation': reputation.reputation_score,
                'trust_level': reputation.trust_level,
                'network_standing': reputation.network_standing
            }
    
    def submit_threat_signature(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process threat signature submission from sentinel node"""
        reporter_node = report_data.get('reporter_node')
        threat_sig = report_data.get('threat_signature', {})
        coordination_req = report_data.get('coordination_request', {})
        
        with self.lock:
            # Validate reporter reputation
            if reporter_node not in self.node_reputations:
                return {'error': 'Reporter not registered'}
            
            reporter_rep = self.node_reputations[reporter_node]
            if reporter_rep.reputation_score < self.reputation_thresholds['low']:
                return {'error': 'Insufficient reputation to report threats'}
            
            # Create threat signature
            signature_id = self._generate_signature_id(threat_sig)
            signature = ThreatSignature(
                signature_id=signature_id,
                threat_type=threat_sig.get('type'),
                confidence=threat_sig.get('confidence', 0.5),
                indicators=threat_sig.get('indicators', []),
                affected_nodes=threat_sig.get('affected_nodes', []),
                recommended_action=threat_sig.get('recommended_action', 'monitor'),
                evidence=threat_sig.get('evidence', {})
            )
            
            self.threat_signatures.append(signature)
            
            # Reward reporter
            reward = signature.confidence * 2.0
            self._adjust_reputation(reporter_node, reward)
            
            # Handle coordination request
            coordination_result = {}
            if coordination_req.get('network_wide_alert'):
                coordination_result['alert_propagated'] = self._propagate_alert(signature)
            
            if coordination_req.get('blacklist_propagation'):
                coordination_result['blacklist_updated'] = self._update_blacklist(signature)
            
            return {
                'threat_accepted': True,
                'signature_id': signature_id,
                'confidence': signature.confidence,
                'reporter_reward': reward,
                'coordination_actions': coordination_result,
                'recommended_response': signature.recommended_action
            }
    
    def coordinate_defense(self, coord_data: Dict[str, Any]) -> Dict[str, Any]:
        """Coordinate defense actions across the network"""
        coordinator_node = coord_data.get('coordinator_node')
        strategy = coord_data.get('strategy', 'standard')
        actions = coord_data.get('actions', [])
        participants = coord_data.get('participants', [])
        
        with self.lock:
            # Validate coordinator
            if coordinator_node not in self.node_reputations:
                return {'error': 'Coordinator not registered'}
            
            coord_rep = self.node_reputations[coordinator_node]
            if coord_rep.reputation_score < self.reputation_thresholds['high']:
                return {'error': 'Insufficient reputation to coordinate defense'}
            
            # Create defense actions
            action_results = []
            for action in actions:
                action_id = self._generate_action_id(action)
                defense_action = DefenseAction(
                    action_id=action_id,
                    action_type=action.get('type'),
                    target=action.get('target'),
                    duration_minutes=action.get('duration_minutes', 30),
                    reason=action.get('reason'),
                    coordinator_node=coordinator_node,
                    participants=participants,
                    status='active'
                )
                
                self.active_defense_actions[action_id] = defense_action
                
                # Execute action
                execution_result = self._execute_defense_action(defense_action)
                action_results.append({
                    'action_id': action_id,
                    'action_type': action.get('type'),
                    'status': 'active',
                    'execution_result': execution_result
                })
            
            # Reward coordinator
            self._adjust_reputation(coordinator_node, len(actions) * 1.0)
            
            return {
                'coordination_success': True,
                'strategy': strategy,
                'actions_initiated': len(action_results),
                'action_details': action_results,
                'participants_notified': len(participants)
            }
    
    def get_node_reputation(self, node_id: str) -> Dict[str, Any]:
        """Get reputation information for a node"""
        with self.lock:
            if node_id not in self.node_reputations:
                return {
                    'node_id': node_id,
                    'reputation_score': 50,
                    'trust_level': 'unknown',
                    'network_standing': 'unregistered'
                }
            
            reputation = self.node_reputations[node_id]
            
            return {
                'node_id': node_id,
                'reputation_score': reputation.reputation_score,
                'trust_level': reputation.trust_level,
                'incident_count': reputation.incident_count,
                'last_incident': reputation.last_incident,
                'positive_contributions': reputation.positive_contributions,
                'network_standing': reputation.network_standing,
                'first_seen': reputation.first_seen,
                'last_updated': reputation.last_updated
            }
    
    def update_node_reputation(self, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update node reputation based on incident or contribution"""
        reporter_node = update_data.get('reporter_node')
        target_node = update_data.get('target_node')
        update_type = update_data.get('update_type')
        severity = update_data.get('severity', 'medium')
        evidence = update_data.get('evidence', {})
        score_adjustment = update_data.get('recommended_score_adjustment', 0)
        
        with self.lock:
            # Validate reporter
            if reporter_node not in self.node_reputations:
                return {'error': 'Reporter not registered'}
            
            reporter_rep = self.node_reputations[reporter_node]
            if reporter_rep.reputation_score < self.reputation_thresholds['neutral']:
                return {'error': 'Insufficient reputation to report incidents'}
            
            # Get or create target reputation
            if target_node not in self.node_reputations:
                self.node_reputations[target_node] = NodeReputation(node_id=target_node)
            
            target_rep = self.node_reputations[target_node]
            
            # Apply reputation adjustment
            if update_type == 'incident_report':
                target_rep.incident_count += 1
                target_rep.last_incident = time.time()
                self._adjust_reputation(target_node, score_adjustment)
                
                # Record incident
                target_rep.incident_history.append({
                    'type': update_type,
                    'severity': severity,
                    'reporter': reporter_node,
                    'evidence': evidence,
                    'timestamp': time.time()
                })
                
                # Check for quarantine/blacklist
                self._check_network_standing(target_node)
                
            elif update_type == 'positive_contribution':
                target_rep.positive_contributions += 1
                self._adjust_reputation(target_node, abs(score_adjustment))
            
            # Update trust level
            target_rep.trust_level = self._calculate_trust_level(target_rep.reputation_score)
            
            return {
                'update_success': True,
                'target_node': target_node,
                'new_reputation_score': target_rep.reputation_score,
                'trust_level': target_rep.trust_level,
                'network_standing': target_rep.network_standing,
                'incident_count': target_rep.incident_count
            }
    
    def get_blockchain_metrics(self) -> Dict[str, Any]:
        """Get blockchain health metrics"""
        # This would integrate with real blockchain in production
        # For now, return simulated metrics
        current_time = time.time()
        
        metrics = {
            'current_block_height': 1250000 + int((current_time % 1000) * 10),
            'network_hashrate_th': 450.5 + (hash(str(current_time)) % 100),
            'average_block_time_minutes': 12.5,
            'active_miners': 1250,
            'difficulty': 25000000000,
            'pending_transactions': 15000 + (hash(str(current_time)) % 5000),
            'network_health_score': 92,
            'anomalies': []
        }
        
        # Detect anomalies (simulated)
        if metrics['network_hashrate_th'] < 400:
            metrics['anomalies'].append({
                'type': 'hashrate_drop',
                'severity': 'medium',
                'change_percent': -15.2,
                'duration_minutes': 45
            })
        
        self.blockchain_metrics_cache = metrics
        return metrics
    
    def submit_blockchain_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process blockchain anomaly alert"""
        reporter_node = alert_data.get('reporter_node')
        alert_type = alert_data.get('alert_type')
        severity = alert_data.get('severity', 'medium')
        details = alert_data.get('details', {})
        
        with self.lock:
            # Validate reporter
            if reporter_node not in self.node_reputations:
                return {'error': 'Reporter not registered'}
            
            # Record alert
            alert_id = self._generate_alert_id(alert_data)
            self.alert_history.append({
                'alert_id': alert_id,
                'reporter_node': reporter_node,
                'alert_type': alert_type,
                'severity': severity,
                'details': details,
                'timestamp': time.time()
            })
            
            # Reward reporter for valid alerts
            if severity in ['high', 'critical']:
                self._adjust_reputation(reporter_node, 2.0)
            else:
                self._adjust_reputation(reporter_node, 0.5)
            
            return {
                'alert_accepted': True,
                'alert_id': alert_id,
                'severity': severity,
                'action_taken': 'monitoring_increased',
                'network_notified': True
            }
    
    def propagate_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Propagate security alert across the network using Intelligence Federation"""
        source_node = alert_data.get('source_node')
        alert_id = alert_data.get('alert_id')
        severity = alert_data.get('severity', 'medium')
        category = alert_data.get('category')
        message = alert_data.get('message')
        affected_components = alert_data.get('affected_components', [])
        recommended_actions = alert_data.get('recommended_actions', [])
        
        with self.lock:
            # Validate source with trust-based filtering
            if source_node not in self.node_reputations:
                return {'error': 'Source node not registered'}
            
            source_reputation = self.node_reputations[source_node]
            
            # Trust-based filtering: only propagate high-severity alerts from trusted sources
            min_reputation_for_propagation = {
                'critical': 70.0,  # Only highly trusted nodes can trigger critical alerts
                'high': 60.0,      # High reputation needed for high-severity alerts
                'medium': 40.0,    # Neutral reputation for medium alerts
                'low': 20.0        # Even low reputation nodes can report low-severity issues
            }
            
            required_reputation = min_reputation_for_propagation.get(severity, 40.0)
            
            if source_reputation.reputation_score < required_reputation:
                return {
                    'propagation_denied': True,
                    'reason': f'Source reputation ({source_reputation.reputation_score:.1f}) below threshold ({required_reputation}) for {severity} severity alerts',
                    'alert_id': alert_id
                }
            
            # Record alert
            self.alert_history.append({
                'alert_id': alert_id,
                'source_node': source_node,
                'severity': severity,
                'category': category,
                'message': message,
                'timestamp': time.time()
            })
            
            # Local propagation count
            local_propagation_count = self._propagate_to_network(alert_data)
            
            # Propagate to Intelligence Federation for network-wide distribution
            federation_propagation_count = 0
            
            # Only propagate critical and high severity alerts to federation
            if severity in ['critical', 'high']:
                try:
                    # Import intelligence federation (circular import prevention)
                    import sys
                    bootstrap_module = sys.modules.get('bootstrap.server')
                    
                    if bootstrap_module and hasattr(bootstrap_module, 'intelligence_federation'):
                        intelligence_federation = bootstrap_module.intelligence_federation
                        
                        # Prepare threat intelligence for sharing
                        threat_intel = {
                            'alert_id': alert_id,
                            'source_node': source_node,
                            'source_reputation': source_reputation.reputation_score,
                            'severity': severity,
                            'category': category,
                            'message': message,
                            'affected_components': affected_components,
                            'recommended_actions': recommended_actions,
                            'timestamp': time.time(),
                            'trust_verified': True
                        }
                        
                        # Share with peer bootstrap nodes
                        intelligence_federation.share_threat_intelligence(threat_intel)
                        federation_propagation_count = len(intelligence_federation.intelligence_peers)
                        
                except Exception as e:
                    # Log error but don't fail the alert propagation
                    print(f"[SENTINEL] Federation propagation error: {e}")
            
            return {
                'propagation_success': True,
                'alert_id': alert_id,
                'local_nodes_notified': local_propagation_count,
                'federation_nodes_notified': federation_propagation_count,
                'total_propagation': local_propagation_count + federation_propagation_count,
                'severity': severity,
                'trust_verified': True,
                'source_reputation': source_reputation.reputation_score,
                'recommended_actions': recommended_actions
            }
    
    def _adjust_reputation(self, node_id: str, delta: float):
        """Adjust node reputation score"""
        if node_id not in self.node_reputations:
            return
        
        reputation = self.node_reputations[node_id]
        reputation.reputation_score = max(0.0, min(100.0, reputation.reputation_score + delta))
        reputation.trust_level = self._calculate_trust_level(reputation.reputation_score)
        reputation.last_updated = time.time()
        
        # Check network standing
        self._check_network_standing(node_id)
    
    def _calculate_trust_level(self, score: float) -> str:
        """Calculate trust level from reputation score"""
        if score >= self.reputation_thresholds['trusted']:
            return 'trusted'
        elif score >= self.reputation_thresholds['high']:
            return 'high'
        elif score >= self.reputation_thresholds['neutral']:
            return 'neutral'
        else:
            return 'low'
    
    def _check_network_standing(self, node_id: str):
        """Check and update network standing based on reputation"""
        if node_id not in self.node_reputations:
            return
        
        reputation = self.node_reputations[node_id]
        
        if reputation.reputation_score <= self.blacklist_threshold:
            reputation.network_standing = 'blacklisted'
        elif reputation.reputation_score <= self.quarantine_threshold:
            reputation.network_standing = 'quarantined'
        elif reputation.reputation_score < self.reputation_thresholds['neutral']:
            reputation.network_standing = 'monitored'
        else:
            reputation.network_standing = 'active'
    
    def _execute_defense_action(self, action: DefenseAction) -> Dict[str, Any]:
        """Execute a defense action"""
        # This would integrate with actual defense systems
        # For now, return execution status
        return {
            'executed': True,
            'action_type': action.action_type,
            'target': action.target,
            'estimated_completion': f"{action.duration_minutes} minutes"
        }
    
    def _propagate_alert(self, signature: ThreatSignature) -> bool:
        """Propagate threat alert to network"""
        # This would send alerts to all registered sentinel nodes
        return True
    
    def _update_blacklist(self, signature: ThreatSignature) -> bool:
        """Update network blacklist based on threat"""
        for node_id in signature.affected_nodes:
            if node_id in self.node_reputations:
                self._adjust_reputation(node_id, -20.0)
        return True
    
    def _propagate_to_network(self, alert_data: Dict[str, Any]) -> int:
        """Propagate alert to network nodes"""
        # This would send to all registered nodes
        # Return simulated count
        return len(self.node_reputations)
    
    def _generate_signature_id(self, threat_sig: Dict) -> str:
        """Generate unique signature ID"""
        sig_str = json.dumps(threat_sig, sort_keys=True)
        return hashlib.sha256(sig_str.encode()).hexdigest()[:16]
    
    def _generate_action_id(self, action: Dict) -> str:
        """Generate unique action ID"""
        action_str = f"{action.get('type')}_{action.get('target')}_{time.time()}"
        return hashlib.sha256(action_str.encode()).hexdigest()[:16]
    
    def _generate_alert_id(self, alert_data: Dict) -> str:
        """Generate unique alert ID"""
        alert_str = json.dumps(alert_data, sort_keys=True)
        return hashlib.sha256(alert_str.encode()).hexdigest()[:16]
    
    def _periodic_cleanup(self):
        """Periodic cleanup of old data"""
        while True:
            try:
                current_time = time.time()
                
                # Clean up completed defense actions (older than 24 hours)
                expired_actions = []
                for action_id, action in self.active_defense_actions.items():
                    if current_time - action.timestamp > 86400:
                        expired_actions.append(action_id)
                
                for action_id in expired_actions:
                    del self.active_defense_actions[action_id]
                
                # Decay reputation slightly over time for inactive nodes
                for node_id, reputation in self.node_reputations.items():
                    if current_time - reputation.last_updated > 604800:  # 1 week
                        reputation.reputation_score = max(0, reputation.reputation_score - 0.1)
                        reputation.trust_level = self._calculate_trust_level(reputation.reputation_score)
                
            except Exception as e:
                print(f"[SENTINEL] Cleanup error: {e}")
            
            time.sleep(3600)  # Run every hour
    
    def get_sentinel_stats(self) -> Dict[str, Any]:
        """Get comprehensive sentinel statistics"""
        with self.lock:
            active_threats = len([s for s in self.threat_signatures 
                                if time.time() - s.timestamp < 3600])
            
            return {
                'registered_nodes': len(self.node_reputations),
                'active_defense_actions': len(self.active_defense_actions),
                'threat_signatures_analyzed': len(self.threat_signatures),
                'active_threats_last_hour': active_threats,
                'recent_alerts': len(self.alert_history),
                'reputation_distribution': self._get_reputation_distribution(),
                'network_standing_summary': self._get_network_standing_summary()
            }
    
    def _get_reputation_distribution(self) -> Dict[str, int]:
        """Get distribution of reputation levels"""
        distribution = {'trusted': 0, 'high': 0, 'neutral': 0, 'low': 0}
        for reputation in self.node_reputations.values():
            level = reputation.trust_level
            if level in distribution:
                distribution[level] += 1
        return distribution
    
    def _get_network_standing_summary(self) -> Dict[str, int]:
        """Get summary of network standing"""
        summary = {'active': 0, 'monitored': 0, 'quarantined': 0, 'blacklisted': 0}
        for reputation in self.node_reputations.values():
            standing = reputation.network_standing
            if standing in summary:
                summary[standing] += 1
        return summary


# Global sentinel service instance
sentinel_service = SentinelService()