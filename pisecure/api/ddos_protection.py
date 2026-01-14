"""
PiSecure Advanced DDoS Protection & Abuse Detection
IP reputation, request fingerprinting, and intelligent rate limiting
"""

import time
import hashlib
import json
import threading
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
import ipaddress
import requests
import re


@dataclass
class ClientProfile:
    """Client behavior profile for DDoS detection"""
    ip_address: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    request_count: int = 0
    violation_count: int = 0
    delay_level: int = 0  # Progressive delay level
    reputation_score: float = 1.0  # 0.0 (blacklisted) to 1.0 (trusted)
    blocked_until: float = 0.0
    geographic_region: str = 'unknown'
    user_agent_fingerprint: str = ''
    request_patterns: Dict[str, int] = field(default_factory=dict)
    recent_requests: deque = field(default_factory=lambda: deque(maxlen=100))


@dataclass
class RequestFingerprint:
    """Unique fingerprint for request pattern analysis"""
    ip_address: str
    user_agent: str
    endpoint: str
    request_size: int
    parameter_count: int
    timestamp: float
    fingerprint_hash: str = ''


class DDoSProtection:
    """
    Advanced DDoS protection with ML-powered threat detection

    Features:
    - IP reputation management with progressive violations
    - Request fingerprinting for attack pattern analysis
    - Suspicious behavior detection (0.0-1.0 confidence)
    - Progressive rate limiting with escalation
    - Geographic threat analysis and regional blocking
    - Bootstrap intelligence integration for adaptive protection
    """

    def __init__(self, bootstrap_url: str = None,
                 intelligence_provider: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None):
        self.clients = {}  # IP -> ClientProfile
        self.fingerprints = deque(maxlen=10000)  # Recent request fingerprints
        self.blocked_ips = set()
        self.blocked_regions = set()

        # Configuration
        self.max_requests_per_minute = 100
        self.max_requests_per_hour = 1000
        self.violation_threshold = 5
        self.block_duration_minutes = 15
        self.geographic_threat_threshold = 0.7

        # Bootstrap integration
        self.bootstrap_url = bootstrap_url or 'http://localhost:8080'
        self.intelligence_provider = intelligence_provider
        self.intelligence_cache = {}
        self.cache_timeout = 300  # 5 minutes

        # Thread safety
        self.lock = threading.RLock()

        # Initialize cleanup thread
        self.cleanup_thread = threading.Thread(target=self._periodic_cleanup, daemon=True)
        self.cleanup_thread.start()

    def set_intelligence_provider(self, provider: Optional[Callable[[str], Optional[Dict[str, Any]]]]):
        """Set callable used to fetch intelligence data without HTTP."""
        self.intelligence_provider = provider

    def analyze_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze incoming request for DDoS patterns and abuse

        Args:
            request_data: Request information including IP, endpoint, headers, etc.

        Returns:
            Analysis result with security decisions
        """
        client_ip = request_data.get('client_ip', 'unknown')
        endpoint = request_data.get('endpoint', 'unknown')
        user_agent = request_data.get('user_agent', '')
        request_size = request_data.get('request_size', 0)
        parameters = request_data.get('parameters', {})

        with self.lock:
            # Get or create client profile
            client = self._get_or_create_client(client_ip, user_agent)

            # Update client activity
            self._update_client_activity(client, endpoint)

            # Generate request fingerprint
            fingerprint = self._generate_fingerprint(client_ip, user_agent, endpoint,
                                                   request_size, len(parameters))
            self.fingerprints.append(fingerprint)

            # Multi-layer analysis
            threat_score = self._calculate_threat_score(client, fingerprint, request_data)
            geographic_threat = self._analyze_geographic_threat(client_ip)
            pattern_anomaly = self._detect_pattern_anomalies(fingerprint)

            # Bootstrap intelligence integration
            intelligence_data = self._get_bootstrap_intelligence(endpoint)

            # Make security decisions
            should_block = self._should_block_request(client, threat_score, geographic_threat)
            delay_seconds = self._calculate_delay(client, threat_score)

            # Update client reputation
            if threat_score > 0.7:
                self._update_client_reputation(client, -0.1)  # Decrease reputation
            elif threat_score < 0.3:
                self._update_client_reputation(client, 0.05)  # Slight reputation increase

            # Handle violations
            if threat_score > 0.8:
                self._handle_violation(client)

            result = {
                'client_ip': client_ip,
                'should_block': should_block,
                'delay_seconds': delay_seconds,
                'threat_score': threat_score,
                'geographic_threat': geographic_threat,
                'pattern_anomaly': pattern_anomaly,
                'client_reputation': client.reputation_score,
                'intelligence_used': bool(intelligence_data),
                'recommendations': self._generate_security_recommendations(client, threat_score)
            }

            return result

    def _get_or_create_client(self, ip_address: str, user_agent: str) -> ClientProfile:
        """Get existing client profile or create new one"""
        if ip_address not in self.clients:
            geographic_region = self._geolocate_ip(ip_address)
            fingerprint = self._generate_user_agent_fingerprint(user_agent)

            self.clients[ip_address] = ClientProfile(
                ip_address=ip_address,
                geographic_region=geographic_region,
                user_agent_fingerprint=fingerprint
            )

        return self.clients[ip_address]

    def _update_client_activity(self, client: ClientProfile, endpoint: str):
        """Update client activity tracking"""
        current_time = time.time()
        client.last_seen = current_time
        client.request_count += 1

        # Track endpoint usage patterns
        if endpoint not in client.request_patterns:
            client.request_patterns[endpoint] = 0
        client.request_patterns[endpoint] += 1

        # Track recent requests for timing analysis
        client.recent_requests.append(current_time)

    def _generate_fingerprint(self, ip: str, user_agent: str, endpoint: str,
                            request_size: int, param_count: int) -> RequestFingerprint:
        """Generate unique request fingerprint for pattern analysis"""
        # Create fingerprint components
        components = [
            ip,
            user_agent[:100],  # Truncate long user agents
            endpoint,
            str(request_size),
            str(param_count),
            str(int(time.time() // 300))  # 5-minute time window
        ]

        # Generate hash
        fingerprint_str = '|'.join(components)
        fingerprint_hash = hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

        return RequestFingerprint(
            ip_address=ip,
            user_agent=user_agent,
            endpoint=endpoint,
            request_size=request_size,
            parameter_count=param_count,
            timestamp=time.time(),
            fingerprint_hash=fingerprint_hash
        )

    def _calculate_threat_score(self, client: ClientProfile, fingerprint: RequestFingerprint,
                               request_data: Dict[str, Any]) -> float:
        """
        Calculate comprehensive threat score using multiple factors

        Returns: 0.0 (safe) to 1.0 (high threat)
        """
        threat_score = 0.0
        factors = []

        # Factor 1: Client reputation (30% weight)
        reputation_factor = (1.0 - client.reputation_score) * 0.3
        threat_score += reputation_factor
        factors.append(('reputation', reputation_factor))

        # Factor 2: Request rate analysis (25% weight)
        rate_factor = self._analyze_request_rate(client) * 0.25
        threat_score += rate_factor
        factors.append(('rate', rate_factor))

        # Factor 3: Pattern anomaly detection (20% weight)
        pattern_factor = self._detect_pattern_anomalies(fingerprint) * 0.2
        threat_score += pattern_factor
        factors.append(('pattern', pattern_factor))

        # Factor 4: Geographic threat level (15% weight)
        geo_factor = self._analyze_geographic_threat(client.ip_address) * 0.15
        threat_score += geo_factor
        factors.append(('geographic', geo_factor))

        # Factor 5: User agent analysis (10% weight)
        ua_factor = self._analyze_user_agent(client, request_data.get('user_agent', '')) * 0.1
        threat_score += ua_factor
        factors.append(('user_agent', ua_factor))

        # Log high-threat requests for analysis
        if threat_score > 0.7:
            self._log_threat_analysis(client.ip_address, threat_score, factors)

        return min(1.0, threat_score)

    def _analyze_request_rate(self, client: ClientProfile) -> float:
        """Analyze request rate for DDoS detection"""
        if len(client.recent_requests) < 5:
            return 0.0  # Not enough data

        current_time = time.time()

        # Analyze different time windows
        rates = []

        # Last minute
        minute_requests = [t for t in client.recent_requests if current_time - t < 60]
        if minute_requests:
            rates.append(len(minute_requests))

        # Last 5 minutes
        five_min_requests = [t for t in client.recent_requests if current_time - t < 300]
        if five_min_requests:
            rates.append(len(five_min_requests) / 5.0)  # per minute rate

        # Last hour
        hour_requests = [t for t in client.recent_requests if current_time - t < 3600]
        if hour_requests:
            rates.append(len(hour_requests) / 60.0)  # per minute rate

        # Calculate threat based on highest rate
        if not rates:
            return 0.0

        max_rate = max(rates)

        # Threat levels based on rate thresholds
        if max_rate > self.max_requests_per_minute * 2:
            return 1.0  # Severe violation
        elif max_rate > self.max_requests_per_minute:
            return 0.8  # High violation
        elif max_rate > self.max_requests_per_minute * 0.7:
            return 0.5  # Moderate violation
        elif max_rate > self.max_requests_per_minute * 0.5:
            return 0.3  # Light violation
        else:
            return 0.0  # Normal

    def _detect_pattern_anomalies(self, fingerprint: RequestFingerprint) -> float:
        """Detect anomalous request patterns"""
        anomaly_score = 0.0

        # Check fingerprint frequency (potential botnet coordination)
        recent_fingerprints = [f for f in self.fingerprints
                             if f.fingerprint_hash == fingerprint.fingerprint_hash
                             and time.time() - f.timestamp < 300]  # Last 5 minutes

        if len(recent_fingerprints) > 10:
            anomaly_score += 0.6  # High frequency of same fingerprint

        # Check for enumeration patterns
        if self._detect_enumeration_pattern(fingerprint):
            anomaly_score += 0.4

        # Check for data exfiltration patterns
        if fingerprint.request_size > 100000:  # Large request
            anomaly_score += 0.3

        # Check parameter count anomalies
        if fingerprint.parameter_count > 20:
            anomaly_score += 0.2

        return min(1.0, anomaly_score)

    def _detect_enumeration_pattern(self, fingerprint: RequestFingerprint) -> bool:
        """Detect API enumeration attacks"""
        # Check for systematic endpoint scanning
        endpoint_pattern = re.search(r'/api/v\d+/(\w+)/(\d+)', fingerprint.endpoint)
        if endpoint_pattern:
            resource_type = endpoint_pattern.group(1)
            resource_id = int(endpoint_pattern.group(2))

            # Look for sequential ID patterns in recent requests
            recent_ids = []
            for f in self.fingerprints:
                if time.time() - f.timestamp < 600:  # Last 10 minutes
                    match = re.search(rf'/api/v\d+/{resource_type}/(\d+)', f.endpoint)
                    if match:
                        recent_ids.append(int(match.group(1)))

            if len(recent_ids) > 5:
                recent_ids.sort()
                # Check for sequential pattern
                sequential_count = 0
                for i in range(1, len(recent_ids)):
                    if recent_ids[i] == recent_ids[i-1] + 1:
                        sequential_count += 1

                if sequential_count > 3:  # 4+ sequential requests
                    return True

        return False

    def _analyze_geographic_threat(self, ip_address: str) -> float:
        """Analyze geographic threat level"""
        region = self._geolocate_ip(ip_address)

        # Check if region is blocked
        if region in self.blocked_regions:
            return 1.0  # Maximum threat

        # Analyze threat patterns by region
        region_requests = [f for f in self.fingerprints
                          if f.ip_address == ip_address and time.time() - f.timestamp < 3600]

        if len(region_requests) < 10:
            return 0.0  # Not enough data

        # Calculate regional threat score
        suspicious_count = 0
        for req in region_requests:
            if req.request_size > 50000 or req.parameter_count > 15:
                suspicious_count += 1

        threat_ratio = suspicious_count / len(region_requests)

        # High threat regions get elevated scores
        region_multipliers = {
            'high_risk': 1.5,
            'unknown': 1.2,  # Unknown locations are suspicious
        }

        multiplier = region_multipliers.get(region, 1.0)
        return min(1.0, threat_ratio * multiplier)

    def _analyze_user_agent(self, client: ClientProfile, user_agent: str) -> float:
        """Analyze user agent for bot detection"""
        threat_score = 0.0

        # Check for known bot patterns
        bot_patterns = [
            r'bot', r'crawler', r'spider', r'scanner',
            r'python-requests', r'curl', r'wget',
            r'go-http-client', r'java/', r'headless'
        ]

        ua_lower = user_agent.lower()
        for pattern in bot_patterns:
            if re.search(pattern, ua_lower):
                threat_score += 0.3
                break

        # Check user agent consistency
        if client.user_agent_fingerprint:
            current_fingerprint = self._generate_user_agent_fingerprint(user_agent)
            if current_fingerprint != client.user_agent_fingerprint:
                threat_score += 0.4  # User agent changing is suspicious

        # Empty or missing user agent
        if not user_agent or user_agent == '-':
            threat_score += 0.5

        return min(1.0, threat_score)

    def _should_block_request(self, client: ClientProfile, threat_score: float,
                            geographic_threat: float) -> bool:
        """Determine if request should be blocked"""
        # Check IP blocklist
        if client.ip_address in self.blocked_ips:
            return True

        # Check temporary blocks
        if time.time() < client.blocked_until:
            return True

        # High threat score
        if threat_score > 0.9:
            return True

        # Geographic blocking
        if geographic_threat > self.geographic_threat_threshold:
            return True

        # Violation threshold exceeded
        if client.violation_count > self.violation_threshold:
            return True

        return False

    def _calculate_delay(self, client: ClientProfile, threat_score: float) -> int:
        """Calculate progressive delay for suspicious requests"""
        if threat_score < 0.5:
            return 0  # No delay

        # Progressive delay based on threat level and violation history
        base_delay = int(threat_score * 5)  # 0-5 seconds
        violation_delay = client.violation_count * 2  # Additional delay per violation

        total_delay = base_delay + violation_delay + client.delay_level

        return min(total_delay, 30)  # Max 30 second delay

    def _handle_violation(self, client: ClientProfile):
        """Handle security violations with progressive responses"""
        client.violation_count += 1
        client.delay_level = min(client.delay_level + 1, 10)

        # Progressive blocking
        if client.violation_count >= self.violation_threshold:
            # Temporary block
            client.blocked_until = time.time() + (self.block_duration_minutes * 60)
            self._log_violation(client.ip_address, f"Temporary block for {self.block_duration_minutes} minutes")

        elif client.violation_count >= self.violation_threshold * 2:
            # Permanent block candidate
            self.blocked_ips.add(client.ip_address)
            self._log_violation(client.ip_address, "Added to permanent blocklist")

    def _update_client_reputation(self, client: ClientProfile, delta: float):
        """Update client reputation score"""
        client.reputation_score = max(0.0, min(1.0, client.reputation_score + delta))

    def _get_bootstrap_intelligence(self, endpoint: str) -> Optional[Dict]:
        """Get intelligence data for adaptive protection"""
        cache_key = f"intelligence_{endpoint}"

        # Check cache first
        if cache_key in self.intelligence_cache:
            cached_data, cache_time = self.intelligence_cache[cache_key]
            if time.time() - cache_time < self.cache_timeout:
                return cached_data

        # Prefer local intelligence provider if configured
        if self.intelligence_provider:
            try:
                data = self.intelligence_provider(endpoint)
                if data:
                    self.intelligence_cache[cache_key] = (data, time.time())
                    return data
            except Exception as e:
                self._log_error(f"Intelligence provider error: {e}")

        # Fallback to HTTP fetch if URL is available
        if not self.bootstrap_url:
            return None

        try:
            intelligence_url = f"{self.bootstrap_url}/api/v1/intelligence/predict"
            response = requests.get(intelligence_url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                self.intelligence_cache[cache_key] = (data, time.time())
                return data

        except Exception as e:
            self._log_error(f"Bootstrap intelligence fetch failed: {e}")

        return None

    def _geolocate_ip(self, ip_address: str) -> str:
        """Geolocate IP address to region"""
        try:
            # Use ip-api.com for geolocation
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=3)
            data = response.json()

            if data.get('status') == 'success':
                country_code = data.get('countryCode', '').lower()
                region = data.get('regionName', '').lower().replace(' ', '_')

                # Classify regions
                if country_code in ['cn', 'ru', 'kp', 'ir']:
                    return 'high_risk'
                elif region:
                    return f"{country_code}_{region}"
                else:
                    return country_code

        except Exception:
            pass

        return 'unknown'

    def _generate_user_agent_fingerprint(self, user_agent: str) -> str:
        """Generate consistent fingerprint for user agent"""
        # Normalize and hash user agent for consistency checking
        normalized = user_agent.lower().strip()
        return hashlib.md5(normalized.encode()).hexdigest()[:12]

    def _generate_security_recommendations(self, client: ClientProfile,
                                         threat_score: float) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []

        if threat_score > 0.8:
            recommendations.append("Immediate blocking recommended")
        elif threat_score > 0.6:
            recommendations.append("Progressive rate limiting applied")
        elif threat_score > 0.4:
            recommendations.append("Monitor client behavior closely")

        if client.violation_count > 2:
            recommendations.append("Client has violation history - consider whitelisting exceptions")

        if client.reputation_score < 0.3:
            recommendations.append("Low reputation client - additional scrutiny recommended")

        return recommendations

    def _periodic_cleanup(self):
        """Periodic cleanup of old data and expired blocks"""
        while True:
            try:
                current_time = time.time()

                # Clean up expired blocks
                expired_clients = []
                for ip, client in self.clients.items():
                    if current_time > client.blocked_until and client.blocked_until > 0:
                        client.blocked_until = 0  # Unblock
                        client.violation_count = max(0, client.violation_count - 1)  # Reduce violations

                    # Remove very old clients (30 days)
                    if current_time - client.last_seen > 2592000:  # 30 days
                        expired_clients.append(ip)

                for ip in expired_clients:
                    del self.clients[ip]

                # Clean old fingerprints (keep last 24 hours)
                cutoff_time = current_time - 86400
                while self.fingerprints and self.fingerprints[0].timestamp < cutoff_time:
                    self.fingerprints.popleft()

            except Exception as e:
                self._log_error(f"Cleanup error: {e}")

            time.sleep(300)  # Run every 5 minutes

    def get_protection_stats(self) -> Dict[str, Any]:
        """Get comprehensive protection statistics"""
        current_time = time.time()

        return {
            'active_clients': len(self.clients),
            'blocked_ips': len(self.blocked_ips),
            'blocked_regions': len(self.blocked_regions),
            'fingerprints_analyzed': len(self.fingerprints),
            'recent_violations': sum(1 for c in self.clients.values()
                                   if current_time - c.last_seen < 3600
                                   and c.violation_count > 0),
            'average_threat_score': sum(c.reputation_score for c in self.clients.values()) / max(1, len(self.clients)),
            'bootstrap_integration': bool(self.intelligence_cache),
            'last_cleanup': current_time
        }

    def _log_violation(self, ip_address: str, message: str):
        """Log security violations"""
        print(f"[DDoS PROTECTION] VIOLATION: {ip_address} - {message}")

    def _log_threat_analysis(self, ip_address: str, threat_score: float, factors: List[Tuple]):
        """Log detailed threat analysis"""
        factor_str = ', '.join([f"{name}: {score:.2f}" for name, score in factors])
        print(f"[DDoS PROTECTION] THREAT ANALYSIS: {ip_address} score={threat_score:.2f} factors=[{factor_str}]")

    def _log_error(self, message: str):
        """Log errors"""
        print(f"[DDoS PROTECTION] ERROR: {message}")


# Global DDoS protection instance
ddos_protection = DDoSProtection()