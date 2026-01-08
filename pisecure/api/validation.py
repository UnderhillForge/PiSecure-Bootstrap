"""
PiSecure Comprehensive Validation Framework
JSON Schema validation, input sanitization, and security-focused validation
"""

import re
import json
import hashlib
import time
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
import ipaddress
from urllib.parse import urlparse


@dataclass
class ValidationResult:
    """Result of validation operation"""
    is_valid: bool
    errors: List[str]
    sanitized_data: Optional[Dict[str, Any]] = None
    security_score: float = 1.0
    validation_time: float = 0.0


class ValidationEngine:
    """Comprehensive validation engine for PiSecure APIs"""

    def __init__(self):
        self.schemas = self._load_schemas()
        self.sanitizers = self._initialize_sanitizers()
        self.security_patterns = self._load_security_patterns()

    def _load_schemas(self) -> Dict[str, Dict]:
        """Load JSON schemas for different API endpoints"""
        return {
            'transaction': {
                'type': 'object',
                'required': ['type', 'data', 'timestamp'],
                'properties': {
                    'type': {'type': 'string', 'enum': ['transfer', 'token_transfer', 'trust_fund', 'mining_share']},
                    'data': {'type': 'object'},
                    'signature': {'type': 'string', 'minLength': 64, 'maxLength': 256},
                    'timestamp': {'type': 'number', 'minimum': 1609459200},  # 2021-01-01
                    'zk_proof': {'type': 'object'}  # Optional zero-knowledge proof
                }
            },
            'wallet_address': {
                'type': 'string',
                'pattern': '^pisecure_[a-f0-9]{32}$',
                'minLength': 40,
                'maxLength': 40
            },
            'blockchain_address': {
                'type': 'string',
                'pattern': '^[a-f0-9]{64}$',
                'minLength': 64,
                'maxLength': 64
            },
            'amount': {
                'type': 'number',
                'minimum': 0.00000001,
                'maximum': 1000000000.0  # 1 billion max
            }
        }

    def _initialize_sanitizers(self) -> Dict[str, callable]:
        """Initialize input sanitization functions"""
        return {
            'html': self._sanitize_html,
            'sql': self._sanitize_sql_injection,
            'xss': self._sanitize_xss,
            'path_traversal': self._sanitize_path_traversal,
            'command_injection': self._sanitize_command_injection,
            'json': self._sanitize_json_input
        }

    def _load_security_patterns(self) -> Dict[str, List[str]]:
        """Load security patterns for detection"""
        return {
            'suspicious_patterns': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'data:',
                r'vbscript:',
                r'on\w+\s*=',
                r'union\s+select',
                r';\s*drop\s+table',
                r';\s*delete\s+from',
                r'--',
                r'/\.\./',
                r'\\.\\.',
                r'\|\|',
                r'&&',
                r';\s*rm\s',
                r';\s*del\s',
                r';\s*format\s',
                r';\s*shutdown'
            ],
            'blockchain_patterns': [
                r'^pisecure_[a-f0-9]{32}$',  # PiSecure wallet format
                r'^[a-f0-9]{64}$',         # SHA256 hash format
                r'^[a-f0-9]{40}$',         # Address format
            ]
        }

    def validate_request(self, endpoint: str, data: Dict[str, Any],
                        client_ip: str = None) -> ValidationResult:
        """
        Comprehensive request validation with security analysis

        Args:
            endpoint: API endpoint identifier
            data: Request data to validate
            client_ip: Client IP address for additional validation

        Returns:
            ValidationResult with validation status and details
        """
        start_time = time.time()

        errors = []
        security_score = 1.0
        sanitized_data = data.copy()

        try:
            # Step 1: Input sanitization
            sanitized_data, sanitization_errors = self._sanitize_input(sanitized_data)
            errors.extend(sanitization_errors)

            if sanitization_errors:
                security_score -= 0.3

            # Step 2: Schema validation
            schema_errors = self._validate_schema(endpoint, sanitized_data)
            errors.extend(schema_errors)

            if schema_errors:
                security_score -= 0.4

            # Step 3: Security pattern analysis
            pattern_errors = self._analyze_security_patterns(sanitized_data)
            errors.extend(pattern_errors)

            if pattern_errors:
                security_score -= 0.5

            # Step 4: Blockchain-specific validation
            blockchain_errors = self._validate_blockchain_specific(endpoint, sanitized_data)
            errors.extend(blockchain_errors)

            if blockchain_errors:
                security_score -= 0.2

            # Step 5: Rate and behavior analysis (if client_ip provided)
            if client_ip:
                behavior_errors = self._analyze_client_behavior(client_ip, endpoint, sanitized_data)
                errors.extend(behavior_errors)

                if behavior_errors:
                    security_score -= 0.2

            # Step 6: Advanced security checks
            advanced_errors = self._advanced_security_checks(endpoint, sanitized_data, client_ip)
            errors.extend(advanced_errors)

            if advanced_errors:
                security_score -= 0.1

        except Exception as e:
            errors.append(f"Validation engine error: {str(e)}")
            security_score = 0.0

        validation_time = time.time() - start_time

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            sanitized_data=sanitized_data if errors else None,
            security_score=max(0.0, security_score),
            validation_time=validation_time
        )

    def _sanitize_input(self, data: Dict[str, Any]) -> tuple:
        """Sanitize input data for security"""
        errors = []

        for key, value in data.items():
            if isinstance(value, str):
                # Apply multiple sanitization layers
                original_value = value
                value = self._sanitize_html(value)
                value = self._sanitize_xss(value)
                value = self._sanitize_sql_injection(value)
                value = self._sanitize_path_traversal(value)
                value = self._sanitize_command_injection(value)

                if value != original_value:
                    data[key] = value
                    errors.append(f"Input sanitized for field '{key}'")

            elif isinstance(value, dict):
                # Recursively sanitize nested objects
                data[key], nested_errors = self._sanitize_input(value)
                errors.extend([f"{key}.{err}" for err in nested_errors])

            elif isinstance(value, list):
                # Sanitize array elements
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        sanitized = self._sanitize_html(item)
                        sanitized = self._sanitize_xss(sanitized)
                        if sanitized != item:
                            value[i] = sanitized
                            errors.append(f"Array element {i} in '{key}' sanitized")

        return data, errors

    def _sanitize_html(self, text: str) -> str:
        """Remove HTML/script tags"""
        # Remove script tags and their content
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
        # Remove other HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        return text.strip()

    def _sanitize_xss(self, text: str) -> str:
        """Remove XSS attack vectors"""
        # Remove javascript: URLs
        text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
        # Remove data: URLs
        text = re.sub(r'data:', '', text, flags=re.IGNORECASE)
        # Remove event handlers
        text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
        # Remove vbscript
        text = re.sub(r'vbscript:', '', text, flags=re.IGNORECASE)
        return text

    def _sanitize_sql_injection(self, text: str) -> str:
        """Remove SQL injection patterns"""
        # Remove common SQL injection patterns
        patterns = [
            r'union\s+select', r';\s*drop\s+table', r';\s*delete\s+from',
            r'--', r'/\*.*?\*/', r';\s*update\s+.*?\s+set'
        ]
        for pattern in patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        return text

    def _sanitize_path_traversal(self, text: str) -> str:
        """Remove path traversal attempts"""
        # Remove ../ and ..\ patterns
        text = re.sub(r'/\.\./', '/', text)
        text = re.sub(r'\\.\\.', '\\\\', text)
        return text

    def _sanitize_command_injection(self, text: str) -> str:
        """Remove command injection patterns"""
        # Remove shell command patterns
        patterns = [
            r';\s*rm\s', r';\s*del\s', r';\s*format\s', r';\s*shutdown',
            r'\|\|', r'&&', r';\s*echo\s', r';\s*cat\s'
        ]
        for pattern in patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        return text

    def _sanitize_json_input(self, data: Any) -> Any:
        """Sanitize JSON input data"""
        if isinstance(data, str):
            # Try to parse as JSON and validate
            try:
                parsed = json.loads(data)
                return parsed
            except json.JSONDecodeError:
                return None
        return data

    def _validate_schema(self, endpoint: str, data: Dict[str, Any]) -> List[str]:
        """Validate data against JSON schema"""
        errors = []

        if endpoint not in self.schemas:
            return errors  # No schema defined for this endpoint

        schema = self.schemas[endpoint]

        # Basic required fields check
        if 'required' in schema:
            for field in schema['required']:
                if field not in data:
                    errors.append(f"Required field '{field}' is missing")

        # Type and constraint validation
        if 'properties' in schema:
            for field, constraints in schema['properties'].items():
                if field in data:
                    value = data[field]
                    field_errors = self._validate_field_constraints(field, value, constraints)
                    errors.extend(field_errors)

        return errors

    def _validate_field_constraints(self, field: str, value: Any, constraints: Dict) -> List[str]:
        """Validate field against schema constraints"""
        errors = []

        # Type validation
        expected_type = constraints.get('type')
        if expected_type:
            if expected_type == 'string' and not isinstance(value, str):
                errors.append(f"Field '{field}' must be a string")
            elif expected_type == 'number' and not isinstance(value, (int, float)):
                errors.append(f"Field '{field}' must be a number")
            elif expected_type == 'object' and not isinstance(value, dict):
                errors.append(f"Field '{field}' must be an object")

        # String constraints
        if isinstance(value, str):
            min_len = constraints.get('minLength')
            max_len = constraints.get('maxLength')
            pattern = constraints.get('pattern')

            if min_len and len(value) < min_len:
                errors.append(f"Field '{field}' must be at least {min_len} characters")
            if max_len and len(value) > max_len:
                errors.append(f"Field '{field}' must be at most {max_len} characters")
            if pattern and not re.match(pattern, value):
                errors.append(f"Field '{field}' does not match required pattern")

        # Number constraints
        if isinstance(value, (int, float)):
            minimum = constraints.get('minimum')
            maximum = constraints.get('maximum')

            if minimum is not None and value < minimum:
                errors.append(f"Field '{field}' must be at least {minimum}")
            if maximum is not None and value > maximum:
                errors.append(f"Field '{field}' must be at most {maximum}")

        # Enum validation
        enum_values = constraints.get('enum', [])
        if enum_values and value not in enum_values:
            errors.append(f"Field '{field}' must be one of: {', '.join(enum_values)}")

        return errors

    def _analyze_security_patterns(self, data: Dict[str, Any]) -> List[str]:
        """Analyze data for security patterns"""
        errors = []

        def check_patterns(obj, path=""):
            if isinstance(obj, str):
                for pattern in self.security_patterns['suspicious_patterns']:
                    if re.search(pattern, obj, re.IGNORECASE):
                        errors.append(f"Suspicious pattern detected in {path}: {pattern}")
            elif isinstance(obj, dict):
                for key, value in obj.items():
                    check_patterns(value, f"{path}.{key}" if path else key)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_patterns(item, f"{path}[{i}]")

        check_patterns(data)
        return errors

    def _validate_blockchain_specific(self, endpoint: str, data: Dict[str, Any]) -> List[str]:
        """Blockchain-specific validation"""
        errors = []

        # Wallet address validation
        if 'wallet_address' in data:
            if not self._is_valid_pisecure_wallet(data['wallet_address']):
                errors.append("Invalid PiSecure wallet address format")

        # Transaction hash validation
        if 'transaction_hash' in data or 'hash' in data:
            hash_value = data.get('transaction_hash') or data.get('hash')
            if not self._is_valid_transaction_hash(hash_value):
                errors.append("Invalid transaction hash format")

        # Amount validation
        if 'amount' in data:
            if not self._is_valid_amount(data['amount']):
                errors.append("Invalid transaction amount")

        # Signature validation (basic format check)
        if 'signature' in data:
            if not self._is_valid_signature_format(data['signature']):
                errors.append("Invalid signature format")

        return errors

    def _is_valid_pisecure_wallet(self, address: str) -> bool:
        """Validate PiSecure wallet address format"""
        return bool(re.match(r'^pisecure_[a-f0-9]{32}$', address))

    def _is_valid_transaction_hash(self, hash_value: str) -> bool:
        """Validate transaction hash format"""
        return bool(re.match(r'^[a-f0-9]{64}$', hash_value))

    def _is_valid_amount(self, amount: Any) -> bool:
        """Validate transaction amount"""
        try:
            num_amount = float(amount)
            return 0.00000001 <= num_amount <= 1000000000.0
        except (ValueError, TypeError):
            return False

    def _is_valid_signature_format(self, signature: str) -> bool:
        """Validate signature format (basic check)"""
        # Basic length and hex format check
        return bool(re.match(r'^[a-f0-9]{64,512}$', signature))

    def _analyze_client_behavior(self, client_ip: str, endpoint: str, data: Dict[str, Any]) -> List[str]:
        """Analyze client behavior patterns"""
        errors = []

        # IP validation
        try:
            ipaddress.ip_address(client_ip)
        except ValueError:
            errors.append("Invalid client IP address")
            return errors

        # Check for rapid-fire requests (would integrate with DDoS protection)
        # This is a placeholder for behavior analysis that would integrate with DDoSProtection

        return errors

    def _advanced_security_checks(self, endpoint: str, data: Dict[str, Any], client_ip: str = None) -> List[str]:
        """Advanced security validation"""
        errors = []

        # Check for data exfiltration attempts
        if self._detect_data_exfiltration(data):
            errors.append("Potential data exfiltration attempt detected")

        # Check for enumeration attacks
        if self._detect_enumeration_attack(endpoint, data):
            errors.append("Potential enumeration attack detected")

        # Check for timing attacks
        if self._detect_timing_attack(data):
            errors.append("Potential timing attack pattern detected")

        return errors

    def _detect_data_exfiltration(self, data: Dict[str, Any]) -> bool:
        """Detect potential data exfiltration attempts"""
        # Check for unusual data volumes or patterns
        total_data_size = len(json.dumps(data))
        if total_data_size > 1000000:  # 1MB limit
            return True

        # Check for encoded data patterns
        def check_encoded(obj):
            if isinstance(obj, str):
                # Check for base64-like patterns
                if re.search(r'^[A-Za-z0-9+/]{100,}=*$', obj):
                    return True
                # Check for hex-encoded data
                if re.search(r'^[a-f0-9]{100,}$', obj):
                    return True
            elif isinstance(obj, (dict, list)):
                for item in (obj.values() if isinstance(obj, dict) else obj):
                    if check_encoded(item):
                        return True
            return False

        return check_encoded(data)

    def _detect_enumeration_attack(self, endpoint: str, data: Dict[str, Any]) -> bool:
        """Detect endpoint enumeration attacks"""
        # Check for sequential ID patterns that might indicate enumeration
        if 'id' in data or 'index' in data:
            return False  # Not necessarily enumeration

        # Check for systematic parameter variations
        return False  # Placeholder for more sophisticated detection

    def _detect_timing_attack(self, data: Dict[str, Any]) -> bool:
        """Detect potential timing attack patterns"""
        # Check for unusually precise timestamps that might indicate automation
        if 'timestamp' in data:
            timestamp = data['timestamp']
            # Check if timestamp is too precise (sub-millisecond precision might indicate automation)
            if isinstance(timestamp, (int, float)):
                fractional_part = timestamp - int(timestamp)
                if fractional_part != 0 and len(str(fractional_part).split('.')[1]) > 3:
                    return True

        return False

    def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation engine statistics"""
        return {
            'schemas_loaded': len(self.schemas),
            'sanitizers_active': len(self.sanitizers),
            'security_patterns': len(self.security_patterns.get('suspicious_patterns', [])),
            'validation_engine_version': '1.0.0'
        }


# Global validation engine instance
validation_engine = ValidationEngine()