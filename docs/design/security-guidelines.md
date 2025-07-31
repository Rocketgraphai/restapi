# Security Guidelines

## Security-First Design Principles

The RocketGraph Public API is built with security as the foundational requirement, implementing multiple layers of protection to ensure enterprise-grade security for commercial deployment.

## Defense in Depth Architecture

### Layer 1: Network Security

**Web Application Firewall (WAF)**
- **SQL Injection Protection**: Detect and block SQL injection attempts
- **XSS Prevention**: Filter malicious scripts and content
- **Rate Limiting**: Network-level rate limiting before requests reach the API
- **Geographic Blocking**: Optional country-based access restrictions
- **DDoS Protection**: Distributed denial of service attack mitigation

**TLS/SSL Configuration**
```yaml
# Minimum TLS configuration
tls:
  min_version: "1.2"
  preferred_version: "1.3"
  cipher_suites:
    - "TLS_AES_256_GCM_SHA384"
    - "TLS_CHACHA20_POLY1305_SHA256"
    - "TLS_AES_128_GCM_SHA256"
  certificates:
    - type: "wildcard"
      domains: ["*.api.rocketgraph.com"]
    - type: "ecc"
      curve: "P-256"
```

**Network Isolation**
- **Private Subnets**: API servers in private subnets
- **VPC Configuration**: Isolated network environments
- **Security Groups**: Restrictive firewall rules
- **Load Balancer**: SSL termination and traffic distribution

### Layer 2: Application Security

**Input Validation & Sanitization**
```python
class RequestValidator:
    """Comprehensive request validation"""
    
    @staticmethod
    def validate_query_input(query: str) -> None:
        """Validate graph query for security issues"""
        
        # 1. Length validation
        if len(query) > 10000:
            raise ValidationError("Query exceeds maximum length")
        
        # 2. Forbidden patterns
        forbidden_patterns = [
            r'(?i)DROP\s+TABLE',
            r'(?i)DELETE\s+FROM',
            r'(?i)UPDATE\s+SET',
            r'(?i)INSERT\s+INTO',
            r'(?i)EXEC(?:UTE)?',
            r'(?i)SCRIPT',
            r'(?i)EVAL'
        ]
        
        for pattern in forbidden_patterns:
            if re.search(pattern, query):
                raise SecurityError(f"Forbidden pattern detected: {pattern}")
        
        # 3. Parameter injection check
        if re.search(r'[\'";]', query):
            # Allow only in quoted strings
            if not validate_quoted_strings(query):
                raise SecurityError("Potential injection attempt detected")
    
    @staticmethod
    def sanitize_graph_name(name: str) -> str:
        """Sanitize graph name to prevent path traversal"""
        # Remove dangerous characters
        clean_name = re.sub(r'[^\w\-_.]', '', name)
        
        # Prevent path traversal
        if '..' in clean_name or clean_name.startswith('/'):
            raise SecurityError("Invalid graph name")
        
        return clean_name
```

**API Key Security**
```python
class ApiKeyManager:
    """Secure API key management"""
    
    @staticmethod
    def generate_key() -> str:
        """Generate cryptographically secure API key"""
        import secrets
        import string
        
        # Use cryptographic random number generator
        chars = string.ascii_letters + string.digits
        key_body = ''.join(secrets.choice(chars) for _ in range(32))
        return f"rg_live_{key_body}"
    
    @staticmethod
    def hash_key(api_key: str, org_id: str) -> str:
        """Hash API key with organization-specific salt"""
        import hashlib
        import hmac
        
        # Use HMAC with organization-specific salt
        salt = f"rg_salt_{org_id}_{settings.SECRET_KEY}"
        return hmac.new(
            salt.encode(),
            api_key.encode(),
            hashlib.sha256
        ).hexdigest()
    
    @staticmethod
    def verify_key(api_key: str, stored_hash: str, org_id: str) -> bool:
        """Verify API key against stored hash"""
        computed_hash = ApiKeyManager.hash_key(api_key, org_id)
        return hmac.compare_digest(computed_hash, stored_hash)
```

**Request Authentication Pipeline**
```python
class AuthenticationMiddleware:
    """Multi-layer authentication and authorization"""
    
    def process_request(self, request):
        """Process authentication for each request"""
        
        # 1. Rate limiting check (before expensive operations)
        if not self.check_rate_limit(request):
            return self.rate_limit_response()
        
        # 2. API key extraction and validation
        auth_context = self.authenticate_api_key(request)
        
        # 3. Permission validation
        required_scope = self.get_required_scope(request)
        if not self.check_permissions(auth_context, required_scope):
            return self.insufficient_permissions_response()
        
        # 4. Organization-level access control
        if not self.check_organization_access(auth_context, request):
            return self.access_denied_response()
        
        # 5. Request signing validation (optional)
        if request.headers.get('X-Request-Signature'):
            if not self.verify_request_signature(request, auth_context):
                return self.invalid_signature_response()
        
        # 6. Audit logging
        self.log_access_attempt(auth_context, request)
        
        return auth_context
```

### Layer 3: Data Security

**Encryption at Rest**
```yaml
# Database encryption configuration
database:
  encryption:
    enabled: true
    algorithm: "AES-256-GCM"
    key_rotation: "quarterly"
    backup_encryption: true
  
  mongodb:
    encryption_at_rest: true
    field_level_encryption:
      - field: "api_keys.key_hash"
        algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
      - field: "organizations.billing_info"
        algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
```

**Data Access Controls**
```python
class DataAccessControl:
    """Organization-scoped data access"""
    
    @staticmethod
    def filter_query_results(results, org_id: str):
        """Ensure query results are scoped to organization"""
        filtered_results = []
        
        for row in results:
            # Verify each result belongs to the organization
            if DataAccessControl.verify_org_ownership(row, org_id):
                # Remove internal metadata
                cleaned_row = DataAccessControl.sanitize_result(row)
                filtered_results.append(cleaned_row)
        
        return filtered_results
    
    @staticmethod
    def create_xgt_connection(org_id: str):
        """Create organization-scoped XGT connection"""
        # Use organization-specific namespace
        namespace = f"org_{org_id}"
        
        connection = xgt.Connection(
            host=settings.XGT_HOST,
            port=settings.XGT_PORT,
            auth=xgt.BasicAuth(
                username=f"api_user_{org_id}",
                password=get_org_password(org_id)
            ),
            namespace=namespace
        )
        
        return connection
```

### Layer 4: Infrastructure Security

**Container Security**
```dockerfile
# Security-hardened Dockerfile
FROM python:3.11-slim-bullseye

# Create non-root user
RUN groupadd -r apiuser && useradd -r -g apiuser apiuser

# Install security updates only
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy application code
COPY --chown=apiuser:apiuser . /app
WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Drop privileges
USER apiuser

# Security configuration
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python health_check.py

EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "app:create_app()"]
```

**Kubernetes Security**
```yaml
# Security-focused Kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rocketgraph-public-api
spec:
  template:
    spec:
      serviceAccountName: rocketgraph-api-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
      containers:
      - name: api
        image: rocketgraph/public-api:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        resources:
          limits:
            cpu: "500m"
            memory: "512Mi"
          requests:
            cpu: "250m"
            memory: "256Mi"
        env:
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
        - name: var-log
          mountPath: /var/log
      volumes:
      - name: tmp-volume
        emptyDir: {}
      - name: var-log
        emptyDir: {}
```

## Rate Limiting & DDoS Protection

### Multi-Tier Rate Limiting

**Implementation Strategy**
```python
class RateLimiter:
    """Redis-based sliding window rate limiter"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def check_rate_limit(self, key: str, limit: int, window: int) -> bool:
        """Check if request is within rate limit"""
        current_time = time.time()
        pipeline = self.redis.pipeline()
        
        # Sliding window implementation
        pipeline.zremrangebyscore(key, 0, current_time - window)
        pipeline.zadd(key, {str(current_time): current_time})
        pipeline.zcard(key)
        pipeline.expire(key, window)
        
        results = pipeline.execute()
        request_count = results[2]
        
        return request_count <= limit

# Rate limiting configuration
RATE_LIMITS = {
    'default': {
        'requests_per_minute': 100,
        'requests_per_hour': 10000,
        'requests_per_day': 100000
    },
    'premium': {
        'requests_per_minute': 500,
        'requests_per_hour': 50000,
        'requests_per_day': 1000000
    },
    'enterprise': {
        'requests_per_minute': 1000,
        'requests_per_hour': 100000,
        'requests_per_day': 10000000
    }
}
```

**Adaptive Rate Limiting**
```python
class AdaptiveRateLimiter:
    """Rate limiter that adapts to system load"""
    
    def get_dynamic_limit(self, api_key: str, endpoint: str) -> int:
        """Calculate dynamic rate limit based on system conditions"""
        base_limit = self.get_base_limit(api_key, endpoint)
        
        # Adjust based on system metrics
        cpu_usage = self.get_cpu_usage()
        memory_usage = self.get_memory_usage()
        
        if cpu_usage > 80 or memory_usage > 80:
            # Reduce limits under high load
            return int(base_limit * 0.5)
        elif cpu_usage < 50 and memory_usage < 50:
            # Increase limits under low load
            return int(base_limit * 1.2)
        
        return base_limit
```

## Security Monitoring & Alerting

### Real-Time Threat Detection

**Anomaly Detection**
```python
class SecurityMonitor:
    """Real-time security monitoring and alerting"""
    
    def detect_anomalies(self, request_log):
        """Detect suspicious patterns in request logs"""
        
        alerts = []
        
        # 1. Rapid-fire requests from single IP
        if self.count_requests_by_ip(request_log.ip, 60) > 1000:
            alerts.append({
                'type': 'RAPID_REQUESTS',
                'severity': 'HIGH',
                'ip': request_log.ip,
                'details': 'Unusually high request rate'
            })
        
        # 2. Multiple failed authentication attempts
        if self.count_auth_failures(request_log.ip, 300) > 10:
            alerts.append({
                'type': 'BRUTE_FORCE',
                'severity': 'CRITICAL',
                'ip': request_log.ip,
                'details': 'Multiple authentication failures'
            })
        
        # 3. Unusual query patterns
        if self.detect_suspicious_queries(request_log.query):
            alerts.append({
                'type': 'SUSPICIOUS_QUERY',
                'severity': 'MEDIUM',
                'api_key': request_log.api_key_id,
                'details': 'Query contains suspicious patterns'
            })
        
        # 4. Geographic anomalies
        if self.detect_geo_anomaly(request_log.api_key_id, request_log.ip):
            alerts.append({
                'type': 'GEO_ANOMALY',
                'severity': 'MEDIUM',
                'details': 'Request from unusual geographic location'
            })
        
        return alerts
```

**Security Event Correlation**
```python
class SecurityEventCorrelator:
    """Correlate security events across multiple dimensions"""
    
    def correlate_events(self, timeframe_minutes=60):
        """Find related security events"""
        
        events = self.get_events(timeframe_minutes)
        correlations = []
        
        # Group events by various dimensions
        by_ip = self.group_by_ip(events)
        by_api_key = self.group_by_api_key(events)
        by_organization = self.group_by_organization(events)
        
        # Detect coordinated attacks
        for ip, ip_events in by_ip.items():
            if len(ip_events) > 100:  # High activity from single IP
                correlations.append({
                    'type': 'COORDINATED_ATTACK',
                    'source': ip,
                    'event_count': len(ip_events),
                    'severity': 'HIGH'
                })
        
        return correlations
```

### Incident Response

**Automated Response Actions**
```python
class IncidentResponse:
    """Automated security incident response"""
    
    def respond_to_threat(self, alert):
        """Take automated action based on threat level"""
        
        if alert['severity'] == 'CRITICAL':
            # Immediate blocking
            self.block_ip(alert['ip'])
            self.disable_api_key(alert.get('api_key'))
            self.notify_security_team(alert)
            
        elif alert['severity'] == 'HIGH':
            # Temporary rate limiting
            self.apply_rate_limit(alert['ip'], factor=0.1)
            self.flag_for_review(alert)
            
        elif alert['severity'] == 'MEDIUM':
            # Enhanced monitoring
            self.increase_monitoring(alert['source'])
            self.log_for_analysis(alert)
        
        # Always log the incident
        self.create_incident_record(alert)
```

## Compliance & Audit Requirements

### Audit Logging

**Comprehensive Audit Trail**
```python
class AuditLogger:
    """Comprehensive audit logging for compliance"""
    
    def log_api_access(self, request, response, auth_context):
        """Log all API access with required details"""
        
        audit_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'request_id': request.id,
            'organization_id': auth_context.organization_id,
            'api_key_id': auth_context.api_key.id,
            'api_key_name': auth_context.api_key.name,
            'user_agent': request.headers.get('User-Agent'),
            'ip_address': self.get_client_ip(request),
            'method': request.method,
            'endpoint': request.path,
            'query_parameters': dict(request.args),
            'request_size_bytes': len(request.data),
            'response_status': response.status_code,
            'response_size_bytes': len(response.data),
            'processing_time_ms': response.processing_time,
            'data_accessed': self.extract_data_references(request, response),
            'geo_location': self.get_geo_location(request.remote_addr),
            'compliance_flags': self.check_compliance_requirements(request)
        }
        
        # Store in tamper-evident audit log
        self.store_audit_record(audit_record)
        
        # Real-time streaming to SIEM
        self.stream_to_siem(audit_record)
```

**Data Access Tracking**
```python
def track_data_access(self, query_result, auth_context):
    """Track what data was accessed for compliance"""
    
    data_access_record = {
        'timestamp': datetime.utcnow().isoformat(),
        'organization_id': auth_context.organization_id,
        'api_key_id': auth_context.api_key.id,
        'graph_ids': self.extract_graph_ids(query_result),
        'record_count': len(query_result.rows),
        'data_types': self.identify_data_types(query_result),
        'pii_detected': self.scan_for_pii(query_result),
        'retention_policy': self.get_retention_policy(auth_context.organization_id)
    }
    
    # Store for compliance reporting
    self.compliance_db.data_access.insert_one(data_access_record)
```

### Privacy Protection

**PII Detection and Masking**
```python
class PrivacyProtection:
    """Detect and protect personally identifiable information"""
    
    PII_PATTERNS = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s?\d{3}-\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
    }
    
    def scan_for_pii(self, data):
        """Scan data for PII patterns"""
        pii_found = []
        
        for record in data:
            for field, value in record.items():
                if isinstance(value, str):
                    for pii_type, pattern in self.PII_PATTERNS.items():
                        if re.search(pattern, value):
                            pii_found.append({
                                'field': field,
                                'type': pii_type,
                                'confidence': 0.9
                            })
        
        return pii_found
    
    def mask_sensitive_data(self, data, masking_rules):
        """Apply masking rules to sensitive data"""
        masked_data = []
        
        for record in data:
            masked_record = {}
            for field, value in record.items():
                if field in masking_rules:
                    rule = masking_rules[field]
                    masked_record[field] = self.apply_masking(value, rule)
                else:
                    masked_record[field] = value
            masked_data.append(masked_record)
        
        return masked_data
```

## Security Best Practices

### For API Operators

1. **Key Management**
   - Rotate API keys regularly (90 days maximum)
   - Use hardware security modules (HSM) for production keys
   - Implement key escrow for compliance requirements

2. **Infrastructure Security**
   - Regular security updates and patches
   - Vulnerability scanning and penetration testing
   - Network segmentation and micro-segmentation

3. **Monitoring and Response**
   - 24/7 security monitoring
   - Automated threat response capabilities
   - Regular security incident drills

### For API Consumers

1. **Secure Integration**
   - Store API keys in secure vaults (not environment variables)
   - Use least-privilege principle for API key scopes
   - Implement client-side rate limiting

2. **Data Handling**
   - Encrypt data in transit and at rest
   - Implement proper data retention policies
   - Regular security audits of integrations

3. **Incident Preparedness**
   - Incident response procedures
   - Key rotation capabilities
   - Communication channels with API provider

This comprehensive security framework ensures that the RocketGraph Public API meets enterprise-grade security requirements while maintaining usability and performance.