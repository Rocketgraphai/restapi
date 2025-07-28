# Monitoring & Auditing

## Overview

Comprehensive monitoring and auditing are essential for maintaining the security, performance, and compliance of the RocketGraph Public API. This document outlines the monitoring strategy, audit requirements, and implementation details.

## Monitoring Architecture

### Three-Tier Monitoring Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                    Tier 1: Infrastructure                   │
│              (Kubernetes, Network, Hardware)                │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                 Tier 2: Application                         │
│            (API Performance, Business Metrics)              │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                  Tier 3: Security                           │
│             (Audit Logs, Threat Detection)                  │
└─────────────────────────────────────────────────────────────┘
```

### Monitoring Stack Components

**Metrics Collection:**
- **Prometheus**: Time-series metrics collection
- **StatsD**: Application metrics aggregation
- **OpenTelemetry**: Distributed tracing

**Log Management:**
- **Elasticsearch**: Log storage and indexing
- **Logstash**: Log processing and enrichment
- **Fluentd**: Log forwarding and aggregation

**Visualization & Alerting:**
- **Grafana**: Metrics visualization and dashboards
- **Kibana**: Log analysis and visualization
- **PagerDuty**: Incident management and alerting

**Security Monitoring:**
- **SIEM Integration**: Splunk, QRadar, or ELK Security
- **Threat Detection**: Custom rules and ML-based detection
- **Compliance Reporting**: Automated compliance dashboards

## Application Monitoring

### Key Performance Indicators (KPIs)

```python
# metrics.py
from prometheus_client import Counter, Histogram, Gauge, Summary
import time
from functools import wraps

# Request metrics
REQUEST_COUNT = Counter(
    'rg_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code', 'organization_id']
)

REQUEST_DURATION = Histogram(
    'rg_http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint'],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
)

REQUEST_SIZE = Histogram(
    'rg_http_request_size_bytes',
    'HTTP request size',
    ['method', 'endpoint']
)

RESPONSE_SIZE = Histogram(
    'rg_http_response_size_bytes',
    'HTTP response size',
    ['method', 'endpoint']
)

# Business metrics
ACTIVE_API_KEYS = Gauge(
    'rg_active_api_keys_total',
    'Number of active API keys',
    ['plan_type']
)

QUERY_EXECUTION_TIME = Histogram(
    'rg_query_execution_duration_seconds',
    'Graph query execution time',
    ['graph_id', 'query_complexity'],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0)
)

QUERY_RESULT_SIZE = Histogram(
    'rg_query_result_size_rows',
    'Number of rows in query results',
    ['graph_id'],
    buckets=(1, 10, 100, 1000, 10000, 100000, 1000000)
)

ACTIVE_QUERIES = Gauge(
    'rg_active_queries_current',
    'Number of currently executing queries'
)

# Error metrics
ERROR_RATE = Counter(
    'rg_errors_total',
    'Total errors by type',
    ['error_type', 'endpoint', 'organization_id']
)

# Rate limiting metrics
RATE_LIMIT_HITS = Counter(
    'rg_rate_limit_violations_total',
    'Rate limit violations',
    ['api_key_id', 'limit_type', 'organization_id']
)

# Security metrics
AUTHENTICATION_ATTEMPTS = Counter(
    'rg_auth_attempts_total',
    'Authentication attempts',
    ['result', 'auth_type']
)

SUSPICIOUS_ACTIVITY = Counter(
    'rg_suspicious_activity_total',
    'Suspicious activity detected',
    ['activity_type', 'severity']
)

def monitor_endpoint(f):
    """Decorator to automatically monitor endpoint performance"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        method = request.method
        endpoint = request.endpoint or 'unknown'
        
        try:
            # Execute the function
            response = f(*args, **kwargs)
            
            # Record successful request
            status_code = getattr(response, 'status_code', 200)
            org_id = getattr(g, 'organization_id', 'unknown')
            
            REQUEST_COUNT.labels(
                method=method,
                endpoint=endpoint,
                status_code=status_code,
                organization_id=org_id
            ).inc()
            
            return response
            
        except Exception as e:
            # Record error
            ERROR_RATE.labels(
                error_type=type(e).__name__,
                endpoint=endpoint,
                organization_id=getattr(g, 'organization_id', 'unknown')
            ).inc()
            raise
            
        finally:
            # Record duration
            duration = time.time() - start_time
            REQUEST_DURATION.labels(
                method=method,
                endpoint=endpoint
            ).observe(duration)
    
    return decorated_function

class MetricsCollector:
    """Centralized metrics collection"""
    
    def __init__(self):
        self.start_time = time.time()
    
    def record_query_execution(self, graph_id: str, execution_time: float, 
                             result_count: int, complexity: str):
        """Record query execution metrics"""
        QUERY_EXECUTION_TIME.labels(
            graph_id=graph_id,
            query_complexity=complexity
        ).observe(execution_time)
        
        QUERY_RESULT_SIZE.labels(
            graph_id=graph_id
        ).observe(result_count)
    
    def record_authentication(self, success: bool, auth_type: str):
        """Record authentication attempt"""
        result = 'success' if success else 'failure'
        AUTHENTICATION_ATTEMPTS.labels(
            result=result,
            auth_type=auth_type
        ).inc()
    
    def record_suspicious_activity(self, activity_type: str, severity: str):
        """Record suspicious activity detection"""
        SUSPICIOUS_ACTIVITY.labels(
            activity_type=activity_type,
            severity=severity
        ).inc()
    
    def update_active_api_keys(self):
        """Update active API keys gauge"""
        # Query database for active API keys by plan
        plans = ['free', 'basic', 'premium', 'enterprise']
        for plan in plans:
            count = self.get_active_api_keys_count(plan)
            ACTIVE_API_KEYS.labels(plan_type=plan).set(count)
    
    def get_system_uptime(self) -> float:
        """Get system uptime in seconds"""
        return time.time() - self.start_time
```

### Custom Business Metrics

```python
# business_metrics.py
class BusinessMetricsCollector:
    """Collect business-specific metrics"""
    
    def __init__(self, mongodb_client):
        self.db = mongodb_client
    
    def collect_daily_metrics(self):
        """Collect daily business metrics"""
        today = datetime.utcnow().date()
        
        metrics = {
            'daily_api_requests': self.get_daily_requests(today),
            'daily_new_organizations': self.get_new_organizations(today),
            'daily_query_executions': self.get_daily_queries(today),
            'daily_data_uploaded_gb': self.get_daily_data_upload(today),
            'daily_revenue': self.calculate_daily_revenue(today),
            'active_organizations': self.get_active_organizations(),
            'average_query_time': self.get_average_query_time(today),
            'error_rate_percentage': self.get_error_rate(today)
        }
        
        # Send to monitoring system
        for metric_name, value in metrics.items():
            BUSINESS_METRICS.labels(metric=metric_name).set(value)
        
        return metrics
    
    def get_daily_requests(self, date) -> int:
        """Get total API requests for a specific date"""
        start_of_day = datetime.combine(date, datetime.min.time())
        end_of_day = start_of_day + timedelta(days=1)
        
        return self.db.audit_logs.count_documents({
            'timestamp': {'$gte': start_of_day, '$lt': end_of_day}
        })
    
    def get_query_performance_metrics(self) -> Dict:
        """Get query performance metrics"""
        pipeline = [
            {
                '$match': {
                    'timestamp': {
                        '$gte': datetime.utcnow() - timedelta(hours=1)
                    },
                    'event_type': 'query_execution'
                }
            },
            {
                '$group': {
                    '_id': None,
                    'avg_execution_time': {'$avg': '$execution_time_ms'},
                    'max_execution_time': {'$max': '$execution_time_ms'},
                    'total_queries': {'$sum': 1},
                    'avg_result_size': {'$avg': '$result_count'}
                }
            }
        ]
        
        result = list(self.db.query_metrics.aggregate(pipeline))
        return result[0] if result else {}

BUSINESS_METRICS = Gauge(
    'rg_business_metrics',
    'Business metrics',
    ['metric']
)
```

## Distributed Tracing

### OpenTelemetry Implementation

```python
# tracing.py
from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.pymongo import PymongoInstrumentor

def configure_tracing():
    """Configure distributed tracing"""
    
    # Set up tracer provider
    trace.set_tracer_provider(TracerProvider())
    tracer = trace.get_tracer(__name__)
    
    # Configure Jaeger exporter
    jaeger_exporter = JaegerExporter(
        agent_host_name="jaeger-agent",
        agent_port=6831,
    )
    
    # Add span processor
    span_processor = BatchSpanProcessor(jaeger_exporter)
    trace.get_tracer_provider().add_span_processor(span_processor)
    
    # Auto-instrument libraries
    FlaskInstrumentor().instrument()
    RequestsInstrumentor().instrument()
    PymongoInstrumentor().instrument()

class TracingMiddleware:
    """Custom tracing middleware for API-specific spans"""
    
    def __init__(self, app):
        self.app = app
        self.tracer = trace.get_tracer(__name__)
    
    def trace_request(self, request):
        """Create custom spans for API requests"""
        
        with self.tracer.start_as_current_span("api_request") as span:
            # Add request attributes
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.url", request.url)
            span.set_attribute("http.scheme", request.scheme)
            span.set_attribute("http.host", request.host)
            
            # Add API-specific attributes
            if hasattr(g, 'organization_id'):
                span.set_attribute("rg.organization_id", g.organization_id)
            if hasattr(g, 'api_key_id'):
                span.set_attribute("rg.api_key_id", g.api_key_id)
    
    def trace_query_execution(self, query: str, graph_id: str):
        """Trace graph query execution"""
        
        with self.tracer.start_as_current_span("query_execution") as span:
            span.set_attribute("rg.query.graph_id", graph_id)
            span.set_attribute("rg.query.length", len(query))
            span.set_attribute("rg.query.hash", hashlib.md5(query.encode()).hexdigest())
            
            # Add query complexity analysis
            complexity = self.analyze_query_complexity(query)
            span.set_attribute("rg.query.complexity", complexity)
    
    def trace_database_operation(self, operation: str, collection: str):
        """Trace database operations"""
        
        with self.tracer.start_as_current_span("database_operation") as span:
            span.set_attribute("db.operation", operation)
            span.set_attribute("db.collection.name", collection)
            span.set_attribute("db.system", "mongodb")
```

## Audit Logging

### Comprehensive Audit Trail

```python
# audit_logging.py
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class AuditEventType(Enum):
    API_REQUEST = "api_request"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_EVENT = "security_event"
    SYSTEM_EVENT = "system_event"

class AuditEventSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class AuditEvent:
    """Structured audit event"""
    event_id: str
    timestamp: datetime
    event_type: AuditEventType
    severity: AuditEventSeverity
    source_ip: str
    user_agent: str
    organization_id: Optional[str]
    api_key_id: Optional[str]
    endpoint: str
    method: str
    status_code: int
    request_id: str
    processing_time_ms: float
    data_accessed: Optional[Dict[str, Any]]
    error_details: Optional[str]
    compliance_tags: List[str]
    geographic_location: Optional[Dict[str, str]]

class AuditLogger:
    """Comprehensive audit logging system"""
    
    def __init__(self, mongodb_client, elasticsearch_client=None):
        self.mongodb = mongodb_client
        self.elasticsearch = elasticsearch_client
        self.audit_collection = mongodb_client.audit_logs
        
        # Create indexes for efficient querying
        self.create_audit_indexes()
    
    def create_audit_indexes(self):
        """Create indexes for audit log collection"""
        indexes = [
            [("timestamp", -1)],
            [("organization_id", 1), ("timestamp", -1)],
            [("api_key_id", 1), ("timestamp", -1)],
            [("event_type", 1), ("timestamp", -1)],
            [("severity", 1), ("timestamp", -1)],
            [("source_ip", 1), ("timestamp", -1)],
            [("compliance_tags", 1), ("timestamp", -1)]
        ]
        
        for index in indexes:
            self.audit_collection.create_index(index)
    
    def log_api_request(self, request, response, auth_context=None, processing_time=0):
        """Log API request with comprehensive details"""
        
        event = AuditEvent(
            event_id=self.generate_event_id(),
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.API_REQUEST,
            severity=self.determine_severity(response.status_code),
            source_ip=self.get_client_ip(request),
            user_agent=request.headers.get('User-Agent', ''),
            organization_id=auth_context.organization_id if auth_context else None,
            api_key_id=auth_context.api_key_id if auth_context else None,
            endpoint=request.path,
            method=request.method,
            status_code=response.status_code,
            request_id=getattr(request, 'id', ''),
            processing_time_ms=processing_time,
            data_accessed=self.extract_data_references(request, response),
            error_details=self.extract_error_details(response),
            compliance_tags=self.generate_compliance_tags(request, auth_context),
            geographic_location=self.get_geographic_location(request)
        )
        
        self.store_audit_event(event)
    
    def log_authentication_event(self, api_key: str, success: bool, 
                                failure_reason: str = None, request=None):
        """Log authentication attempts"""
        
        event = AuditEvent(
            event_id=self.generate_event_id(),
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.AUTHENTICATION,
            severity=AuditEventSeverity.WARNING if not success else AuditEventSeverity.INFO,
            source_ip=self.get_client_ip(request) if request else 'unknown',
            user_agent=request.headers.get('User-Agent', '') if request else '',
            organization_id=None,  # Not available during auth
            api_key_id=self.hash_api_key(api_key) if api_key else None,
            endpoint='/authentication',
            method='POST',
            status_code=200 if success else 401,
            request_id=getattr(request, 'id', '') if request else '',
            processing_time_ms=0,
            data_accessed=None,
            error_details=failure_reason,
            compliance_tags=['authentication', 'security'],
            geographic_location=self.get_geographic_location(request) if request else None
        )
        
        self.store_audit_event(event)
    
    def log_data_access(self, graph_ids: List[str], query: str, 
                       result_count: int, auth_context, pii_detected: bool = False):
        """Log data access events for compliance"""
        
        compliance_tags = ['data_access']
        if pii_detected:
            compliance_tags.extend(['pii', 'gdpr', 'ccpa'])
        
        data_accessed = {
            'graph_ids': graph_ids,
            'query_hash': hashlib.sha256(query.encode()).hexdigest(),
            'result_count': result_count,
            'pii_detected': pii_detected,
            'data_classification': self.classify_graphs(graph_ids)
        }
        
        event = AuditEvent(
            event_id=self.generate_event_id(),
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.DATA_ACCESS,
            severity=AuditEventSeverity.WARNING if pii_detected else AuditEventSeverity.INFO,
            source_ip=self.get_client_ip(request),
            user_agent=request.headers.get('User-Agent', ''),
            organization_id=auth_context.organization_id,
            api_key_id=auth_context.api_key_id,
            endpoint=request.path,
            method=request.method,
            status_code=200,
            request_id=getattr(request, 'id', ''),
            processing_time_ms=0,
            data_accessed=data_accessed,
            error_details=None,
            compliance_tags=compliance_tags,
            geographic_location=self.get_geographic_location(request)
        )
        
        self.store_audit_event(event)
    
    def log_security_event(self, event_type: str, severity: AuditEventSeverity,
                          details: Dict[str, Any], request=None):
        """Log security events"""
        
        event = AuditEvent(
            event_id=self.generate_event_id(),
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.SECURITY_EVENT,
            severity=severity,
            source_ip=self.get_client_ip(request) if request else 'system',
            user_agent=request.headers.get('User-Agent', '') if request else 'system',
            organization_id=details.get('organization_id'),
            api_key_id=details.get('api_key_id'),
            endpoint=request.path if request else '/security',
            method=request.method if request else 'SYSTEM',
            status_code=details.get('status_code', 0),
            request_id=getattr(request, 'id', '') if request else '',
            processing_time_ms=0,
            data_accessed=details.get('data_accessed'),
            error_details=details.get('description'),
            compliance_tags=['security', event_type],
            geographic_location=self.get_geographic_location(request) if request else None
        )
        
        self.store_audit_event(event)
    
    def store_audit_event(self, event: AuditEvent):
        """Store audit event in multiple systems"""
        
        # Convert to dictionary
        event_dict = asdict(event)
        
        # Convert enum values to strings
        event_dict['event_type'] = event.event_type.value
        event_dict['severity'] = event.severity.value
        
        # Store in MongoDB (primary audit store)
        self.audit_collection.insert_one(event_dict)
        
        # Store in Elasticsearch for search and analytics
        if self.elasticsearch:
            self.elasticsearch.index(
                index=f"audit-logs-{datetime.now().strftime('%Y-%m')}",
                body=event_dict
            )
        
        # Stream to SIEM if configured
        self.stream_to_siem(event_dict)
        
        # Real-time alerting for critical events
        if event.severity == AuditEventSeverity.CRITICAL:
            self.trigger_security_alert(event_dict)
    
    def generate_compliance_tags(self, request, auth_context) -> List[str]:
        """Generate compliance tags based on request context"""
        tags = []
        
        # Geographic compliance
        country = self.get_country_from_request(request)
        if country in ['US', 'CA']:
            tags.append('ccpa')
        if country in EU_COUNTRIES:
            tags.append('gdpr')
        
        # Industry compliance
        if auth_context and hasattr(auth_context, 'industry'):
            if auth_context.industry == 'healthcare':
                tags.append('hipaa')
            elif auth_context.industry == 'finance':
                tags.append('pci_dss')
        
        # Data sensitivity
        if 'query' in request.path:
            tags.append('data_access')
        if 'upload' in request.path:
            tags.append('data_modification')
        
        return tags
    
    def search_audit_logs(self, filters: Dict[str, Any], 
                         start_date: datetime, end_date: datetime) -> List[Dict]:
        """Search audit logs with filters"""
        
        query = {
            'timestamp': {
                '$gte': start_date,
                '$lte': end_date
            }
        }
        
        # Add filters
        for key, value in filters.items():
            if key in ['organization_id', 'api_key_id', 'event_type', 'severity']:
                query[key] = value
            elif key == 'source_ip':
                query['source_ip'] = {'$regex': value}
            elif key == 'compliance_tags':
                query['compliance_tags'] = {'$in': value if isinstance(value, list) else [value]}
        
        # Execute query with pagination
        cursor = self.audit_collection.find(query).sort('timestamp', -1)
        return list(cursor)

# Usage example
audit_logger = AuditLogger(mongodb_client, elasticsearch_client)

@app.before_request
def before_request():
    g.request_start_time = time.time()
    g.request_id = str(uuid.uuid4())

@app.after_request
def after_request(response):
    processing_time = (time.time() - g.request_start_time) * 1000
    
    # Log the request
    audit_logger.log_api_request(
        request=request,
        response=response,
        auth_context=getattr(g, 'auth_context', None),
        processing_time=processing_time
    )
    
    return response
```

## Security Monitoring

### Threat Detection System

```python
# threat_detection.py
from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
import re

@dataclass
class ThreatIndicator:
    indicator_type: str
    severity: str
    confidence: float
    description: str
    evidence: Dict[str, Any]
    mitigations: List[str]

class ThreatDetectionEngine:
    """Real-time threat detection and response"""
    
    def __init__(self, audit_logger: AuditLogger, redis_client):
        self.audit_logger = audit_logger
        self.redis = redis_client
        self.detection_rules = self.load_detection_rules()
    
    def analyze_request(self, request, auth_context) -> List[ThreatIndicator]:
        """Analyze incoming request for threats"""
        threats = []
        
        # Rate-based anomaly detection
        threats.extend(self.detect_rate_anomalies(request, auth_context))
        
        # Pattern-based detection
        threats.extend(self.detect_suspicious_patterns(request))
        
        # Geographic anomalies
        threats.extend(self.detect_geographic_anomalies(request, auth_context))
        
        # Behavioral analysis
        threats.extend(self.detect_behavioral_anomalies(request, auth_context))
        
        return threats
    
    def detect_rate_anomalies(self, request, auth_context) -> List[ThreatIndicator]:
        """Detect unusual request rate patterns"""
        threats = []
        
        if not auth_context:
            return threats
        
        api_key_id = auth_context.api_key_id
        current_time = time.time()
        
        # Check for burst patterns
        burst_key = f"burst_detection:{api_key_id}"
        request_times = self.redis.zrangebyscore(
            burst_key, current_time - 60, current_time
        )
        
        if len(request_times) > 100:  # 100 requests in 1 minute
            threats.append(ThreatIndicator(
                indicator_type="RATE_BURST",
                severity="HIGH",
                confidence=0.9,
                description=f"Unusual burst pattern detected: {len(request_times)} requests in 60 seconds",
                evidence={
                    "api_key_id": api_key_id,
                    "request_count": len(request_times),
                    "time_window": 60
                },
                mitigations=["rate_limit_reduction", "temporary_suspension"]
            ))
        
        return threats
    
    def detect_suspicious_patterns(self, request) -> List[ThreatIndicator]:
        """Detect suspicious request patterns"""
        threats = []
        
        # SQL injection patterns in query parameters
        sql_injection_patterns = [
            r"(?i)(union|select|insert|update|delete|drop)\s+",
            r"(?i)(\s|^)(or|and)\s+\d+\s*=\s*\d+",
            r"(?i)'.*?'",
            r"(?i);.*?--",
            r"(?i)/\*.*?\*/"
        ]
        
        query_string = str(request.args) + str(request.get_json() or {})
        
        for pattern in sql_injection_patterns:
            if re.search(pattern, query_string):
                threats.append(ThreatIndicator(
                    indicator_type="SQL_INJECTION_ATTEMPT",
                    severity="CRITICAL",
                    confidence=0.8,
                    description=f"SQL injection pattern detected: {pattern}",
                    evidence={
                        "pattern": pattern,
                        "query_string": query_string[:500],  # Truncate for security
                        "endpoint": request.path
                    },
                    mitigations=["block_request", "alert_security_team"]
                ))
        
        # XSS patterns
        xss_patterns = [
            r"(?i)<script.*?>.*?</script>",
            r"(?i)javascript:",
            r"(?i)on\w+\s*=",
            r"(?i)<iframe.*?>",
            r"(?i)eval\s*\("
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, query_string):
                threats.append(ThreatIndicator(
                    indicator_type="XSS_ATTEMPT",
                    severity="HIGH",
                    confidence=0.7,
                    description=f"XSS pattern detected: {pattern}",
                    evidence={
                        "pattern": pattern,
                        "query_string": query_string[:500],
                        "endpoint": request.path
                    },
                    mitigations=["sanitize_input", "block_request"]
                ))
        
        return threats
    
    def detect_geographic_anomalies(self, request, auth_context) -> List[ThreatIndicator]:
        """Detect unusual geographic access patterns"""
        threats = []
        
        if not auth_context:
            return threats
        
        current_location = self.get_geographic_location(request)
        if not current_location:
            return threats
        
        api_key_id = auth_context.api_key_id
        
        # Get recent access locations
        recent_locations = self.get_recent_access_locations(api_key_id, days=7)
        
        if recent_locations and self.is_geographic_anomaly(current_location, recent_locations):
            threats.append(ThreatIndicator(
                indicator_type="GEOGRAPHIC_ANOMALY",
                severity="MEDIUM",
                confidence=0.6,
                description=f"Access from unusual location: {current_location['country']}",
                evidence={
                    "current_location": current_location,
                    "recent_locations": recent_locations,
                    "api_key_id": api_key_id
                },
                mitigations=["additional_verification", "notification"]
            ))
        
        return threats
    
    def detect_behavioral_anomalies(self, request, auth_context) -> List[ThreatIndicator]:
        """Detect anomalous user behavior"""
        threats = []
        
        if not auth_context:
            return threats
        
        api_key_id = auth_context.api_key_id
        
        # Analyze request patterns
        patterns = self.analyze_request_patterns(api_key_id)
        
        # Unusual time-of-day access
        current_hour = datetime.now().hour
        typical_hours = patterns.get('typical_access_hours', [])
        
        if typical_hours and current_hour not in typical_hours:
            if len(typical_hours) >= 5:  # Sufficient data for pattern
                threats.append(ThreatIndicator(
                    indicator_type="UNUSUAL_ACCESS_TIME",
                    severity="LOW",
                    confidence=0.4,
                    description=f"Access outside typical hours: {current_hour}:00",
                    evidence={
                        "current_hour": current_hour,
                        "typical_hours": typical_hours,
                        "api_key_id": api_key_id
                    },
                    mitigations=["monitoring_increase", "notification"]
                ))
        
        # Unusual endpoint access
        endpoint = request.path
        typical_endpoints = patterns.get('typical_endpoints', [])
        
        if typical_endpoints and endpoint not in typical_endpoints:
            threats.append(ThreatIndicator(
                indicator_type="UNUSUAL_ENDPOINT_ACCESS",
                severity="LOW",
                confidence=0.3,
                description=f"Access to unusual endpoint: {endpoint}",
                evidence={
                    "endpoint": endpoint,
                    "typical_endpoints": typical_endpoints,
                    "api_key_id": api_key_id
                },
                mitigations=["monitoring_increase"]
            ))
        
        return threats
    
    def respond_to_threats(self, threats: List[ThreatIndicator], request, auth_context):
        """Automatically respond to detected threats"""
        
        for threat in threats:
            # Log security event
            self.audit_logger.log_security_event(
                event_type=threat.indicator_type,
                severity=AuditEventSeverity.CRITICAL if threat.severity == "CRITICAL" else AuditEventSeverity.WARNING,
                details={
                    'description': threat.description,
                    'confidence': threat.confidence,
                    'evidence': threat.evidence,
                    'mitigations': threat.mitigations,
                    'organization_id': auth_context.organization_id if auth_context else None,
                    'api_key_id': auth_context.api_key_id if auth_context else None
                },
                request=request
            )
            
            # Execute mitigations
            for mitigation in threat.mitigations:
                self.execute_mitigation(mitigation, threat, request, auth_context)
    
    def execute_mitigation(self, mitigation: str, threat: ThreatIndicator, 
                          request, auth_context):
        """Execute specific mitigation actions"""
        
        if mitigation == "block_request":
            # Block the current request
            abort(403, description="Request blocked due to security concerns")
        
        elif mitigation == "rate_limit_reduction":
            # Temporarily reduce rate limits
            if auth_context:
                self.temporarily_reduce_rate_limits(auth_context.api_key_id)
        
        elif mitigation == "temporary_suspension":
            # Temporarily suspend API key
            if auth_context:
                self.temporarily_suspend_api_key(auth_context.api_key_id, duration=3600)
        
        elif mitigation == "alert_security_team":
            # Send immediate alert to security team
            self.send_security_alert(threat)
        
        elif mitigation == "additional_verification":
            # Require additional verification
            self.require_additional_verification(auth_context.api_key_id if auth_context else None)
```

## Alerting and Incident Response

### Alert Configuration

```yaml
# alerting_rules.yml
groups:
- name: api_performance
  rules:
  - alert: HighErrorRate
    expr: rate(rg_errors_total[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
      team: platform
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value }} errors per second"
      runbook_url: "https://runbooks.company.com/high-error-rate"
  
  - alert: SlowResponseTime
    expr: histogram_quantile(0.95, rate(rg_http_request_duration_seconds_bucket[5m])) > 2
    for: 5m
    labels:
      severity: warning
      team: platform
    annotations:
      summary: "Slow API response times"
      description: "95th percentile response time is {{ $value }}s"

- name: security_alerts
  rules:
  - alert: SuspiciousActivity
    expr: rate(rg_suspicious_activity_total[1m]) > 0
    for: 0s
    labels:
      severity: critical
      team: security
    annotations:
      summary: "Suspicious activity detected"
      description: "{{ $value }} suspicious activities per second"
      
  - alert: AuthenticationFailures
    expr: rate(rg_auth_attempts_total{result="failure"}[5m]) > 10
    for: 1m
    labels:
      severity: warning
      team: security
    annotations:
      summary: "High authentication failure rate"
      description: "{{ $value }} authentication failures per second"

- name: business_metrics
  rules:
  - alert: LowAPIUsage
    expr: rate(rg_http_requests_total[1h]) < 10
    for: 30m
    labels:
      severity: info
      team: business
    annotations:
      summary: "Low API usage detected"
      description: "API usage is {{ $value }} requests per second"
```

### Incident Response Automation

```python
# incident_response.py
class IncidentResponseManager:
    """Automated incident response system"""
    
    def __init__(self, pagerduty_client, slack_client):
        self.pagerduty = pagerduty_client
        self.slack = slack_client
        self.response_playbooks = self.load_playbooks()
    
    def handle_alert(self, alert: Dict[str, Any]):
        """Handle incoming alert and execute response"""
        
        severity = alert['labels']['severity']
        alert_name = alert['labels']['alertname']
        team = alert['labels'].get('team', 'platform')
        
        # Create incident
        incident = self.create_incident(alert)
        
        # Execute appropriate response
        if severity == 'critical':
            self.execute_critical_response(incident, alert)
        elif severity == 'warning':
            self.execute_warning_response(incident, alert)
        else:
            self.execute_info_response(incident, alert)
        
        # Notify stakeholders
        self.notify_stakeholders(incident, alert, team)
    
    def execute_critical_response(self, incident, alert):
        """Execute critical incident response"""
        
        # Page on-call engineer
        self.pagerduty.create_incident({
            'incident': {
                'type': 'incident',
                'title': f"CRITICAL: {alert['labels']['alertname']}",
                'service': {'id': 'API_SERVICE_ID', 'type': 'service_reference'},
                'urgency': 'high',
                'body': {
                    'type': 'incident_body',
                    'details': alert['annotations']['description']
                }
            }
        })
        
        # Execute automated mitigations
        if 'DDoS' in alert['labels']['alertname']:
            self.enable_ddos_protection()
        elif 'DatabaseDown' in alert['labels']['alertname']:
            self.failover_database()
        elif 'HighErrorRate' in alert['labels']['alertname']:
            self.scale_up_instances()
    
    def create_incident_dashboard(self, incident_id: str) -> str:
        """Create real-time incident dashboard"""
        
        dashboard_config = {
            "dashboard": {
                "title": f"Incident {incident_id} - Live Monitoring",
                "tags": ["incident", incident_id],
                "timezone": "UTC",
                "panels": [
                    {
                        "title": "Error Rate",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(rg_errors_total[1m])",
                                "legendFormat": "Errors/sec"
                            }
                        ]
                    },
                    {
                        "title": "Response Time",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "histogram_quantile(0.95, rate(rg_http_request_duration_seconds_bucket[5m]))",
                                "legendFormat": "95th percentile"
                            }
                        ]
                    },
                    {
                        "title": "Active Queries",
                        "type": "singlestat",
                        "targets": [
                            {
                                "expr": "rg_active_queries_current",
                                "legendFormat": "Active Queries"
                            }
                        ]
                    }
                ]
            }
        }
        
        # Create dashboard in Grafana
        dashboard_url = self.create_grafana_dashboard(dashboard_config)
        return dashboard_url
```

This comprehensive monitoring and auditing system provides enterprise-grade observability, security monitoring, and compliance capabilities for the RocketGraph Public API.