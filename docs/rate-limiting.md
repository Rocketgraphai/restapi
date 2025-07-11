# Rate Limiting Strategy

## Overview

Rate limiting is a critical component of the RocketGraph Public API security and performance strategy, protecting against abuse while ensuring fair resource allocation across all users.

## Multi-Tier Rate Limiting Architecture

### Tier 1: Network Level (WAF/Load Balancer)

**First line of defense against DDoS and abuse:**

```yaml
# AWS WAF Rate Limiting Rules
waf_rules:
  global_rate_limit:
    requests_per_5_minutes: 10000
    block_duration: 300  # 5 minutes
    
  ip_based_limits:
    requests_per_minute: 1000
    burst_capacity: 200
    
  geographic_restrictions:
    blocked_countries: ["CN", "RU"]  # Example
    
  suspicious_patterns:
    rapid_requests: 100_per_10_seconds
    user_agent_blocking: ["curl", "wget", "bot"]
```

**CloudFlare Configuration:**
```javascript
// cloudflare-worker.js
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const ip = request.headers.get('CF-Connecting-IP')
  const country = request.cf.country
  
  // Country-based blocking
  if (['CN', 'RU'].includes(country)) {
    return new Response('Access denied', { status: 403 })
  }
  
  // Rate limiting by IP
  const rateLimitKey = `rate_limit:${ip}`
  const count = await RATE_LIMIT_KV.get(rateLimitKey)
  
  if (count && parseInt(count) > 1000) {
    return new Response('Rate limit exceeded', { status: 429 })
  }
  
  // Increment counter
  await RATE_LIMIT_KV.put(rateLimitKey, (parseInt(count) || 0) + 1, {
    expirationTtl: 60  // 1 minute window
  })
  
  return fetch(request)
}
```

### Tier 2: Application Level (API Gateway)

**Sophisticated rate limiting with business logic:**

```python
# rate_limiter.py
import redis
import time
import json
from typing import Dict, Optional
from enum import Enum

class RateLimitType(Enum):
    REQUESTS_PER_MINUTE = "requests_per_minute"
    REQUESTS_PER_HOUR = "requests_per_hour"
    REQUESTS_PER_DAY = "requests_per_day"
    QUERY_EXECUTIONS_PER_HOUR = "query_executions_per_hour"
    DATA_UPLOAD_PER_DAY = "data_upload_per_day"

class RateLimiter:
    """Redis-based sliding window rate limiter"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
    
    def is_allowed(self, key: str, limit: int, window_seconds: int) -> tuple[bool, Dict]:
        """
        Check if request is within rate limit using sliding window
        Returns: (is_allowed, rate_limit_info)
        """
        current_time = time.time()
        pipeline = self.redis.pipeline()
        
        # Remove expired entries
        pipeline.zremrangebyscore(key, 0, current_time - window_seconds)
        
        # Count current requests
        pipeline.zcard(key)
        
        # Add current request
        pipeline.zadd(key, {str(current_time): current_time})
        
        # Set expiration
        pipeline.expire(key, window_seconds)
        
        results = pipeline.execute()
        current_count = results[1]
        
        # Calculate rate limit info
        reset_time = current_time + window_seconds
        remaining = max(0, limit - current_count)
        
        rate_limit_info = {
            'limit': limit,
            'remaining': remaining,
            'reset_time': reset_time,
            'window_seconds': window_seconds,
            'current_count': current_count
        }
        
        return current_count <= limit, rate_limit_info
    
    def get_rate_limit_key(self, identifier: str, limit_type: RateLimitType) -> str:
        """Generate rate limit key for Redis"""
        return f"rate_limit:{identifier}:{limit_type.value}"

class ApiRateLimiter:
    """API-specific rate limiting logic"""
    
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.rate_limits = self._load_rate_limits()
    
    def _load_rate_limits(self) -> Dict:
        """Load rate limits from configuration"""
        return {
            'free': {
                RateLimitType.REQUESTS_PER_MINUTE: 100,
                RateLimitType.REQUESTS_PER_HOUR: 1000,
                RateLimitType.REQUESTS_PER_DAY: 10000,
                RateLimitType.QUERY_EXECUTIONS_PER_HOUR: 100,
                RateLimitType.DATA_UPLOAD_PER_DAY: 1024 * 1024 * 100  # 100MB
            },
            'basic': {
                RateLimitType.REQUESTS_PER_MINUTE: 500,
                RateLimitType.REQUESTS_PER_HOUR: 10000,
                RateLimitType.REQUESTS_PER_DAY: 100000,
                RateLimitType.QUERY_EXECUTIONS_PER_HOUR: 1000,
                RateLimitType.DATA_UPLOAD_PER_DAY: 1024 * 1024 * 1024  # 1GB
            },
            'premium': {
                RateLimitType.REQUESTS_PER_MINUTE: 1000,
                RateLimitType.REQUESTS_PER_HOUR: 50000,
                RateLimitType.REQUESTS_PER_DAY: 1000000,
                RateLimitType.QUERY_EXECUTIONS_PER_HOUR: 10000,
                RateLimitType.DATA_UPLOAD_PER_DAY: 1024 * 1024 * 1024 * 10  # 10GB
            },
            'enterprise': {
                RateLimitType.REQUESTS_PER_MINUTE: 5000,
                RateLimitType.REQUESTS_PER_HOUR: 200000,
                RateLimitType.REQUESTS_PER_DAY: 10000000,
                RateLimitType.QUERY_EXECUTIONS_PER_HOUR: 100000,
                RateLimitType.DATA_UPLOAD_PER_DAY: 1024 * 1024 * 1024 * 100  # 100GB
            }
        }
    
    def check_rate_limits(self, api_key_context: Dict, endpoint: str) -> tuple[bool, Dict]:
        """Check all applicable rate limits for a request"""
        org_id = api_key_context['organization_id']
        plan = api_key_context['plan']
        api_key_id = api_key_context['api_key_id']
        
        limits_to_check = [
            # Per-API-key limits
            (f"api_key:{api_key_id}", RateLimitType.REQUESTS_PER_MINUTE, 60),
            (f"api_key:{api_key_id}", RateLimitType.REQUESTS_PER_HOUR, 3600),
            (f"api_key:{api_key_id}", RateLimitType.REQUESTS_PER_DAY, 86400),
            
            # Per-organization limits
            (f"org:{org_id}", RateLimitType.REQUESTS_PER_MINUTE, 60),
            (f"org:{org_id}", RateLimitType.REQUESTS_PER_HOUR, 3600),
            (f"org:{org_id}", RateLimitType.REQUESTS_PER_DAY, 86400)
        ]
        
        # Add endpoint-specific limits
        if endpoint.startswith('/query'):
            limits_to_check.extend([
                (f"api_key:{api_key_id}", RateLimitType.QUERY_EXECUTIONS_PER_HOUR, 3600),
                (f"org:{org_id}", RateLimitType.QUERY_EXECUTIONS_PER_HOUR, 3600)
            ])
        elif endpoint.startswith('/upload'):
            limits_to_check.extend([
                (f"api_key:{api_key_id}", RateLimitType.DATA_UPLOAD_PER_DAY, 86400),
                (f"org:{org_id}", RateLimitType.DATA_UPLOAD_PER_DAY, 86400)
            ])
        
        # Check each limit
        rate_limit_headers = {}
        for identifier, limit_type, window in limits_to_check:
            limit_value = self.rate_limits[plan][limit_type]
            key = self.rate_limiter.get_rate_limit_key(identifier, limit_type)
            
            is_allowed, rate_info = self.rate_limiter.is_allowed(
                key, limit_value, window
            )
            
            if not is_allowed:
                return False, {
                    'error': 'Rate limit exceeded',
                    'limit_type': limit_type.value,
                    'limit': limit_value,
                    'window_seconds': window,
                    'retry_after': rate_info['reset_time'] - time.time()
                }
            
            # Collect headers for most restrictive limits
            header_prefix = f"X-RateLimit-{limit_type.value.replace('_', '-').title()}"
            rate_limit_headers.update({
                f"{header_prefix}-Limit": str(rate_info['limit']),
                f"{header_prefix}-Remaining": str(rate_info['remaining']),
                f"{header_prefix}-Reset": str(int(rate_info['reset_time']))
            })
        
        return True, rate_limit_headers
```

### Tier 3: Adaptive Rate Limiting

**Dynamic rate limiting based on system conditions:**

```python
class AdaptiveRateLimiter:
    """Rate limiter that adapts to system load and user behavior"""
    
    def __init__(self, base_rate_limiter: ApiRateLimiter):
        self.base_limiter = base_rate_limiter
        self.system_metrics = SystemMetrics()
        self.user_behavior = UserBehaviorAnalyzer()
    
    def get_adaptive_limits(self, api_key_context: Dict) -> Dict:
        """Calculate adaptive rate limits based on current conditions"""
        base_limits = self.base_limiter.rate_limits[api_key_context['plan']]
        
        # System load factor
        system_load_factor = self._calculate_system_load_factor()
        
        # User behavior factor
        behavior_factor = self._calculate_behavior_factor(api_key_context)
        
        # Historical usage factor
        usage_factor = self._calculate_usage_factor(api_key_context)
        
        # Apply adaptive factors
        adaptive_limits = {}
        for limit_type, base_value in base_limits.items():
            adaptive_value = base_value * system_load_factor * behavior_factor * usage_factor
            adaptive_limits[limit_type] = max(1, int(adaptive_value))
        
        return adaptive_limits
    
    def _calculate_system_load_factor(self) -> float:
        """Calculate system load factor (0.1 to 1.5)"""
        cpu_usage = self.system_metrics.get_cpu_usage()
        memory_usage = self.system_metrics.get_memory_usage()
        queue_depth = self.system_metrics.get_queue_depth()
        
        if cpu_usage > 90 or memory_usage > 90 or queue_depth > 1000:
            return 0.1  # Severe load - restrict heavily
        elif cpu_usage > 70 or memory_usage > 70 or queue_depth > 500:
            return 0.5  # High load - moderate restriction
        elif cpu_usage < 30 and memory_usage < 30 and queue_depth < 100:
            return 1.5  # Low load - allow higher limits
        else:
            return 1.0  # Normal load
    
    def _calculate_behavior_factor(self, api_key_context: Dict) -> float:
        """Calculate user behavior factor based on patterns"""
        api_key_id = api_key_context['api_key_id']
        
        # Check for good behavior patterns
        good_patterns = 0
        if self.user_behavior.has_consistent_usage_pattern(api_key_id):
            good_patterns += 1
        if self.user_behavior.respects_rate_limits(api_key_id):
            good_patterns += 1
        if self.user_behavior.uses_efficient_queries(api_key_id):
            good_patterns += 1
        
        # Check for bad behavior patterns
        bad_patterns = 0
        if self.user_behavior.has_burst_patterns(api_key_id):
            bad_patterns += 1
        if self.user_behavior.frequent_rate_limit_violations(api_key_id):
            bad_patterns += 1
        if self.user_behavior.uses_inefficient_queries(api_key_id):
            bad_patterns += 1
        
        # Calculate factor
        if bad_patterns >= 2:
            return 0.3  # Penalize bad behavior
        elif good_patterns >= 2:
            return 1.3  # Reward good behavior
        else:
            return 1.0  # Neutral
    
    def _calculate_usage_factor(self, api_key_context: Dict) -> float:
        """Calculate usage history factor"""
        api_key_id = api_key_context['api_key_id']
        
        # Historical compliance with rate limits
        compliance_rate = self.user_behavior.get_compliance_rate(api_key_id, days=30)
        
        if compliance_rate > 0.95:
            return 1.2  # Excellent compliance
        elif compliance_rate > 0.8:
            return 1.0  # Good compliance
        elif compliance_rate > 0.6:
            return 0.8  # Poor compliance
        else:
            return 0.5  # Very poor compliance

class SystemMetrics:
    """Collect system performance metrics"""
    
    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        # Implementation depends on monitoring system
        pass
    
    def get_memory_usage(self) -> float:
        """Get current memory usage percentage"""
        pass
    
    def get_queue_depth(self) -> int:
        """Get current request queue depth"""
        pass

class UserBehaviorAnalyzer:
    """Analyze user behavior patterns"""
    
    def has_consistent_usage_pattern(self, api_key_id: str) -> bool:
        """Check if user has consistent usage patterns"""
        # Analyze request timing patterns
        pass
    
    def respects_rate_limits(self, api_key_id: str) -> bool:
        """Check if user consistently stays within rate limits"""
        pass
    
    def frequent_rate_limit_violations(self, api_key_id: str) -> bool:
        """Check for frequent rate limit violations"""
        pass
```

## Rate Limiting Middleware

### Flask Middleware Implementation

```python
# rate_limiting_middleware.py
from flask import request, jsonify, g
from functools import wraps
import time

class RateLimitingMiddleware:
    """Flask middleware for rate limiting"""
    
    def __init__(self, app, rate_limiter: AdaptiveRateLimiter):
        self.app = app
        self.rate_limiter = rate_limiter
        self.app.before_request(self.before_request)
        self.app.after_request(self.after_request)
    
    def before_request(self):
        """Check rate limits before processing request"""
        
        # Skip rate limiting for health checks
        if request.path in ['/health', '/ready', '/live']:
            return
        
        # Get API key context from authentication middleware
        api_key_context = getattr(g, 'api_key_context', None)
        if not api_key_context:
            return  # Will be handled by authentication middleware
        
        # Check rate limits
        is_allowed, rate_info = self.rate_limiter.check_rate_limits(
            api_key_context, request.path
        )
        
        if not is_allowed:
            response = jsonify({
                'error': {
                    'code': 'RATE_LIMIT_EXCEEDED',
                    'message': rate_info['error'],
                    'limit_type': rate_info['limit_type'],
                    'retry_after': rate_info['retry_after']
                }
            })
            response.status_code = 429
            response.headers['Retry-After'] = str(int(rate_info['retry_after']))
            return response
        
        # Store rate limit info for response headers
        g.rate_limit_headers = rate_info
    
    def after_request(self, response):
        """Add rate limiting headers to response"""
        
        rate_limit_headers = getattr(g, 'rate_limit_headers', {})
        for header, value in rate_limit_headers.items():
            response.headers[header] = value
        
        return response

def rate_limit(limit_type: RateLimitType, custom_limit: Optional[int] = None):
    """Decorator for endpoint-specific rate limiting"""
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Custom rate limiting logic for specific endpoints
            if custom_limit:
                # Apply custom limit
                pass
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Usage example
@app.route('/api/v1/public/datasets/{id}/query', methods=['POST'])
@rate_limit(RateLimitType.QUERY_EXECUTIONS_PER_HOUR, custom_limit=100)
def execute_query(id):
    # Query execution logic
    pass
```

## Rate Limiting Algorithms

### Sliding Window Implementation

```python
class SlidingWindowRateLimiter:
    """Accurate sliding window rate limiter using Redis sorted sets"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def is_allowed(self, key: str, limit: int, window_seconds: int) -> bool:
        """
        Sliding window rate limiting
        More accurate than fixed window, prevents burst at window boundaries
        """
        current_time = time.time()
        
        # Lua script for atomic operations
        lua_script = """
        local key = KEYS[1]
        local window = tonumber(ARGV[1])
        local limit = tonumber(ARGV[2])
        local current_time = tonumber(ARGV[3])
        
        -- Remove expired entries
        redis.call('ZREMRANGEBYSCORE', key, 0, current_time - window)
        
        -- Count current entries
        local current_count = redis.call('ZCARD', key)
        
        if current_count < limit then
            -- Add current request
            redis.call('ZADD', key, current_time, current_time)
            redis.call('EXPIRE', key, window)
            return {1, current_count + 1}
        else
            return {0, current_count}
        end
        """
        
        result = self.redis.eval(lua_script, 1, key, window_seconds, limit, current_time)
        return bool(result[0])

class TokenBucketRateLimiter:
    """Token bucket algorithm for smooth rate limiting"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def is_allowed(self, key: str, capacity: int, refill_rate: float) -> bool:
        """
        Token bucket rate limiting
        Allows bursts up to capacity, then enforces steady rate
        """
        current_time = time.time()
        
        lua_script = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local current_time = tonumber(ARGV[3])
        
        -- Get current bucket state
        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1]) or capacity
        local last_refill = tonumber(bucket[2]) or current_time
        
        -- Calculate tokens to add
        local time_passed = current_time - last_refill
        local tokens_to_add = time_passed * refill_rate
        tokens = math.min(capacity, tokens + tokens_to_add)
        
        if tokens >= 1 then
            -- Consume token
            tokens = tokens - 1
            redis.call('HMSET', key, 'tokens', tokens, 'last_refill', current_time)
            redis.call('EXPIRE', key, 3600)  -- Expire after 1 hour of inactivity
            return 1
        else
            -- Update last refill time
            redis.call('HMSET', key, 'tokens', tokens, 'last_refill', current_time)
            redis.call('EXPIRE', key, 3600)
            return 0
        end
        """
        
        result = self.redis.eval(lua_script, 1, key, capacity, refill_rate, current_time)
        return bool(result)
```

## Rate Limiting Configuration

### Environment-Specific Configurations

```yaml
# rate_limits.yml
development:
  default_plan: "free"
  enforce_limits: false
  rate_limits:
    free:
      requests_per_minute: 1000  # Higher for testing
      requests_per_hour: 10000
      requests_per_day: 100000

staging:
  default_plan: "basic"
  enforce_limits: true
  rate_limits:
    free:
      requests_per_minute: 100
      requests_per_hour: 1000
      requests_per_day: 10000
    basic:
      requests_per_minute: 500
      requests_per_hour: 10000
      requests_per_day: 100000

production:
  default_plan: "free"
  enforce_limits: true
  adaptive_limiting: true
  burst_protection: true
  rate_limits:
    free:
      requests_per_minute: 100
      requests_per_hour: 1000
      requests_per_day: 10000
      burst_capacity: 200
    basic:
      requests_per_minute: 500
      requests_per_hour: 10000
      requests_per_day: 100000
      burst_capacity: 1000
    premium:
      requests_per_minute: 1000
      requests_per_hour: 50000
      requests_per_day: 1000000
      burst_capacity: 2000
    enterprise:
      requests_per_minute: 5000
      requests_per_hour: 200000
      requests_per_day: 10000000
      burst_capacity: 10000
```

### Dynamic Configuration Updates

```python
class RateLimitConfigManager:
    """Manage rate limit configurations dynamically"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.config_key = "rate_limit_config"
    
    def update_organization_limits(self, org_id: str, new_limits: Dict):
        """Update rate limits for a specific organization"""
        config_key = f"{self.config_key}:org:{org_id}"
        self.redis.hset(config_key, mapping=new_limits)
        
        # Notify all API instances of config change
        self.redis.publish("rate_limit_config_update", json.dumps({
            'type': 'organization_update',
            'organization_id': org_id,
            'limits': new_limits
        }))
    
    def update_api_key_limits(self, api_key_id: str, new_limits: Dict):
        """Update rate limits for a specific API key"""
        config_key = f"{self.config_key}:api_key:{api_key_id}"
        self.redis.hset(config_key, mapping=new_limits)
        
        self.redis.publish("rate_limit_config_update", json.dumps({
            'type': 'api_key_update',
            'api_key_id': api_key_id,
            'limits': new_limits
        }))
    
    def get_effective_limits(self, api_key_context: Dict) -> Dict:
        """Get effective rate limits considering all overrides"""
        base_limits = self.get_plan_limits(api_key_context['plan'])
        
        # Check for organization-specific overrides
        org_limits = self.redis.hgetall(
            f"{self.config_key}:org:{api_key_context['organization_id']}"
        )
        
        # Check for API key-specific overrides
        key_limits = self.redis.hgetall(
            f"{self.config_key}:api_key:{api_key_context['api_key_id']}"
        )
        
        # Apply overrides in order of precedence
        effective_limits = base_limits.copy()
        effective_limits.update(org_limits)
        effective_limits.update(key_limits)
        
        return effective_limits
```

## Monitoring and Alerting

### Rate Limiting Metrics

```python
# rate_limit_metrics.py
from prometheus_client import Counter, Histogram, Gauge

# Rate limiting metrics
RATE_LIMIT_HITS = Counter(
    'rg_rate_limit_violations_total',
    'Total rate limit violations',
    ['organization_id', 'api_key_id', 'limit_type', 'endpoint']
)

RATE_LIMIT_CHECKS = Counter(
    'rg_rate_limit_checks_total',
    'Total rate limit checks',
    ['organization_id', 'limit_type', 'result']
)

RATE_LIMIT_RESPONSE_TIME = Histogram(
    'rg_rate_limit_check_duration_seconds',
    'Rate limit check duration'
)

CURRENT_USAGE = Gauge(
    'rg_current_usage_ratio',
    'Current usage as ratio of limit',
    ['organization_id', 'api_key_id', 'limit_type']
)

def record_rate_limit_check(api_key_context, limit_type, is_allowed, check_duration):
    """Record rate limiting metrics"""
    
    RATE_LIMIT_CHECKS.labels(
        organization_id=api_key_context['organization_id'],
        limit_type=limit_type,
        result='allowed' if is_allowed else 'denied'
    ).inc()
    
    RATE_LIMIT_RESPONSE_TIME.observe(check_duration)
    
    if not is_allowed:
        RATE_LIMIT_HITS.labels(
            organization_id=api_key_context['organization_id'],
            api_key_id=api_key_context['api_key_id'],
            limit_type=limit_type,
            endpoint=request.path
        ).inc()
```

### Alerting Rules

```yaml
# prometheus_alerts.yml
groups:
- name: rate_limiting
  rules:
  - alert: HighRateLimitViolations
    expr: rate(rg_rate_limit_violations_total[5m]) > 10
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: "High rate limit violations detected"
      description: "Organization {{ $labels.organization_id }} has {{ $value }} rate limit violations per second"
  
  - alert: RateLimitCheckLatency
    expr: histogram_quantile(0.95, rate(rg_rate_limit_check_duration_seconds_bucket[5m])) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "Rate limit checks are slow"
      description: "95th percentile rate limit check latency is {{ $value }}s"
  
  - alert: SuspiciousRateLimitPattern
    expr: rate(rg_rate_limit_violations_total[1m]) > 100
    for: 30s
    labels:
      severity: critical
    annotations:
      summary: "Possible DDoS attack detected"
      description: "Extremely high rate limit violations: {{ $value }} per second"
```

This comprehensive rate limiting strategy provides multiple layers of protection while ensuring fair resource allocation and maintaining API performance under varying load conditions.