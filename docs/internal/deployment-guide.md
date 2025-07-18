# Deployment Guide

## Overview

This guide covers production deployment strategies for the RocketGraph Public API, including infrastructure requirements, scaling considerations, and operational best practices.

## Deployment Architecture Options

### Option 1: Cloud-Native Kubernetes (Recommended)

**Infrastructure Stack:**
```
┌─────────────────────────────────────────────────────────────┐
│                 Load Balancer (AWS ALB/GCP LB)              │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                 Kubernetes Cluster                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Zone A    │  │   Zone B    │  │   Zone C    │         │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │         │
│  │ │API Pods │ │  │ │API Pods │ │  │ │API Pods │ │         │
│  │ │(2-4)    │ │  │ │(2-4)    │ │  │ │(2-4)    │ │         │
│  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                 Managed Services                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Redis     │  │  MongoDB    │  │   XGT       │         │
│  │ (ElastiCache│  │ (Atlas/     │  │ (Custom     │         │
│  │  /MemStore) │  │  DocDB)     │  │  Cluster)   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

**Kubernetes Manifests:**

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: rocketgraph-api
  labels:
    name: rocketgraph-api
    environment: production

---
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rocketgraph-public-api
  namespace: rocketgraph-api
spec:
  replicas: 6
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 2
  selector:
    matchLabels:
      app: rocketgraph-public-api
  template:
    metadata:
      labels:
        app: rocketgraph-public-api
        version: v1.0.0
    spec:
      serviceAccountName: rocketgraph-api-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
      containers:
      - name: api
        image: rocketgraph/public-api:1.0.0
        ports:
        - containerPort: 8000
          name: http
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: redis-credentials
              key: url
        - name: MONGODB_URI
          valueFrom:
            secretKeyRef:
              name: mongodb-credentials
              key: uri
        - name: XGT_HOST
          valueFrom:
            configMapKeyRef:
              name: xgt-config
              key: host
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: secret-key
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: 2000m
            memory: 4Gi
        livenessProbe:
          httpGet:
            path: /api/v1/public/health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/v1/public/health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - rocketgraph-public-api
              topologyKey: kubernetes.io/hostname

---
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: rocketgraph-public-api-service
  namespace: rocketgraph-api
spec:
  selector:
    app: rocketgraph-public-api
  ports:
  - name: http
    port: 80
    targetPort: 8000
  type: ClusterIP

---
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: rocketgraph-public-api-hpa
  namespace: rocketgraph-api
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: rocketgraph-public-api
  minReplicas: 6
  maxReplicas: 50
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60

---
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rocketgraph-public-api-ingress
  namespace: rocketgraph-api
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "1000"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - api.rocketgraph.com
    secretName: rocketgraph-api-tls
  rules:
  - host: api.rocketgraph.com
    http:
      paths:
      - path: /api/v1/public
        pathType: Prefix
        backend:
          service:
            name: rocketgraph-public-api-service
            port:
              number: 80
```

### Option 2: Container-Based (Docker + Docker Compose)

**For smaller deployments or development environments:**

```yaml
# docker-compose.production.yml
version: '3.8'

services:
  api:
    image: rocketgraph/public-api:latest
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '0.5'
          memory: 1G
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
    ports:
      - "8000-8002:8000"
    environment:
      - ENVIRONMENT=production
      - REDIS_URL=redis://redis:6379
      - MONGODB_URI=mongodb://mongodb:27017/rocketgraph
      - XGT_HOST=xgt
      - XGT_PORT=4367
    secrets:
      - app_secret_key
      - mongodb_password
    networks:
      - api_network
    depends_on:
      - redis
      - mongodb
      - xgt

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl:ro
    depends_on:
      - api
    networks:
      - api_network

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    networks:
      - api_network
    deploy:
      resources:
        limits:
          memory: 2G

  mongodb:
    image: mongo:6
    environment:
      MONGO_INITDB_ROOT_USERNAME_FILE: /run/secrets/mongodb_username
      MONGO_INITDB_ROOT_PASSWORD_FILE: /run/secrets/mongodb_password
    volumes:
      - mongodb_data:/data/db
    secrets:
      - mongodb_username
      - mongodb_password
    networks:
      - api_network

  xgt:
    image: xgt:latest
    environment:
      XGT_LICENSE_FILE: /run/secrets/xgt_license
    volumes:
      - xgt_data:/data
    secrets:
      - xgt_license
    networks:
      - api_network

networks:
  api_network:
    driver: overlay
    encrypted: true

volumes:
  redis_data:
  mongodb_data:
  xgt_data:

secrets:
  app_secret_key:
    file: ./secrets/app_secret_key.txt
  mongodb_username:
    file: ./secrets/mongodb_username.txt
  mongodb_password:
    file: ./secrets/mongodb_password.txt
  xgt_license:
    file: ./secrets/xgt_license.txt
```

### Option 3: Serverless (AWS Lambda/Google Cloud Functions)

**For variable workloads with cost optimization:**

```yaml
# serverless.yml
service: rocketgraph-public-api

provider:
  name: aws
  runtime: python3.11
  region: us-east-1
  stage: ${opt:stage, 'production'}
  environment:
    REDIS_URL: ${ssm:/rocketgraph/${self:provider.stage}/redis_url}
    MONGODB_URI: ${ssm:/rocketgraph/${self:provider.stage}/mongodb_uri}
    XGT_HOST: ${ssm:/rocketgraph/${self:provider.stage}/xgt_host}
    SECRET_KEY: ${ssm:/rocketgraph/${self:provider.stage}/secret_key~true}
  
  vpc:
    securityGroupIds:
      - sg-12345678
    subnetIds:
      - subnet-12345678
      - subnet-87654321

  apiGateway:
    restApiId: ${ssm:/rocketgraph/${self:provider.stage}/api_gateway_id}
    restApiRootResourceId: ${ssm:/rocketgraph/${self:provider.stage}/api_gateway_root_id}

functions:
  api:
    handler: app.lambda_handler
    timeout: 30
    memorySize: 1024
    reservedConcurrency: 100
    events:
      - http:
          path: api/v1/public/{proxy+}
          method: ANY
          cors: true

plugins:
  - serverless-python-requirements
  - serverless-plugin-warmup

custom:
  pythonRequirements:
    dockerizePip: true
    zip: true
  warmup:
    enabled: true
    frequency: 'rate(5 minutes)'
```

## Environment Configuration

### Production Environment Variables

```bash
# Application Configuration
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=<generated-secret-key>

# Database Configuration
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/rocketgraph
REDIS_URL=redis://elasticache-cluster:6379

# XGT Configuration
XGT_HOST=xgt-cluster.internal
XGT_PORT=4367
XGT_USE_SSL=true
XGT_SSL_CERT=/etc/ssl/certs/xgt-server.pem

# API Configuration
API_VERSION=1.0.0
API_BASE_URL=https://api.rocketgraph.com
CORS_ORIGINS=https://dashboard.rocketgraph.com,https://app.rocketgraph.com

# Security Configuration
JWT_SECRET_KEY=<jwt-secret-key>
API_KEY_SALT=<api-key-salt>
RATE_LIMIT_STORAGE=redis
RATE_LIMIT_STORAGE_URL=${REDIS_URL}

# Monitoring & Logging
LOG_LEVEL=INFO
SENTRY_DSN=<sentry-dsn>
DATADOG_API_KEY=<datadog-api-key>
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090

# Feature Flags
ENABLE_QUERY_CACHING=true
ENABLE_RESULT_STREAMING=true
ENABLE_ADVANCED_ANALYTICS=true
```

### Configuration Management

**Using HashiCorp Vault:**
```python
# config/vault_config.py
import hvac

class VaultConfig:
    def __init__(self):
        self.client = hvac.Client(url='https://vault.company.com:8200')
        self.client.token = os.environ['VAULT_TOKEN']
    
    def get_secret(self, path):
        """Retrieve secret from Vault"""
        response = self.client.secrets.kv.v2.read_secret_version(path=path)
        return response['data']['data']
    
    def get_database_config(self):
        """Get database configuration from Vault"""
        return self.get_secret('rocketgraph/production/database')
    
    def get_api_keys(self):
        """Get API service keys from Vault"""
        return self.get_secret('rocketgraph/production/api-keys')
```

**Using Kubernetes Secrets:**
```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: rocketgraph-api
type: Opaque
data:
  secret-key: <base64-encoded-secret>
  jwt-secret: <base64-encoded-jwt-secret>
  api-key-salt: <base64-encoded-salt>

---
apiVersion: v1
kind: Secret
metadata:
  name: mongodb-credentials
  namespace: rocketgraph-api
type: Opaque
data:
  uri: <base64-encoded-mongodb-uri>

---
apiVersion: v1
kind: Secret
metadata:
  name: redis-credentials
  namespace: rocketgraph-api
type: Opaque
data:
  url: <base64-encoded-redis-url>
```

## Infrastructure Requirements

### Minimum Production Requirements

**API Servers:**
- **CPU**: 2 vCPUs per instance
- **Memory**: 4 GB RAM per instance
- **Storage**: 20 GB SSD
- **Network**: 1 Gbps
- **Instances**: Minimum 3 for high availability

**Database Servers:**

**MongoDB (API Metadata):**
- **CPU**: 4 vCPUs
- **Memory**: 8 GB RAM
- **Storage**: 100 GB SSD (with automatic scaling)
- **Backup**: Daily automated backups with 30-day retention

**Redis (Rate Limiting & Caching):**
- **CPU**: 2 vCPUs
- **Memory**: 4 GB RAM
- **Storage**: Memory-optimized
- **Replication**: Master-slave configuration

**XGT Graph Database:**
- **CPU**: 8+ vCPUs (depending on workload)
- **Memory**: 32+ GB RAM
- **Storage**: 500+ GB NVMe SSD
- **Network**: 10 Gbps for large datasets

### Scaling Guidelines

**Horizontal Scaling Triggers:**
```yaml
# Auto-scaling configuration
scaling_metrics:
  cpu_utilization:
    scale_up_threshold: 70%
    scale_down_threshold: 30%
    
  memory_utilization:
    scale_up_threshold: 80%
    scale_down_threshold: 40%
    
  request_rate:
    scale_up_threshold: 1000 req/min per instance
    scale_down_threshold: 300 req/min per instance
    
  response_time:
    scale_up_threshold: 500ms p95
    scale_down_threshold: 200ms p95

scaling_behavior:
  min_instances: 3
  max_instances: 50
  scale_up_cooldown: 300s
  scale_down_cooldown: 600s
  scale_up_factor: 2x
  scale_down_factor: 0.5x
```

**Database Scaling Strategy:**
- **MongoDB**: Replica sets with read replicas
- **Redis**: Cluster mode for horizontal scaling
- **XGT**: Distributed cluster setup for large datasets

## Monitoring & Observability

### Application Metrics

**Prometheus Configuration:**
```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rocketgraph_rules.yml"

scrape_configs:
  - job_name: 'rocketgraph-api'
    static_configs:
      - targets: ['api:9090']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
```

**Key Metrics to Monitor:**
```python
# metrics.py
from prometheus_client import Counter, Histogram, Gauge

# Request metrics
REQUEST_COUNT = Counter(
    'rocketgraph_requests_total',
    'Total API requests',
    ['method', 'endpoint', 'status_code', 'organization_id']
)

REQUEST_DURATION = Histogram(
    'rocketgraph_request_duration_seconds',
    'Request duration in seconds',
    ['method', 'endpoint']
)

# Query metrics
QUERY_EXECUTION_TIME = Histogram(
    'rocketgraph_query_execution_seconds',
    'Query execution time',
    ['dataset_id', 'query_type']
)

ACTIVE_QUERIES = Gauge(
    'rocketgraph_active_queries',
    'Number of currently executing queries'
)

# Rate limiting metrics
RATE_LIMIT_HITS = Counter(
    'rocketgraph_rate_limit_hits_total',
    'Rate limit violations',
    ['api_key_id', 'limit_type']
)

# Error metrics
ERROR_RATE = Counter(
    'rocketgraph_errors_total',
    'Total errors',
    ['error_type', 'endpoint']
)
```

### Logging Strategy

**Structured Logging Configuration:**
```python
# logging_config.py
import structlog
import json

def configure_logging():
    """Configure structured logging for production"""
    
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

# Usage example
import structlog
logger = structlog.get_logger()

def process_query(query, auth_context):
    logger.info(
        "Query execution started",
        query_id=query.id,
        organization_id=auth_context.organization_id,
        api_key_id=auth_context.api_key.id,
        query_length=len(query.text),
        estimated_rows=query.estimated_result_size
    )
```

### Health Checks

**Comprehensive Health Check Endpoint:**
```python
# health.py
from flask import Blueprint, jsonify
import time

health_bp = Blueprint('health', __name__)

@health_bp.route('/health')
def health_check():
    """Comprehensive health check endpoint"""
    
    start_time = time.time()
    health_status = {
        'status': 'healthy',
        'timestamp': time.time(),
        'version': '1.0.0',
        'services': {}
    }
    
    # Check database connectivity
    try:
        db.admin.command('ismaster')
        health_status['services']['mongodb'] = 'healthy'
    except Exception as e:
        health_status['services']['mongodb'] = f'unhealthy: {str(e)}'
        health_status['status'] = 'degraded'
    
    # Check Redis connectivity
    try:
        redis_client.ping()
        health_status['services']['redis'] = 'healthy'
    except Exception as e:
        health_status['services']['redis'] = f'unhealthy: {str(e)}'
        health_status['status'] = 'degraded'
    
    # Check XGT connectivity
    try:
        xgt_connection = get_xgt_connection()
        xgt_connection.get_server_info()
        health_status['services']['xgt'] = 'healthy'
    except Exception as e:
        health_status['services']['xgt'] = f'unhealthy: {str(e)}'
        health_status['status'] = 'unhealthy'
    
    # Performance metrics
    health_status['response_time_ms'] = (time.time() - start_time) * 1000
    
    # Determine HTTP status code
    if health_status['status'] == 'healthy':
        status_code = 200
    elif health_status['status'] == 'degraded':
        status_code = 200  # Still serving traffic
    else:
        status_code = 503  # Service unavailable
    
    return jsonify(health_status), status_code

@health_bp.route('/ready')
def readiness_check():
    """Kubernetes readiness probe"""
    # Check if service is ready to receive traffic
    if all_services_ready():
        return jsonify({'status': 'ready'}), 200
    else:
        return jsonify({'status': 'not ready'}), 503

@health_bp.route('/live')
def liveness_check():
    """Kubernetes liveness probe"""
    # Simple check to ensure service is running
    return jsonify({'status': 'alive'}), 200
```

## Security Hardening

### Network Security

**Firewall Rules:**
```bash
# iptables rules for API servers
# Allow incoming HTTP/HTTPS traffic
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow internal cluster communication
iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT

# Allow monitoring access
iptables -A INPUT -p tcp --dport 9090 -s monitoring_subnet -j ACCEPT

# Block all other traffic
iptables -A INPUT -j DROP
```

**TLS Configuration:**
```nginx
# nginx.conf SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;

# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Security headers
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options DENY;
add_header X-XSS-Protection "1; mode=block";
add_header Referrer-Policy "strict-origin-when-cross-origin";
```

### Secrets Management

**Kubernetes Secrets Rotation:**
```bash
#!/bin/bash
# secrets-rotation.sh

# Rotate API secrets
kubectl create secret generic app-secrets-new \
  --from-literal=secret-key=$(openssl rand -base64 32) \
  --from-literal=jwt-secret=$(openssl rand -base64 32) \
  --from-literal=api-key-salt=$(openssl rand -base64 16) \
  --namespace=rocketgraph-api

# Update deployment to use new secrets
kubectl patch deployment rocketgraph-public-api \
  -p '{"spec":{"template":{"spec":{"volumes":[{"name":"secret-volume","secret":{"secretName":"app-secrets-new"}}]}}}}' \
  --namespace=rocketgraph-api

# Wait for rollout
kubectl rollout status deployment/rocketgraph-public-api --namespace=rocketgraph-api

# Delete old secrets
kubectl delete secret app-secrets --namespace=rocketgraph-api

# Rename new secrets
kubectl patch secret app-secrets-new --type='merge' -p='{"metadata":{"name":"app-secrets"}}' --namespace=rocketgraph-api
```

## Disaster Recovery

### Backup Strategy

**Automated Backup Script:**
```python
# backup.py
import subprocess
import boto3
from datetime import datetime

class BackupManager:
    def __init__(self):
        self.s3_client = boto3.client('s3')
        self.backup_bucket = 'rocketgraph-backups'
    
    def backup_mongodb(self):
        """Backup MongoDB to S3"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"mongodb_backup_{timestamp}.gz"
        
        # Create MongoDB dump
        subprocess.run([
            'mongodump',
            '--uri', os.environ['MONGODB_URI'],
            '--gzip',
            '--archive', backup_filename
        ])
        
        # Upload to S3
        self.s3_client.upload_file(
            backup_filename,
            self.backup_bucket,
            f"mongodb/{backup_filename}"
        )
        
        # Cleanup local file
        os.remove(backup_filename)
    
    def backup_redis(self):
        """Backup Redis data"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"redis_backup_{timestamp}.rdb"
        
        # Create Redis backup
        subprocess.run([
            'redis-cli',
            '--rdb', backup_filename
        ])
        
        # Upload to S3
        self.s3_client.upload_file(
            backup_filename,
            self.backup_bucket,
            f"redis/{backup_filename}"
        )
        
        # Cleanup local file
        os.remove(backup_filename)

# Schedule backups
if __name__ == "__main__":
    backup_manager = BackupManager()
    backup_manager.backup_mongodb()
    backup_manager.backup_redis()
```

### Recovery Procedures

**MongoDB Recovery:**
```bash
# Restore MongoDB from backup
mongorestore --uri="mongodb://localhost:27017/rocketgraph" \
  --gzip \
  --archive=mongodb_backup_20240115_120000.gz \
  --drop
```

**Redis Recovery:**
```bash
# Stop Redis service
systemctl stop redis

# Replace Redis dump file
cp redis_backup_20240115_120000.rdb /var/lib/redis/dump.rdb

# Start Redis service
systemctl start redis
```

This deployment guide provides a comprehensive foundation for deploying the RocketGraph Public API in production environments with enterprise-grade reliability, security, and scalability.