# Architecture Overview

## Executive Summary

The RocketGraph Public API is designed as a **separate service** from the desktop application backend, providing secure, scalable access to XGT graph database operations for external developers and integrations.

## Design Rationale

### Why Separate Repository?

1. **Different Security Models**
   - **Desktop App**: Session-based auth, JWT cookies, CSRF protection, single-user focus
   - **Public API**: API key authentication, rate limiting, multi-tenant, different threat model

2. **Different Deployment Patterns**
   - **Desktop Backend**: Single instance, deployed with desktop app
   - **Public API**: Horizontal scaling, load balancing, CDN integration, multiple environments

3. **Different Development Cycles**
   - **Desktop App**: Feature-driven releases tied to desktop app versions
   - **Public API**: API versioning, backward compatibility, SLA commitments

4. **Security Isolation**
   - **Attack Surface**: Public API is internet-facing, desktop backend is not
   - **Credential Exposure**: Separate repos prevent accidental exposure
   - **Compliance**: Public API may need SOC2, PCI compliance

## Repository Structure

```
rocketgraph-public-api/          # New separate repo
├── app/
│   ├── api/v1/
│   │   ├── __init__.py
│   │   ├── auth.py              # API key authentication
│   │   ├── datasets.py          # Dataset operations
│   │   ├── queries.py           # Query operations
│   │   ├── schemas.py           # Schema operations
│   │   └── middleware.py        # Rate limiting, validation
│   ├── auth/
│   │   ├── api_keys.py          # API key management
│   │   ├── organizations.py     # Multi-tenant support
│   │   └── permissions.py       # Scope-based access
│   ├── middleware/
│   │   ├── rate_limiting.py     # Rate limiting implementation
│   │   ├── validation.py        # Request validation
│   │   └── audit.py             # Audit logging
│   ├── models/
│   │   ├── api_key.py           # API key data model
│   │   ├── organization.py      # Organization model
│   │   └── audit_log.py         # Audit log model
│   └── utils/
│       ├── xgt_operations.py    # XGT integration (copied/adapted)
│       ├── security.py          # Security utilities
│       └── monitoring.py        # Metrics and monitoring
├── tests/
│   ├── unit/
│   ├── integration/
│   └── security/
├── docs/
│   ├── api/                     # OpenAPI specifications
│   ├── guides/                  # Developer guides
│   └── security/                # Security documentation
├── deploy/
│   ├── docker/
│   ├── kubernetes/
│   └── terraform/
├── config/
│   ├── production.yml
│   ├── staging.yml
│   └── development.yml
└── requirements/
    ├── base.txt
    ├── production.txt
    └── development.txt
```

## System Architecture

### High-Level Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Internet                                  │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                Load Balancer + WAF                          │
│              (DDoS Protection, SSL Termination)             │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                 API Gateway (Optional)                      │
│            (Additional Rate Limiting, Analytics)            │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│              RocketGraph Public API Instances               │
│                (Horizontally Scalable)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   API-1     │  │   API-2     │  │   API-N     │         │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │         │
│  │ │Auth     │ │  │ │Auth     │ │  │ │Auth     │ │         │
│  │ │Validate │ │  │ │Validate │ │  │ │Validate │ │         │
│  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │         │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │         │
│  │ │Rate     │ │  │ │Rate     │ │  │ │Rate     │ │         │
│  │ │Limiting │ │  │ │Limiting │ │  │ │Limiting │ │         │
│  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │         │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │         │
│  │ │XGT Ops  │ │  │ │XGT Ops  │ │  │ │XGT Ops  │ │         │
│  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                  Shared Services                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Redis     │  │  MongoDB    │  │   XGT       │         │
│  │(Rate Limit  │  │(API Keys,   │  │ Database    │         │
│  │& Caching)   │  │Audit Logs)  │  │ Cluster     │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Request Authentication**
   ```
   Client → Load Balancer → API Instance → API Key Validation → Rate Limit Check
   ```

2. **Request Processing**
   ```
   Rate Limit Check → Input Validation → XGT Operations → Response Formation
   ```

3. **Audit & Monitoring**
   ```
   Every Step → Audit Log → Metrics Collection → Monitoring Dashboard
   ```

## Integration Strategy with Existing System

### Shared Components

**Option A: Shared Library Package**
```python
# rocketgraph-common (pip package)
├── rocketgraph_common/
│   ├── xgt_operations.py        # Shared XGT operations
│   ├── config/
│   ├── utils/
│   └── models/
```

**Option B: Service-to-Service Communication**
- Public API calls desktop backend for XGT operations
- Better separation, but more complex

**Option C: Direct XGT Integration (Recommended)**
- Public API has its own XGT operations
- Complete independence and security isolation

### Recommended: Option C (Direct Integration)

**Benefits:**
1. **Complete Isolation** - No shared attack vectors
2. **Independent Scaling** - Optimize each service separately
3. **Cleaner Security Model** - Each service has its own XGT connections
4. **Easier Compliance** - Public API can meet enterprise requirements

**Implementation:**
- Copy essential XGT operations from desktop backend
- Redesign for stateless, API-first patterns
- Add public API specific optimizations

## Deployment Environments

### Development Environment
```yaml
# docker-compose.dev.yml
services:
  public-api:
    build: .
    environment:
      - ENV=development
      - DEBUG=true
    ports:
      - "8000:8000"
  
  redis:
    image: redis:alpine
  
  mongodb:
    image: mongo:latest
  
  xgt:
    image: xgt:latest
```

### Staging Environment
- Kubernetes deployment
- Production-like data volumes
- Security scanning
- Performance testing

### Production Environment
- Multi-zone deployment
- Auto-scaling groups
- Comprehensive monitoring
- Disaster recovery

## Security Architecture

### Defense in Depth

1. **Network Level**
   - WAF (Web Application Firewall)
   - DDoS protection
   - Geographic restrictions

2. **Application Level**
   - API key authentication
   - Rate limiting
   - Input validation
   - Output sanitization

3. **Infrastructure Level**
   - TLS encryption
   - Secret management
   - Network isolation
   - Access logging

### Multi-Tenant Security

1. **Data Isolation**
   - Organization-scoped API keys
   - Database-level isolation
   - Query result filtering

2. **Access Control**
   - Scope-based permissions
   - Role-based access control
   - Resource-level restrictions

## Scalability Considerations

### Horizontal Scaling
- Stateless API design
- Load balancer compatibility
- Database connection pooling
- Cache layer optimization

### Performance Optimization
- Response caching
- Query result pagination
- Async job processing
- Connection multiplexing

### Monitoring & Observability
- Real-time metrics
- Distributed tracing
- Error tracking
- Performance profiling

## Migration Strategy

### Phase 1: Foundation
1. Create new repository
2. Set up basic infrastructure
3. Implement authentication system
4. Create core API endpoints

### Phase 2: Core Features
1. Implement graph operations
2. Add rate limiting
3. Set up monitoring
4. Create documentation

### Phase 3: Production Ready
1. Security hardening
2. Performance optimization
3. Compliance validation
4. Launch preparation

### Phase 4: Enhancement
1. Advanced features
2. SDK development
3. Partner integrations
4. Enterprise features

This architecture provides a solid foundation for a secure, scalable public API while maintaining complete separation from the existing desktop application infrastructure.