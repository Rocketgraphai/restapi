# RocketGraph Public API Documentation

This directory contains comprehensive documentation for the RocketGraph Public API, a secure REST API for graph database operations using XGT.

## Documentation Structure

- **[Architecture Overview](architecture-overview.md)** - High-level system design and deployment options
- **[Authentication Strategy](authentication-strategy.md)** - API key management and security model
- **[API Design](api-design.md)** - Endpoint specifications and usage patterns
- **[Security Guidelines](security-guidelines.md)** - Security best practices and implementation details
- **[Deployment Guide](deployment-guide.md)** - Production deployment and infrastructure requirements
- **[Rate Limiting](rate-limiting.md)** - Rate limiting strategies and configuration
- **[Monitoring & Auditing](monitoring-auditing.md)** - Logging, metrics, and compliance requirements

## Quick Start

The RocketGraph Public API is designed as a separate service from the desktop application backend, providing:

- **Secure API Key Authentication** - Bearer token authentication with scoped access
- **Multi-tenant Support** - Organization-based resource isolation
- **Enterprise Security** - Rate limiting, audit logging, and comprehensive monitoring
- **Graph Database Operations** - Full access to XGT graph database functionality
- **RESTful Design** - Standard HTTP methods with JSON payloads

## Design Principles

1. **Security First** - Every design decision prioritizes security and compliance
2. **Separation of Concerns** - Public API is completely separate from desktop application
3. **Scalability** - Designed for horizontal scaling and high availability
4. **Developer Experience** - Clear documentation, consistent patterns, helpful error messages
5. **Enterprise Ready** - Audit trails, monitoring, and SLA compliance built-in

## Target Architecture

```
┌─────────────────┐    ┌─────────────────┐
│  Desktop App    │    │   Public API    │
│   (Existing)    │    │  (New Service)  │
├─────────────────┤    ├─────────────────┤
│ Session Auth    │    │ API Key Auth    │
│ JWT Cookies     │    │ Bearer Tokens   │
│ CSRF Protection │    │ Rate Limiting   │
│ Single User     │    │ Multi-tenant    │
└─────────────────┘    └─────────────────┘
        │                       │
        └───────┬───────────────┘
                │
        ┌─────────────────┐
        │   XGT Database  │
        │  (Graph Engine) │
        └─────────────────┘
```

## Next Steps

1. Review the [Architecture Overview](architecture-overview.md) to understand the system design
2. Examine the [Authentication Strategy](authentication-strategy.md) for security implementation
3. Study the [API Design](api-design.md) for endpoint specifications
4. Follow the [Deployment Guide](deployment-guide.md) for production setup

## Contributing

This documentation is designed to evolve with the API implementation. Each document includes implementation notes and considerations for the development team.