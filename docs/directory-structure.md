# Directory Structure

## Overview

This document describes the complete directory structure for the RocketGraph Public API project, organized to support enterprise-grade development, testing, deployment, and operations.

## Complete Directory Structure

```
rocketgraph-public-api/
├── 📁 app/                          # Main application code
│   ├── 📁 api/                      # API endpoints
│   │   ├── 📁 v1/                   # API version 1
│   │   │   ├── 📁 public/           # Public API endpoints
│   │   │   │   ├── __init__.py
│   │   │   │   ├── datasets.py      # Dataset operations
│   │   │   │   ├── queries.py       # Query execution
│   │   │   │   ├── schemas.py       # Schema operations
│   │   │   │   ├── uploads.py       # Data upload
│   │   │   │   └── health.py        # Health checks
│   │   │   └── 📁 admin/            # Admin API endpoints
│   │   │       ├── __init__.py
│   │   │       ├── api_keys.py      # API key management
│   │   │       ├── organizations.py # Organization management
│   │   │       ├── users.py         # User management
│   │   │       ├── audit.py         # Audit log access
│   │   │       └── system.py        # System administration
│   │   └── 📁 v2/                   # API version 2 (future)
│   │       └── 📁 public/           # Public API endpoints v2
│   │           └── __init__.py
│   ├── 📁 auth/                     # Authentication & authorization
│   │   ├── __init__.py
│   │   ├── api_keys.py              # API key authentication
│   │   ├── permissions.py           # Permission checking
│   │   ├── organizations.py         # Multi-tenant support
│   │   └── decorators.py            # Auth decorators
│   ├── 📁 middleware/               # Request middleware
│   │   ├── __init__.py
│   │   ├── rate_limiting.py         # Rate limiting middleware
│   │   ├── authentication.py       # Auth middleware
│   │   ├── validation.py            # Request validation
│   │   ├── audit_logging.py         # Audit logging
│   │   ├── cors.py                  # CORS handling
│   │   └── security.py              # Security headers
│   ├── 📁 models/                   # Data models
│   │   ├── __init__.py
│   │   ├── api_key.py               # API key model
│   │   ├── organization.py          # Organization model
│   │   ├── user.py                  # User model
│   │   ├── audit_log.py             # Audit log model
│   │   ├── dataset.py               # Dataset model
│   │   └── query.py                 # Query model
│   ├── 📁 utils/                    # Utility functions
│   │   ├── __init__.py
│   │   ├── xgt_operations.py        # XGT database operations
│   │   ├── security.py              # Security utilities
│   │   ├── monitoring.py            # Metrics and monitoring
│   │   ├── encryption.py            # Encryption utilities
│   │   ├── validation.py            # Input validation
│   │   ├── geo_location.py          # Geographic utilities
│   │   └── exceptions.py            # Custom exceptions
│   └── 📁 config/                   # Application configuration
│       ├── __init__.py
│       ├── app_config.py            # Main app configuration
│       ├── database.py              # Database configuration
│       ├── rate_limits.py           # Rate limiting configuration
│       ├── security.py              # Security configuration
│       └── monitoring.py            # Monitoring configuration
├── 📁 tests/                        # Test suites
│   ├── __init__.py
│   ├── conftest.py                  # Pytest configuration
│   ├── fixtures/                    # Test fixtures
│   │   ├── __init__.py
│   │   ├── api_keys.py              # API key fixtures
│   │   ├── organizations.py         # Organization fixtures
│   │   └── test_data.py             # Test data fixtures
│   ├── 📁 unit/                     # Unit tests
│   │   ├── __init__.py
│   │   ├── test_auth.py             # Authentication tests
│   │   ├── test_models.py           # Model tests
│   │   ├── test_utils.py            # Utility tests
│   │   ├── test_middleware.py       # Middleware tests
│   │   └── test_api/                # API endpoint tests
│   │       ├── __init__.py
│   │       ├── test_datasets.py
│   │       ├── test_queries.py
│   │       └── test_uploads.py
│   ├── 📁 integration/              # Integration tests
│   │   ├── __init__.py
│   │   ├── test_api_workflows.py    # End-to-end API tests
│   │   ├── test_database.py         # Database integration
│   │   ├── test_xgt_integration.py  # XGT integration tests
│   │   └── test_auth_flows.py       # Authentication flows
│   ├── 📁 security/                 # Security tests
│   │   ├── __init__.py
│   │   ├── test_injection.py        # Injection attack tests
│   │   ├── test_auth_bypass.py      # Auth bypass tests
│   │   ├── test_rate_limiting.py    # Rate limiting tests
│   │   ├── test_input_validation.py # Input validation tests
│   │   └── test_encryption.py       # Encryption tests
│   └── 📁 performance/              # Performance tests
│       ├── __init__.py
│       ├── test_load.py             # Load testing
│       ├── test_stress.py           # Stress testing
│       ├── test_scalability.py      # Scalability testing
│       └── benchmarks/              # Performance benchmarks
│           ├── __init__.py
│           ├── api_benchmarks.py
│           └── query_benchmarks.py
├── 📁 deploy/                       # Deployment configurations
│   ├── 📁 docker/                   # Docker configurations
│   │   ├── Dockerfile               # Production Dockerfile
│   │   ├── Dockerfile.dev           # Development Dockerfile
│   │   ├── docker-compose.yml       # Docker Compose for local dev
│   │   ├── docker-compose.prod.yml  # Production Docker Compose
│   │   └── .dockerignore            # Docker ignore file
│   ├── 📁 kubernetes/               # Kubernetes manifests
│   │   ├── namespace.yaml           # Namespace definition
│   │   ├── deployment.yaml          # Application deployment
│   │   ├── service.yaml             # Service definition
│   │   ├── ingress.yaml             # Ingress configuration
│   │   ├── configmap.yaml           # Configuration maps
│   │   ├── secrets.yaml             # Secret templates
│   │   ├── hpa.yaml                 # Horizontal Pod Autoscaler
│   │   ├── networkpolicy.yaml       # Network policies
│   │   └── monitoring/              # Monitoring resources
│   │       ├── servicemonitor.yaml
│   │       └── prometheusrule.yaml
│   ├── 📁 terraform/                # Infrastructure as code
│   │   ├── main.tf                  # Main Terraform configuration
│   │   ├── variables.tf             # Variable definitions
│   │   ├── outputs.tf               # Output definitions
│   │   ├── versions.tf              # Provider versions
│   │   ├── modules/                 # Terraform modules
│   │   │   ├── vpc/                 # VPC module
│   │   │   ├── eks/                 # EKS cluster module
│   │   │   ├── rds/                 # RDS module
│   │   │   └── elasticache/         # ElastiCache module
│   │   └── environments/            # Environment-specific configs
│   │       ├── dev.tfvars
│   │       ├── staging.tfvars
│   │       └── production.tfvars
│   └── 📁 helm/                     # Helm charts
│       ├── Chart.yaml               # Helm chart metadata
│       ├── values.yaml              # Default values
│       ├── templates/               # Kubernetes templates
│       │   ├── deployment.yaml
│       │   ├── service.yaml
│       │   ├── ingress.yaml
│       │   ├── configmap.yaml
│       │   └── secrets.yaml
│       └── values/                  # Environment values
│           ├── dev.yaml
│           ├── staging.yaml
│           └── production.yaml
├── 📁 config/                       # Configuration files
│   ├── 📁 environments/             # Environment-specific configs
│   │   ├── development.yml          # Development configuration
│   │   ├── staging.yml              # Staging configuration
│   │   ├── production.yml           # Production configuration
│   │   └── testing.yml              # Testing configuration
│   ├── 📁 secrets/                  # Secret templates
│   │   ├── api-keys.template.yml    # API key templates
│   │   ├── database.template.yml    # Database secret templates
│   │   ├── certificates.template.yml # Certificate templates
│   │   └── README.md                # Secret management guide
│   └── 📁 ssl/                      # SSL certificates
│       ├── certs/                   # Certificate files
│       ├── private/                 # Private keys
│       └── ca/                      # Certificate authorities
├── 📁 scripts/                      # Operational scripts
│   ├── 📁 deployment/               # Deployment scripts
│   │   ├── deploy.sh                # Main deployment script
│   │   ├── rollback.sh              # Rollback script
│   │   ├── blue-green-deploy.sh     # Blue-green deployment
│   │   ├── canary-deploy.sh         # Canary deployment
│   │   └── health-check.sh          # Health check script
│   ├── 📁 monitoring/               # Monitoring scripts
│   │   ├── setup-monitoring.sh      # Setup monitoring stack
│   │   ├── alert-rules.py           # Alert rule generator
│   │   ├── dashboard-generator.py   # Dashboard generator
│   │   └── metrics-exporter.py      # Custom metrics exporter
│   ├── 📁 maintenance/              # Maintenance scripts
│   │   ├── database-cleanup.py      # Database cleanup
│   │   ├── log-rotation.sh          # Log rotation
│   │   ├── certificate-renewal.sh   # Certificate renewal
│   │   └── cache-warming.py         # Cache warming
│   └── 📁 backup/                   # Backup scripts
│       ├── backup-database.py       # Database backup
│       ├── backup-configs.sh        # Configuration backup
│       ├── restore-database.py      # Database restore
│       └── disaster-recovery.py     # Disaster recovery
├── 📁 requirements/                 # Python dependencies
│   ├── base.txt                     # Base requirements
│   ├── development.txt              # Development requirements
│   ├── production.txt               # Production requirements
│   ├── testing.txt                  # Testing requirements
│   └── security.txt                 # Security-focused packages
├── 📁 tools/                        # Development tools
│   ├── 📁 development/              # Development utilities
│   │   ├── api-client.py            # API testing client
│   │   ├── data-generator.py        # Test data generator
│   │   ├── schema-validator.py      # Schema validation tool
│   │   └── local-setup.sh           # Local development setup
│   ├── 📁 testing/                  # Testing tools
│   │   ├── test-runner.py           # Custom test runner
│   │   ├── coverage-reporter.py     # Coverage reporting
│   │   ├── security-scanner.py      # Security scanning
│   │   └── performance-profiler.py  # Performance profiling
│   └── 📁 monitoring/               # Monitoring tools
│       ├── log-analyzer.py          # Log analysis tool
│       ├── metric-collector.py      # Custom metric collector
│       ├── alert-tester.py          # Alert testing tool
│       └── dashboard-updater.py     # Dashboard maintenance
├── 📁 docs/                         # Documentation
│   ├── README.md                    # Project overview
│   ├── architecture-overview.md     # System architecture
│   ├── authentication-strategy.md   # Authentication design
│   ├── api-design.md               # API specifications
│   ├── security-guidelines.md       # Security best practices
│   ├── deployment-guide.md          # Deployment instructions
│   ├── rate-limiting.md             # Rate limiting strategy
│   ├── monitoring-auditing.md       # Monitoring and auditing
│   ├── directory-structure.md       # This file
│   ├── 📁 api/                      # API documentation
│   │   ├── openapi.yaml             # OpenAPI specification
│   │   ├── postman-collection.json  # Postman collection
│   │   └── examples/                # API examples
│   ├── 📁 guides/                   # User guides
│   │   ├── quick-start.md           # Quick start guide
│   │   ├── integration-guide.md     # Integration guide
│   │   └── troubleshooting.md       # Troubleshooting guide
│   └── 📁 development/              # Development documentation
│       ├── contributing.md          # Contributing guidelines
│       ├── coding-standards.md      # Coding standards
│       └── release-process.md       # Release process
├── .env.example                     # Environment variables example
├── .gitignore                       # Git ignore rules
├── .pre-commit-config.yaml          # Pre-commit hooks
├── .github/                         # GitHub workflows
│   └── workflows/                   # CI/CD workflows
│       ├── ci.yml                   # Continuous integration
│       ├── cd.yml                   # Continuous deployment
│       ├── security.yml             # Security scanning
│       └── release.yml              # Release automation
├── pyproject.toml                   # Python project configuration
├── pytest.ini                      # Pytest configuration
├── Makefile                         # Build automation
├── README.md                        # Project README
├── LICENSE                          # License file
└── CHANGELOG.md                     # Change log
```

## Directory Descriptions

### Core Application (`app/`)

**`app/api/`** - API endpoint implementations
- Organized by version (`v1/`, `v2/`)
- Separated public and admin endpoints
- RESTful resource-based organization

**`app/auth/`** - Authentication and authorization
- API key management and validation
- Permission checking and scoping
- Multi-tenant organization support

**`app/middleware/`** - Request processing middleware
- Rate limiting and throttling
- Request validation and sanitization
- Audit logging and security headers

**`app/models/`** - Data models and schemas
- Database entity definitions
- API request/response models
- Validation schemas

**`app/utils/`** - Shared utility functions
- XGT database operations
- Security and encryption utilities
- Monitoring and metrics collection

**`app/config/`** - Application configuration
- Environment-specific settings
- Feature flags and toggles
- Third-party service configurations

### Testing (`tests/`)

**`tests/unit/`** - Unit tests
- Individual function and class testing
- Mocked dependencies
- Fast execution for development feedback

**`tests/integration/`** - Integration tests
- Multi-component interaction testing
- Database and external service integration
- End-to-end workflow validation

**`tests/security/`** - Security-focused tests
- Penetration testing scenarios
- Input validation and injection testing
- Authentication and authorization testing

**`tests/performance/`** - Performance and load tests
- API endpoint performance benchmarks
- Scalability and stress testing
- Resource utilization analysis

### Deployment (`deploy/`)

**`deploy/docker/`** - Container configurations
- Multi-stage Dockerfiles for different environments
- Docker Compose for local development
- Container optimization and security

**`deploy/kubernetes/`** - Kubernetes manifests
- Production-ready Kubernetes deployments
- Auto-scaling and health monitoring
- Security policies and network isolation

**`deploy/terraform/`** - Infrastructure as Code
- Cloud infrastructure provisioning
- Environment-specific configurations
- Modular and reusable infrastructure components

**`deploy/helm/`** - Kubernetes package management
- Templated Kubernetes deployments
- Environment-specific value overrides
- Dependency management

### Configuration (`config/`)

**`config/environments/`** - Environment configurations
- Development, staging, and production settings
- Feature flag configurations
- Service endpoint configurations

**`config/secrets/`** - Secret management templates
- Kubernetes secret templates
- Certificate and key management
- Credential rotation procedures

**`config/ssl/`** - SSL/TLS certificates
- Certificate storage and management
- Certificate authority configurations
- Automated certificate renewal

### Operations (`scripts/`)

**`scripts/deployment/`** - Deployment automation
- Deployment orchestration scripts
- Blue-green and canary deployment strategies
- Rollback and recovery procedures

**`scripts/monitoring/`** - Monitoring setup and maintenance
- Monitoring stack deployment
- Alert rule configuration
- Dashboard and visualization setup

**`scripts/maintenance/`** - System maintenance
- Database cleanup and optimization
- Log rotation and archival
- Certificate renewal and updates

**`scripts/backup/`** - Backup and recovery
- Automated backup procedures
- Disaster recovery scripts
- Data restoration utilities

### Development Support

**`requirements/`** - Python dependency management
- Environment-specific requirements
- Security-focused package versions
- Dependency vulnerability scanning

**`tools/`** - Development and operational tools
- API testing and validation tools
- Performance profiling utilities
- Custom monitoring and alerting tools

**`docs/`** - Comprehensive documentation
- Architecture and design documentation
- API specifications and examples
- Operational runbooks and guides

## Design Principles

### Separation of Concerns
- Clear separation between application logic, configuration, and deployment
- Modular architecture supporting independent development and testing
- Environment-specific configurations isolated from application code

### Security First
- Security considerations integrated throughout the directory structure
- Dedicated security testing and validation
- Secret management and certificate handling

### Operational Excellence
- Comprehensive monitoring and alerting capabilities
- Automated deployment and rollback procedures
- Disaster recovery and backup strategies

### Developer Experience
- Clear development workflow support
- Comprehensive testing infrastructure
- Documentation and tooling for efficient development

### Scalability and Maintainability
- Version-aware API structure
- Modular and reusable infrastructure components
- Clear separation of environments and configurations

This directory structure provides a solid foundation for building, testing, deploying, and maintaining an enterprise-grade public API service.