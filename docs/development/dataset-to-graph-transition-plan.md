# Dataset → Graph Transition Plan

## Overview

This document outlines the plan to transition from `dataset` to `graph` terminology throughout the REST API that interfaces with the Rocketgraph xGT graph engine. This transition aligns the API with the new `graph` data structure/object being added to xGT.

## Current State Analysis

The API currently uses `dataset` extensively across:
- **Route endpoints**: `/datasets`, `/datasets/{dataset_name}/*`
- **Models**: `DatasetInfo`, `DatasetsResponse`, `DatasetFrameInfo`
- **Parameters**: `dataset_name` throughout query operations
- **Documentation**: All docstrings reference "datasets"
- **14+ Python files** with dataset references
- **17 documentation files** requiring updates

## Phase 1: Direct API Layer Changes (Clean Cutover)

### 1.1 Route Endpoints - Complete Replacement

#### File Changes
```
app/api/v1/public/datasets.py → app/api/v1/public/graphs.py
```

#### URL Changes
```
/api/v1/public/datasets → /api/v1/public/graphs
/api/v1/public/datasets/{dataset_name} → /api/v1/public/graphs/{graph_name}
/api/v1/public/datasets/{dataset_name}/schema → /api/v1/public/graphs/{graph_name}/schema
/api/v1/public/datasets/{dataset_name}/query → /api/v1/public/graphs/{graph_name}/query
```

### 1.2 Model Transformations

#### Model Renames
```python
DatasetInfo → GraphInfo
DatasetsResponse → GraphsResponse  
DatasetFrameInfo → FrameInfo (base class)
VertexFrameInfo → VertexFrameInfo (cleaned up, no Graph prefix)
EdgeFrameInfo → EdgeFrameInfo (cleaned up, no Graph prefix)
```

**Note**: Graph is a collection of frames, not a frame itself. The models now correctly reflect that:
- `GraphInfo` contains collections of `VertexFrameInfo` and `EdgeFrameInfo`
- Frame models don't have "Graph" prefix to avoid confusion

#### Field Changes
```python
# Response fields
datasets: list[DatasetInfo] → graphs: list[GraphInfo]

# Parameters throughout
dataset_name: str → graph_name: str

# Field descriptions
"Dataset the query was executed against" → "Graph the query was executed against"
"Available datasets" → "Available graphs"
"Filter by dataset name" → "Filter by graph name"
```

## Phase 2: XGT Integration Layer (Deferred)

### Constraint
Cannot update XGT integration until the graph feature is committed to the xGT repository.

### Current Approach
- Keep existing `datasets_info()` method calls in XGT operations
- Maintain `dataset_name` parameters in XGT operations  
- **Translation layer**: API models translate `graph_name` → `dataset_name` for XGT calls
- **Future**: Replace when XGT graph API becomes available

### Files Affected (Deferred)
- `app/utils/xgt_user_operations.py`
- `app/utils/xgt_operations.py`

## Phase 3: Testing & Infrastructure

### Test File Changes
```
tests/unit/test_datasets.py → tests/unit/test_graphs.py
tests/integration/test_xgt_datasets.py → tests/integration/test_xgt_graphs.py
```

### Script Updates
- `scripts/run-ci-tests.py`: Update test file references
- `test_auth_system.py`: Update endpoint paths from `/public/datasets` to `/public/graphs`

### Test Content Updates
- All endpoint URLs in test cases
- Response field assertions (`data["datasets"]` → `data["graphs"]`)
- Test method names and descriptions

## Phase 4: Documentation Updates (High Impact)

### Files Requiring Updates (17 total)
- `docs/developer-api-guide.md` - API endpoint examples  
- `docs/design/api-design.md` - Core endpoint documentation
- `docs/design/architecture-overview.md` - System terminology
- `docs/design/authentication-strategy.md`
- `docs/design/directory-structure.md`
- `docs/design/security-guidelines.md`
- `docs/internal/deployment-guide.md`
- `docs/internal/monitoring-auditing.md`
- `docs/internal/rate-limiting.md`
- `docs/testing/mock-vs-docker-analysis.md`
- `docs/quick-start-guide.md`
- `docs/api-developer-readme.md`
- `docs/archive/TRANSFORMATION_LOG.md`
- `README.md` - Example URLs and test commands
- `FASTAPI_DOCS_DEMO.md`
- `AUTH_MIGRATION_STATUS.md`
- `AUTHENTICATION_CONFIG_CLEANED.md`

### Documentation Changes
- Replace "dataset" with "graph" in all contexts
- Update API endpoint examples
- Update response schema examples
- Update test command examples

## Implementation Strategy

### Immediate Changes (No Backward Compatibility)
Since this is a pre-release product, we can make breaking changes:

1. **Delete** `datasets.py` after creating `graphs.py`
2. **Direct replacement** of all endpoint URLs
3. **Complete model renames** without aliases
4. **Clean test file renames**

### Implementation Order
1. **Week 1**: 
   - Create `graphs.py` route file
   - Update all models and schemas
   - Update `main.py` imports
   - Update test files
   - Update documentation

2. **Future** (when XGT graph API ready):
   - Update XGT integration layer
   - Remove translation layer

## Breaking Changes Summary

### API Endpoints
- All `/datasets` endpoints become `/graphs`
- Parameter `dataset_name` becomes `graph_name`

### Response Models
- `DatasetsResponse.datasets` becomes `GraphsResponse.graphs`
- All model class names change from Dataset* to Graph*

### Client Impact
- All client code must update endpoint URLs
- All response parsing must use new field names
- No migration period - immediate cutover

## Estimated Effort

- **API Layer Changes**: 1-2 days
- **Documentation Updates**: 4-6 hours  
- **Testing & Validation**: 1 day
- **Total**: 2-3 days

## Rollback Plan

If issues arise:
1. Revert git commits for API changes
2. Keep old documentation versions available
3. XGT integration layer unchanged, so minimal backend risk

---

**Status**: Phase 1 Complete ✅  
**Completed**: 
- ✅ Route endpoints updated (/datasets → /graphs)
- ✅ Models renamed and corrected (Graph ≠ Frame)
- ✅ Query endpoints updated
- ✅ Test files updated
- ✅ Core documentation updated

**Next Step**: Ready for Phase 2 when XGT graph API is available  
**Last Updated**: 2025-07-28