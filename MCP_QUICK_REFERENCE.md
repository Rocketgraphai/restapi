# RocketGraph MCP Quick Reference

## Connection Modes

**Mode 1**: Claude launches MCP server (simple setup)
- No server startup needed
- Claude manages the process automatically

**Mode 2**: Connect to persistent server (production)
- Server runs continuously  
- Better for teams and monitoring

## Quick Setup Commands

```bash
# Option A: Let Claude launch server (no commands needed)
# Just configure Claude Desktop - see below

# Option B: Run persistent server
python main.py --hybrid     # REST + MCP (recommended)
python main.py --mcp-only   # MCP only
python main.py --rest-only  # REST only

# Test MCP functionality
echo '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' | python main.py --mcp-only
```

## Claude Desktop Configuration

**File**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "rocketgraph": {
      "command": "python",
      "args": ["/path/to/restapi/main.py", "--mcp-only"],
      "env": {
        "PYTHONPATH": "/path/to/restapi",
        "XGT_HOST": "your-xgt-server.com",
        "XGT_PORT": "4367",
        "MCP_ENABLED": "true"
      }
    }
  }
}
```

## Common Claude Prompts

### Authentication
```
Please authenticate with RocketGraph using:
- Username: analyst
- Password: mypassword
- Auth type: basic
```

### Schema Exploration
```
Show me the schema for all available graphs in RocketGraph
```

```
What's the structure of the CustomerGraph dataset?
```

### Data Queries
```
Find the top 10 customers by transaction volume in the last month
```

```
Show me all fraud patterns in the transaction network
```

```
List all connected components in the social network graph
```

### Frame Data Inspection
```
Show me sample data from the Customer frame (first 20 rows)
```

## Environment Variables Quick Reference

```bash
# Essential settings
export XGT_HOST="xgt-server.company.com"
export XGT_PORT="4367"
export XGT_USE_SSL="true"
export MCP_ENABLED="true"

# Optional MCP settings
export MCP_SESSION_TIMEOUT="3600"           # 1 hour
export MCP_MAX_CONCURRENT_SESSIONS="10"     # Max sessions
export MCP_MAX_QUERY_TIME="300"             # 5 minutes
export MCP_MAX_RESULT_ROWS="10000"          # Max rows per query
```

## MCP Tools Overview

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `rocketgraph_authenticate` | Login to XGT | `auth_type`, `username`, `password` |
| `rocketgraph_query` | Execute Cypher queries | `query`, `session_id`, `parameters` |
| `rocketgraph_schema` | Get graph schemas | `session_id`, `dataset_name` |
| `rocketgraph_list_graphs` | List available graphs | `session_id` |
| `rocketgraph_frame_data` | Get sample data | `session_id`, `frame_name`, `limit` |

## Troubleshooting Commands

```bash
# Check if MCP server starts
python main.py --mcp-only 2>&1 | head -20

# Test XGT connection
python -c "
import os
os.environ['PYTHONPATH'] = '.'
from app.utils.xgt_operations import test_xgt_connection
test_xgt_connection()
"

# Check configuration
python -c "
from app.config.app_config import get_settings
settings = get_settings()
print(f'MCP Enabled: {settings.MCP_ENABLED}')
print(f'XGT Host: {settings.XGT_HOST}:{settings.XGT_PORT}')
"

# Debug mode
export LOG_LEVEL=DEBUG
python main.py --mcp-only
```

## Common Error Solutions

| Error | Solution |
|-------|----------|
| "MCP server not responding" | Check command path, ensure `python main.py --mcp-only` works |
| "Authentication failed" | Verify XGT credentials and server connectivity |
| "No graphs found" | Check user permissions and namespace access |
| "Query timeout" | Increase `MCP_MAX_QUERY_TIME` or optimize query |
| "Import error" | Set `PYTHONPATH` to RestAPI directory |

## Example Cypher Queries

```cypher
-- Find all customers
MATCH (c:Customer) RETURN c.name, c.id LIMIT 10

-- Transaction analysis
MATCH (c:Customer)-[:MADE_TRANSACTION]->(t:Transaction)
WHERE t.amount > 1000
RETURN c.name, sum(t.amount) as total_volume
ORDER BY total_volume DESC LIMIT 10

-- Network analysis
MATCH (a:Account)-[:TRANSFER]->(b:Account)
RETURN a.id, b.id, count(*) as transfer_count
ORDER BY transfer_count DESC LIMIT 20

-- Fraud detection
MATCH (c:Customer)-[:OWNS]->(a:Account)-[:SUSPICIOUS_ACTIVITY]->(s:Alert)
RETURN c.name, count(s) as alert_count
ORDER BY alert_count DESC LIMIT 5
```

## Performance Tips

1. **Use LIMIT** in queries to avoid large result sets
2. **Index frequently queried properties** in XGT
3. **Set appropriate timeouts** for complex analytics
4. **Monitor session usage** with multiple concurrent users
5. **Use parameters** for repeated queries with different values

## Security Checklist

- [ ] Use environment variables for credentials
- [ ] Enable SSL for XGT connections (`XGT_USE_SSL=true`)
- [ ] Set appropriate query timeouts
- [ ] Limit result set sizes
- [ ] Monitor authentication logs
- [ ] Restrict network access to authorized users
- [ ] Use PKI authentication in production environments