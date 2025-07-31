# Claude Usage Examples with RocketGraph MCP

This document provides real examples of how to interact with RocketGraph through Claude using MCP.

## Basic Authentication and Setup

### Example 1: First Connection

**User**: "Hi Claude, I need to connect to RocketGraph to analyze some graph data. Can you help me get started?"

**Claude Response**: "I'll help you connect to RocketGraph! First, I need to authenticate you with the graph database. I can see the RocketGraph MCP tools are available. 

What type of authentication would you like to use?
- Basic authentication (username/password)
- PKI authentication (certificates)
- Proxy PKI authentication

Please provide your credentials and I'll get you connected."

**User**: "Use basic auth. My username is 'analyst' and password is 'graph2024'"

**Claude will then**:
1. Use the `rocketgraph_authenticate` tool with the provided credentials
2. Store the session ID for subsequent operations
3. Confirm successful authentication

## Schema Discovery Examples

### Example 2: Exploring Available Data

**User**: "What graphs are available for me to analyze?"

**Claude Response**: "Let me check what graphs are available in your RocketGraph instance."

```
[Claude uses rocketgraph_list_graphs tool]
```

**Claude Output**: "I found 3 graphs available to you:

1. **CustomerGraph** - Contains 15,432 customer nodes and 89,234 transaction edges
2. **SocialNetwork** - Contains 8,901 user nodes and 45,678 friendship edges  
3. **SupplyChain** - Contains 2,341 supplier nodes and 12,567 shipment edges

Which graph would you like to explore first?"

### Example 3: Schema Analysis

**User**: "Show me the detailed schema for the CustomerGraph"

**Claude Response**: "I'll get the detailed schema for CustomerGraph."

```
[Claude uses rocketgraph_schema tool with dataset_name="CustomerGraph"]
```

**Claude Output**: "Here's the schema for CustomerGraph:

**Node Types:**
- **Customer** (5,432 nodes)
  - id: TEXT (primary key)
  - name: TEXT
  - email: TEXT
  - registration_date: DATETIME
  - total_spent: FLOAT
  - risk_score: INTEGER

- **Account** (12,891 nodes)
  - account_id: TEXT (primary key)
  - account_type: TEXT
  - balance: FLOAT
  - created_date: DATETIME
  - status: TEXT

**Edge Types:**
- **OWNS** (Customer → Account)
  - relationship_date: DATETIME
  - ownership_type: TEXT

- **TRANSACTION** (Account → Account)
  - amount: FLOAT
  - transaction_date: DATETIME
  - transaction_type: TEXT
  - status: TEXT

This looks like a financial analysis dataset. What kind of analysis would you like to perform?"

## Query Examples

### Example 4: Simple Data Exploration

**User**: "Show me the top 10 customers by total spending"

**Claude Response**: "I'll query the CustomerGraph to find the top spenders."

```cypher
MATCH (c:Customer) 
RETURN c.name, c.total_spent 
ORDER BY c.total_spent DESC 
LIMIT 10
```

**Claude Output**: "Here are the top 10 customers by total spending:

1. Sarah Johnson - $45,230.50
2. Michael Chen - $38,920.25
3. Emma Rodriguez - $32,180.75
4. David Kim - $29,450.00
5. Lisa Wang - $27,335.50
6. James Thompson - $25,890.25
7. Maria Garcia - $24,560.75
8. Robert Lee - $23,120.00
9. Jennifer Taylor - $22,890.50
10. Alex Brown - $21,775.25

These customers represent your highest-value segment. Would you like to analyze their transaction patterns or demographics?"

### Example 5: Complex Analysis

**User**: "Find customers who have made large transactions (over $10,000) in the last 30 days and show their risk profiles"

**Claude Response**: "I'll analyze recent large transactions and associated customer risk profiles."

```cypher
MATCH (c:Customer)-[:OWNS]->(a1:Account)-[t:TRANSACTION]->(a2:Account)
WHERE t.amount > 10000 
  AND t.transaction_date > datetime() - duration({days: 30})
  AND t.status = 'COMPLETED'
RETURN c.name, c.risk_score, t.amount, t.transaction_date, t.transaction_type
ORDER BY t.amount DESC
```

**Claude Output**: "Found 23 customers with large transactions in the last 30 days:

**High Risk (Score 7-10):**
- Michael Chen (Risk: 8) - $25,000 wire transfer on 2024-01-15
- David Kim (Risk: 9) - $18,500 international transfer on 2024-01-12  
- Alex Brown (Risk: 7) - $15,200 cash withdrawal on 2024-01-18

**Medium Risk (Score 4-6):**
- Sarah Johnson (Risk: 5) - $22,000 business payment on 2024-01-20
- Emma Rodriguez (Risk: 4) - $12,800 investment transfer on 2024-01-16

**Low Risk (Score 1-3):**
- Lisa Wang (Risk: 2) - $11,500 mortgage payment on 2024-01-14
- Jennifer Taylor (Risk: 3) - $10,200 loan repayment on 2024-01-19

⚠️ **Alert**: 3 high-risk customers made large transactions. Would you like me to investigate their transaction networks or patterns?"

## Advanced Analytics Examples

### Example 6: Network Analysis

**User**: "Analyze the transaction network to find potential money laundering patterns"

**Claude Response**: "I'll analyze the transaction network for suspicious patterns that might indicate money laundering."

```cypher
// Find circular transaction patterns
MATCH path = (a1:Account)-[:TRANSACTION*3..5]->(a1)
WHERE all(r in relationships(path) WHERE r.amount > 5000)
  AND all(r in relationships(path) WHERE r.transaction_date > datetime() - duration({days: 90}))
RETURN 
  [n in nodes(path) | n.account_id] as account_cycle,
  [r in relationships(path) | r.amount] as amounts,
  length(path) as cycle_length,
  reduce(total = 0, r in relationships(path) | total + r.amount) as total_amount
ORDER BY total_amount DESC
LIMIT 10
```

**Claude Output**: "🚨 **Suspicious Activity Detected**

Found 7 potential circular transaction patterns:

**High Priority Alerts:**
1. **Circular Pattern A**: 4 accounts, $89,500 total
   - Accounts: ACC_1234 → ACC_5678 → ACC_9012 → ACC_1234  
   - Pattern: $25K → $30K → $34.5K (3-hop cycle)
   - Timeframe: Last 15 days

2. **Circular Pattern B**: 3 accounts, $67,200 total
   - Accounts: ACC_2468 → ACC_1357 → ACC_2468
   - Pattern: $32K → $35.2K (2-hop cycle)  
   - Timeframe: Last 8 days

**Recommendations:**
- Flag these accounts for manual review
- Check customer backgrounds for these account holders
- Monitor for additional suspicious patterns

Would you like me to investigate the customers associated with these accounts?"

### Example 7: Frame Data Inspection

**User**: "Show me some sample transaction data to understand the data quality"

**Claude Response**: "I'll retrieve sample transaction data to show you the data structure and quality."

```
[Claude uses rocketgraph_frame_data tool with frame_name="TRANSACTION", limit=20]
```

**Claude Output**: "Here's a sample of transaction data (20 records):

| Transaction ID | From Account | To Account | Amount | Date | Type | Status |
|----------------|--------------|------------|--------|------|------|--------|
| TXN_001 | ACC_1234 | ACC_5678 | $2,500.00 | 2024-01-20 | TRANSFER | COMPLETED |
| TXN_002 | ACC_5678 | ACC_9012 | $1,200.50 | 2024-01-20 | PAYMENT | COMPLETED |
| TXN_003 | ACC_2468 | ACC_1357 | $15,000.00 | 2024-01-19 | WIRE | PENDING |
| ... | ... | ... | ... | ... | ... | ... |

**Data Quality Assessment:**
✅ **Good**: All required fields populated  
✅ **Good**: Consistent date formats  
✅ **Good**: Valid amount ranges  
⚠️ **Note**: 3 transactions show 'PENDING' status from yesterday  

The data looks clean and well-structured for analysis. Would you like to explore any specific aspects?"

## Troubleshooting Examples

### Example 8: Authentication Issues

**User**: "I'm getting authentication errors"

**Claude Response**: "Let me help troubleshoot the authentication issue. I'll try to reconnect and provide diagnostic information."

```
[Claude attempts rocketgraph_authenticate and analyzes the error]
```

**Claude Output**: "I see the authentication failed with error: 'Invalid credentials for user analyst'

**Troubleshooting steps:**
1. ✅ MCP connection is working
2. ❌ Authentication failed - check credentials
3. Possible issues:
   - Username/password incorrect
   - Account may be locked
   - XGT server connectivity issues

Please verify:
- Is your username 'analyst' correct?
- Has your password changed recently?
- Can you access XGT through other tools?

Would you like to try different credentials or authentication method?"

## Visualization and Reporting

### Example 9: Creating Reports

**User**: "Generate a summary report of customer transaction patterns for this month"

**Claude Response**: "I'll analyze the transaction patterns and create a comprehensive report."

```
[Claude runs multiple queries to gather data]
```

**Claude Output**: 

# 📊 Customer Transaction Report - January 2024

## Executive Summary
- **Total Transactions**: 45,678 (↑12% vs last month)
- **Total Volume**: $12.4M (↑8% vs last month)  
- **Average Transaction**: $271.50
- **Active Customers**: 3,892 (↑5% vs last month)

## Key Insights

### 🔥 Top Trends
1. **Digital Payments Growth**: 67% of transactions now digital (↑15%)
2. **International Transfers**: $2.1M volume (↑25%)
3. **High-Value Transactions**: 234 transactions >$10K (↑18%)

### ⚠️ Risk Indicators  
- 7 suspicious circular patterns detected
- 12 customers exceeded daily limits
- 3 accounts flagged for unusual activity

### 💰 Revenue Impact
- **Top 100 customers**: Generated 43% of total volume
- **New customers**: 289 acquired this month
- **Churned customers**: 67 (retention rate: 98.3%)

## Recommendations
1. **Immediate**: Review flagged accounts within 24 hours
2. **Short-term**: Implement enhanced monitoring for high-value transactions  
3. **Long-term**: Develop predictive models for fraud detection

Would you like me to dive deeper into any of these areas or export this data for further analysis?"

## Integration Examples

### Example 10: Automated Monitoring

**User**: "Set up monitoring for suspicious activity patterns"

**Claude Response**: "I'll help you set up queries that can be used for ongoing monitoring of suspicious patterns. Here are the key monitoring queries I recommend:

**Daily Monitoring Queries:**

1. **Large Transaction Alert** (Run daily):
```cypher
MATCH (c:Customer)-[:OWNS]->(a1:Account)-[t:TRANSACTION]->(a2:Account)
WHERE t.amount > 15000 
  AND t.transaction_date > datetime() - duration({days: 1})
RETURN c.name, t.amount, t.transaction_date, c.risk_score
ORDER BY t.amount DESC
```

2. **Velocity Check** (Unusual activity volume):
```cypher
MATCH (c:Customer)-[:OWNS]->(a:Account)-[t:TRANSACTION]->()
WHERE t.transaction_date > datetime() - duration({days: 1})
WITH c, count(t) as daily_txns, avg(t.amount) as avg_amount
WHERE daily_txns > 20 OR avg_amount > 5000
RETURN c.name, daily_txns, avg_amount, c.risk_score
ORDER BY daily_txns DESC
```

I can run these queries for you regularly, or you can integrate them into your monitoring systems. Would you like me to execute these checks now?"

These examples show how Claude can serve as an intelligent interface to your graph data, providing both ad-hoc analysis and structured reporting capabilities through the MCP integration.