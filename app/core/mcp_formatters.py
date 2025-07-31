"""
Result formatters for MCP (Model Context Protocol) responses.

Formats XGT query results and schema information for optimal consumption by Claude.
"""

import logging
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class MCPResultFormatter:
    """Formatter for converting XGT results to Claude-friendly formats."""
    
    @staticmethod
    def format_query_results(
        results: List[Any], 
        columns: Optional[List[str]] = None,
        execution_time_ms: Optional[float] = None,
        total_rows: Optional[int] = None
    ) -> str:
        """
        Format graph query results for optimal Claude consumption.
        
        Args:
            results: Query results as list of rows
            columns: Column names
            execution_time_ms: Query execution time in milliseconds
            total_rows: Total number of rows available
            
        Returns:
            Formatted string optimized for Claude understanding
        """
        if not results:
            output = "Query executed successfully.\nNo results returned."
            if execution_time_ms is not None:
                output = f"Query executed successfully in {execution_time_ms:.2f}ms.\nNo results returned."
            return output
        
        # Build header with execution info
        output_lines = []
        if execution_time_ms is not None:
            output_lines.append(f"Query executed successfully in {execution_time_ms:.2f}ms")
        else:
            output_lines.append("Query executed successfully")
            
        row_count = len(results)
        if total_rows is not None and total_rows != row_count:
            output_lines.append(f"Showing {row_count} of {total_rows} total rows")
        else:
            output_lines.append(f"Returned {row_count} rows")
        
        output_lines.append("")  # Empty line before results
        
        # Determine if we should show full table or summary
        if row_count <= 20:
            # Small result sets: show full table
            output_lines.append(MCPResultFormatter._format_as_table(results, columns))
        else:
            # Large result sets: show summary + sample
            output_lines.append(MCPResultFormatter._format_summary(results, columns))
            output_lines.append("")
            output_lines.append("Sample rows (first 10):")
            output_lines.append(MCPResultFormatter._format_as_table(results[:10], columns))
        
        return "\n".join(output_lines)
    
    @staticmethod
    def _format_as_table(results: List[Any], columns: Optional[List[str]] = None) -> str:
        """
        Format results as a table with proper alignment.
        
        Args:
            results: Query results
            columns: Column names
            
        Returns:
            Formatted table string
        """
        if not results:
            return "No data to display."
        
        # Handle different result formats
        if isinstance(results[0], dict):
            # Results are dictionaries
            if not columns:
                columns = list(results[0].keys())
            rows = [[str(row.get(col, "")) for col in columns] for row in results]
        elif isinstance(results[0], (list, tuple)):
            # Results are already lists/tuples
            rows = [[str(cell) for cell in row] for row in results]
            if not columns:
                columns = [f"col_{i}" for i in range(len(rows[0]))] if rows else []
        else:
            # Results are single values
            rows = [[str(row)] for row in results]
            columns = columns or ["value"]
        
        if not columns:
            columns = [f"col_{i}" for i in range(len(rows[0]))] if rows else []
        
        # Calculate column widths
        col_widths = [len(header) for header in columns]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Build table
        table_lines = []
        
        # Header
        header_row = " | ".join(h.ljust(w) for h, w in zip(columns, col_widths))
        table_lines.append(header_row)
        table_lines.append("-" * len(header_row))
        
        # Data rows
        for row in rows:
            # Ensure row has same length as columns
            padded_row = row + [""] * (len(columns) - len(row))
            data_row = " | ".join(str(cell).ljust(w) for cell, w in zip(padded_row, col_widths))
            table_lines.append(data_row)
        
        return "\n".join(table_lines)
    
    @staticmethod
    def _format_summary(results: List[Any], columns: Optional[List[str]] = None) -> str:
        """
        Format a summary of large result sets.
        
        Args:
            results: Query results
            columns: Column names
            
        Returns:
            Summary string
        """
        if not results:
            return "No data to summarize."
        
        summary_lines = []
        
        # Basic stats
        summary_lines.append(f"Result Summary:")
        summary_lines.append(f"- Total rows: {len(results)}")
        
        # Column information
        if columns:
            summary_lines.append(f"- Columns ({len(columns)}): {', '.join(columns)}")
        elif isinstance(results[0], dict):
            keys = list(results[0].keys())
            summary_lines.append(f"- Columns ({len(keys)}): {', '.join(keys)}")
        elif isinstance(results[0], (list, tuple)):
            summary_lines.append(f"- Columns: {len(results[0])} columns")
        
        return "\n".join(summary_lines)
    
    @staticmethod
    def format_schema_info(schema_data: Dict[str, Any]) -> str:
        """
        Format schema information for Claude.
        
        Args:
            schema_data: Schema information from XGT
            
        Returns:
            Formatted schema string
        """
        output_lines = []
        output_lines.append("Graph Schema Information")
        output_lines.append("=" * 25)
        output_lines.append("")
        
        # Graph name
        if "graph" in schema_data and schema_data["graph"]:
            output_lines.append(f"Graph: {schema_data['graph']}")
            output_lines.append("")
        
        # Node information
        if "nodes" in schema_data and schema_data["nodes"]:
            output_lines.append("Node Types:")
            for node in schema_data["nodes"]:
                output_lines.append(f"- {node.get('name', 'Unknown')}")
                if "properties" in node and node["properties"]:
                    for prop in node["properties"]:
                        prop_name = prop.get("name", "unknown")
                        prop_type = prop.get("type", "unknown")
                        output_lines.append(f"  • {prop_name}: {prop_type}")
                if "key" in node:
                    output_lines.append(f"  Key: {node['key']}")
                output_lines.append("")
        
        # Edge information
        if "edges" in schema_data and schema_data["edges"]:
            output_lines.append("Relationship Types:")
            for edge in schema_data["edges"]:
                edge_name = edge.get("name", "Unknown")
                source = edge.get("source", "Unknown")
                target = edge.get("target", "Unknown")
                output_lines.append(f"- {edge_name}: ({source}) -> ({target})")
                
                if "properties" in edge and edge["properties"]:
                    for prop in edge["properties"]:
                        prop_name = prop.get("name", "unknown")
                        prop_type = prop.get("type", "unknown")
                        output_lines.append(f"  • {prop_name}: {prop_type}")
                output_lines.append("")
        
        # Additional metadata
        if "nodes" in schema_data:
            node_count = len(schema_data["nodes"])
            output_lines.append(f"Total Node Types: {node_count}")
        
        if "edges" in schema_data:
            edge_count = len(schema_data["edges"])
            output_lines.append(f"Total Relationship Types: {edge_count}")
        
        return "\n".join(output_lines)
    
    @staticmethod
    def format_frame_data(frame_data: Dict[str, Any]) -> str:
        """
        Format frame data information for Claude.
        
        Args:
            frame_data: Frame data from XGT
            
        Returns:
            Formatted frame data string
        """
        output_lines = []
        
        frame_name = frame_data.get("frame_name", "Unknown")
        frame_type = frame_data.get("frame_type", "unknown")
        namespace = frame_data.get("namespace")
        
        output_lines.append(f"Frame: {frame_name}")
        output_lines.append(f"Type: {frame_type}")
        if namespace:
            output_lines.append(f"Namespace: {namespace}")
        
        total_rows = frame_data.get("total_rows", 0)
        returned_rows = frame_data.get("returned_rows", 0)
        output_lines.append(f"Total Rows: {total_rows}")
        output_lines.append(f"Showing: {returned_rows} rows")
        output_lines.append("")
        
        # Show data if available
        if "rows" in frame_data and frame_data["rows"]:
            columns = frame_data.get("columns", [])
            rows = frame_data["rows"]
            
            # Format as table
            table_str = MCPResultFormatter._format_as_table(rows, columns)
            output_lines.append(table_str)
        else:
            output_lines.append("No data available.")
        
        return "\n".join(output_lines)
    
    @staticmethod
    def format_error_message(error: Exception, context: str = "") -> str:
        """
        Format error messages for Claude consumption.
        
        Args:
            error: The exception that occurred
            context: Additional context about the error
            
        Returns:
            Formatted error message
        """
        error_lines = []
        
        if context:
            error_lines.append(f"Error in {context}:")
        else:
            error_lines.append("Error occurred:")
        
        error_lines.append(f"- Type: {type(error).__name__}")
        error_lines.append(f"- Message: {str(error)}")
        
        return "\n".join(error_lines)