#!/usr/bin/env python3
"""
Test MCP Connection to RocketGraph RestAPI

This script tests the MCP connection to verify everything is working correctly.
Run this before connecting Claude to ensure the setup is correct.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

def test_mcp_server():
    """Test if the MCP server starts correctly."""
    print("🚀 Testing MCP Server Connection...")
    
    # Get the RestAPI directory
    restapi_dir = Path(__file__).parent.parent
    
    # Test the MCP server startup
    try:
        # Start the MCP server process
        cmd = [sys.executable, "main.py", "--mcp-only"]
        env = os.environ.copy()
        env['PYTHONPATH'] = str(restapi_dir)
        
        print(f"   Running: {' '.join(cmd)}")
        print(f"   Directory: {restapi_dir}")
        
        process = subprocess.Popen(
            cmd,
            cwd=restapi_dir,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Give it a moment to start
        time.sleep(2)
        
        # Test with a simple MCP request
        test_request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        }
        
        stdout, stderr = process.communicate(
            input=json.dumps(test_request) + "\n",
            timeout=10
        )
        
        if process.returncode == 0:
            print("✅ MCP server started successfully!")
            
            # Try to parse the response
            try:
                lines = stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        response = json.loads(line)
                        if 'result' in response and 'tools' in response['result']:
                            tools = response['result']['tools']
                            print(f"   Found {len(tools)} MCP tools:")
                            for tool in tools:
                                print(f"   - {tool['name']}: {tool['description']}")
                            return True
            except json.JSONDecodeError:
                print("⚠️  Server started but response format unexpected")
                print(f"   stdout: {stdout}")
                return False
                
        else:
            print("❌ MCP server failed to start")
            print(f"   Return code: {process.returncode}")
            print(f"   stderr: {stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ MCP server timed out")
        process.kill()
        return False
    except Exception as e:
        print(f"❌ Error testing MCP server: {e}")
        return False

def check_configuration():
    """Check the configuration settings."""
    print("\n🔧 Checking Configuration...")
    
    try:
        # Add the RestAPI directory to Python path
        restapi_dir = Path(__file__).parent.parent
        sys.path.insert(0, str(restapi_dir))
        
        from app.config.app_config import get_settings
        
        settings = get_settings()
        
        print(f"   MCP Enabled: {settings.MCP_ENABLED}")
        print(f"   XGT Host: {settings.XGT_HOST}")
        print(f"   XGT Port: {settings.XGT_PORT}")
        print(f"   XGT SSL: {settings.XGT_USE_SSL}")
        print(f"   MCP Stdio Mode: {settings.MCP_STDIO_MODE}")
        print(f"   MCP Session Timeout: {settings.MCP_SESSION_TIMEOUT}")
        
        if not settings.MCP_ENABLED:
            print("⚠️  MCP is not enabled! Set MCP_ENABLED=true")
            return False
            
        if not settings.XGT_HOST:
            print("⚠️  XGT_HOST is not configured!")
            return False
            
        print("✅ Configuration looks good!")
        return True
        
    except Exception as e:
        print(f"❌ Error checking configuration: {e}")
        return False

def generate_claude_config():
    """Generate Claude Desktop configuration."""
    print("\n📝 Generating Claude Desktop Configuration...")
    
    restapi_dir = Path(__file__).parent.parent.absolute()
    
    config = {
        "mcpServers": {
            "rocketgraph": {
                "command": "python",
                "args": [str(restapi_dir / "main.py"), "--mcp-only"],
                "env": {
                    "PYTHONPATH": str(restapi_dir)
                }
            }
        }
    }
    
    # Add environment variables if they exist
    env_vars = ["XGT_HOST", "XGT_PORT", "XGT_USE_SSL", "MCP_ENABLED"]
    for var in env_vars:
        if var in os.environ:
            config["mcpServers"]["rocketgraph"]["env"][var] = os.environ[var]
    
    config_json = json.dumps(config, indent=2)
    
    print("   Claude Desktop configuration:")
    print("   " + "\n   ".join(config_json.split("\n")))
    
    # Try to detect Claude Desktop config location
    home = Path.home()
    possible_locations = [
        home / "Library/Application Support/Claude/claude_desktop_config.json",  # macOS
        home / "AppData/Roaming/Claude/claude_desktop_config.json",  # Windows
        home / ".config/claude/claude_desktop_config.json",  # Linux
    ]
    
    for location in possible_locations:
        if location.parent.exists():
            print(f"\n   💡 You can save this to: {location}")
            break
    else:
        print(f"\n   💡 Save this to your Claude Desktop configuration file")
    
    return config_json

def main():
    """Run all tests."""
    print("🧪 RocketGraph MCP Connection Test\n")
    
    # Check if we're in the right directory
    if not (Path.cwd() / "main.py").exists():
        print("❌ Please run this script from the RestAPI directory")
        sys.exit(1)
    
    success = True
    
    # Test configuration
    if not check_configuration():
        success = False
    
    # Test MCP server
    if not test_mcp_server():
        success = False
    
    # Generate Claude config
    generate_claude_config()
    
    if success:
        print("\n🎉 All tests passed! You're ready to connect Claude.")
        print("\nNext steps:")
        print("1. Copy the Claude Desktop configuration above")
        print("2. Restart Claude Desktop")
        print("3. Ask Claude: 'Please list available RocketGraph tools'")
    else:
        print("\n❌ Some tests failed. Please check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()