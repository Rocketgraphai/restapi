#!/usr/bin/env python3
"""
Test script to verify the /auth/me endpoint works with pass-through authentication.
"""

import sys
import requests
import json

def test_auth_me_endpoint(token):
    """Test the /auth/me endpoint with the provided token."""
    
    url = "http://localhost:8000/api/v1/auth/xgt/auth/me"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    try:
        print(f"Testing: GET {url}")
        print(f"Token: {token[:50]}...")
        
        response = requests.get(url, headers=headers)
        
        print(f"\nResponse Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            user_info = response.json()
            print(f"\n✅ SUCCESS!")
            print(f"User Info: {json.dumps(user_info, indent=2)}")
        else:
            print(f"\n❌ FAILED!")
            try:
                error_detail = response.json()
                print(f"Error: {json.dumps(error_detail, indent=2)}")
            except:
                print(f"Error Text: {response.text}")
                
    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Could not connect to localhost:8000")
        print("Make sure the API server is running with: python main.py")
    except Exception as e:
        print(f"❌ ERROR: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_auth_endpoint.py <jwt_token>")
        sys.exit(1)
    
    token = sys.argv[1]
    test_auth_me_endpoint(token)