#!/usr/bin/env python3
"""
Debug script to test JWT token validation for pass-through authentication.
"""

import sys
import jwt as pyjwt  # Make sure we're using PyJWT
import json
from datetime import datetime

def decode_token(token_string):
    """Decode and inspect a JWT token."""
    try:
        # Remove 'Bearer ' prefix if present
        if token_string.startswith('Bearer '):
            token_string = token_string[7:]
        
        # Decode without verification first to see the content
        print("=== JWT Token Analysis ===")
        print(f"Token: {token_string[:50]}...")
        
        # Decode header
        header = pyjwt.get_unverified_header(token_string)
        print(f"\nHeader: {json.dumps(header, indent=2)}")
        
        # Decode payload (without signature verification)
        payload = pyjwt.decode(token_string, options={"verify_signature": False})
        print(f"\nPayload: {json.dumps(payload, indent=2)}")
        
        # Check expiration
        if 'exp' in payload:
            exp_time = datetime.fromtimestamp(payload['exp'])
            now = datetime.now()
            print(f"\nExpiration: {exp_time}")
            print(f"Current time: {now}")
            print(f"Token expired: {now > exp_time}")
        
        # Check XGT credentials
        if 'xgt_credentials' in payload:
            print(f"\nXGT credentials present: Yes")
            print(f"Credentials length: {len(payload['xgt_credentials'])}")
        else:
            print(f"\nXGT credentials present: No")
        
        return payload
        
    except Exception as e:
        print(f"Error decoding token: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python debug_token.py <jwt_token>")
        sys.exit(1)
    
    token = sys.argv[1]
    decode_token(token)