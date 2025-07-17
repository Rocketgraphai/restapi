#!/usr/bin/env python3
"""
Test JWT validation directly using the PassthroughAuthService.
"""

import sys
import os
sys.path.append('.')

def test_jwt_validation(token):
    """Test JWT validation directly."""
    try:
        from app.auth.passthrough import get_passthrough_auth_service
        from app.config.app_config import get_settings
        
        print("=== JWT Validation Test ===")
        
        # Get the auth service
        auth_service = get_passthrough_auth_service()
        print(f"Auth service created: {type(auth_service)}")
        
        # Get settings to check JWT configuration
        settings = get_settings()
        print(f"JWT Secret Key: {settings.JWT_SECRET_KEY[:20]}...")
        print(f"JWT Algorithm: {settings.JWT_ALGORITHM}")
        
        # Try to validate the token
        print(f"\nValidating token: {token[:50]}...")
        result = auth_service.validate_jwt_token(token)
        
        if result:
            print("✅ Token validation SUCCESS!")
            print(f"Validation result: {result}")
        else:
            print("❌ Token validation FAILED!")
            print("Result is None or False")
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_jwt_validation.py <jwt_token>")
        sys.exit(1)
    
    token = sys.argv[1]
    test_jwt_validation(token)