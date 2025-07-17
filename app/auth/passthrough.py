"""
Pass-through authentication service for XGT credentials.

Handles authentication by testing XGT connections with user credentials
and generating JWT tokens containing encrypted XGT connection information.
"""

import logging
import base64
import tempfile
import os
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union
from cryptography.fernet import Fernet
from cachetools import TTLCache

# Dynamic JWT import to avoid conflicts
JWT_AVAILABLE = False
pyjwt = None

def _get_jwt_module():
    """Dynamically import JWT to avoid module conflicts."""
    global pyjwt, JWT_AVAILABLE
    if pyjwt is None:
        try:
            import importlib
            pyjwt = importlib.import_module('jwt')
            JWT_AVAILABLE = True
        except ImportError:
            JWT_AVAILABLE = False
            pyjwt = None
    return pyjwt

from ..config.app_config import get_settings
from ..utils.exceptions import XGTConnectionError, XGTOperationError
from .passthrough_models import XGTAuthType, XGTBasicAuthRequest, XGTPKIAuthRequest, XGTProxyPKIAuthRequest

# XGT imports
try:
    import xgt
except ImportError:
    xgt = None

logger = logging.getLogger(__name__)


class XGTCredentials:
    """Encrypted XGT credentials for secure storage in JWT tokens."""
    
    def __init__(self, auth_type: XGTAuthType, encryption_key: str, **auth_data):
        self.auth_type = auth_type
        self.auth_data = auth_data
        self._fernet = Fernet(self._derive_fernet_key(encryption_key))
    
    def encrypt(self) -> str:
        """Encrypt credentials for JWT storage."""
        credentials_data = {
            'auth_type': self.auth_type.value,
            'auth_data': self.auth_data
        }
        import json
        encrypted = self._fernet.encrypt(json.dumps(credentials_data).encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    @classmethod
    def decrypt(cls, encrypted_data: str, encryption_key: str) -> 'XGTCredentials':
        """Decrypt credentials from JWT token."""
        fernet = Fernet(cls._derive_fernet_key(encryption_key))
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted = fernet.decrypt(encrypted_bytes).decode()
        import json
        credentials_data = json.loads(decrypted)
        return cls(
            auth_type=XGTAuthType(credentials_data['auth_type']),
            encryption_key=encryption_key,
            **credentials_data['auth_data']
        )
    
    @staticmethod
    def _derive_fernet_key(secret_key: str) -> bytes:
        """Derive a valid Fernet key from any string."""
        # Use SHA256 to create a 32-byte key, then base64 encode it
        key_hash = hashlib.sha256(secret_key.encode()).digest()
        return base64.urlsafe_b64encode(key_hash)
    
    @property
    def username(self) -> Optional[str]:
        """Get username from auth data."""
        if self.auth_type == XGTAuthType.BASIC:
            return self.auth_data.get('username')
        elif self.auth_type == XGTAuthType.PROXY_PKI:
            return self.auth_data.get('user_id')
        elif self.auth_type == XGTAuthType.PKI:
            # For PKI, username would be extracted from certificate
            return self.auth_data.get('extracted_username')
        return None


class PassthroughAuthService:
    """Service for XGT pass-through authentication."""
    
    def __init__(self):
        self.settings = get_settings()
        # Cache for connection validation (username -> validation result)
        self._connection_cache = TTLCache(maxsize=100, ttl=300)  # 5 min TTL
    
    def authenticate_xgt_user(self, auth_request: Union[XGTBasicAuthRequest, XGTPKIAuthRequest, XGTProxyPKIAuthRequest]) -> Dict[str, Any]:
        """
        Authenticate user by testing XGT connection with their credentials.
        
        Args:
            auth_request: Authentication request (Basic, PKI, or Proxy PKI)
            
        Returns:
            Authentication result with user info and JWT token
            
        Raises:
            XGTConnectionError: If XGT connection fails
            XGTOperationError: If authentication fails
        """
        if xgt is None:
            raise XGTConnectionError("XGT library not available")
        
        try:
            # Create XGT auth object based on request type
            if isinstance(auth_request, XGTBasicAuthRequest):
                auth_obj, username, auth_data = self._create_basic_auth(auth_request)
            elif isinstance(auth_request, XGTPKIAuthRequest):
                auth_obj, username, auth_data = self._create_pki_auth(auth_request)
            elif isinstance(auth_request, XGTProxyPKIAuthRequest):
                auth_obj, username, auth_data = self._create_proxy_pki_auth(auth_request)
            else:
                raise XGTOperationError(f"Unsupported authentication type: {type(auth_request)}")
            
            # Test XGT connection using context manager approach
            connection = None
            try:
                connection = xgt.Connection(
                    host=self.settings.XGT_HOST,
                    port=self.settings.XGT_PORT,
                    auth=auth_obj,
                    flags=self._get_connection_flags(auth_request)
                )
                
                # Get user information from XGT
                user_info = self._get_xgt_user_info(connection, username)
                
            finally:
                # Close test connection safely
                if connection:
                    try:
                        if hasattr(connection, 'close'):
                            connection.close()
                        elif hasattr(connection, '__del__'):
                            del connection
                    except:
                        pass  # Ignore close errors
            
            # Create encrypted credentials
            logger.debug(f"Creating encrypted credentials for user: {username}")
            credentials = XGTCredentials(
                auth_type=auth_request.auth_type,
                encryption_key=self.settings.SECRET_KEY,
                **auth_data
            )
            logger.debug("Credentials created successfully")
            
            # Generate JWT token with encrypted credentials
            logger.debug("Generating JWT token")
            jwt_token = self._generate_jwt_token(username, credentials, user_info)
            logger.debug("JWT token generated successfully")
            
            logger.info(f"XGT user {username} authenticated successfully with {auth_request.auth_type}")
            
            return {
                'success': True,
                'access_token': jwt_token,
                'token_type': 'bearer',
                'expires_in': self.settings.JWT_EXPIRY_SECONDS,
                'user_info': {
                    'username': username,
                    'namespace': user_info.get('namespace'),
                    'authenticated_at': datetime.utcnow().isoformat(),
                    'auth_type': auth_request.auth_type.value
                }
            }
            
        except Exception as e:
            username = getattr(auth_request, 'username', getattr(auth_request, 'user_id', 'unknown'))
            logger.error(f"XGT authentication failed for user {username}: {e}")
            if "authentication" in str(e).lower() or "unauthorized" in str(e).lower():
                raise XGTOperationError(f"Invalid XGT credentials for user {username}")
            elif "connection" in str(e).lower():
                raise XGTConnectionError(f"Cannot connect to XGT server: {e}")
            else:
                raise XGTOperationError(f"XGT authentication error: {e}")
    
    def _create_basic_auth(self, auth_request: XGTBasicAuthRequest) -> tuple:
        """Create XGT BasicAuth object."""
        try:
            auth_obj = xgt.BasicAuth(username=auth_request.username, password=auth_request.password)
            auth_data = {
                'username': auth_request.username,
                'password': auth_request.password
            }
            logger.debug(f"Created BasicAuth for user: {auth_request.username}")
            return auth_obj, auth_request.username, auth_data
        except Exception as e:
            logger.error(f"Failed to create BasicAuth: {e}")
            raise XGTOperationError(f"BasicAuth creation failed: {e}")
    
    def _create_pki_auth(self, auth_request: XGTPKIAuthRequest) -> tuple:
        """Create XGT PKI auth object."""
        # Decode base64 certificates and save to temporary files
        temp_dir = tempfile.mkdtemp(prefix="xgt_pki_")
        
        try:
            # Decode and save client certificate
            client_cert_path = os.path.join(temp_dir, "client.cert.pem")
            with open(client_cert_path, 'wb') as f:
                f.write(base64.b64decode(auth_request.client_cert))
            
            # Decode and save client private key
            client_key_path = os.path.join(temp_dir, "client.key.pem")
            with open(client_key_path, 'wb') as f:
                f.write(base64.b64decode(auth_request.client_key))
            
            # Decode and save CA chain if provided
            ca_chain_path = None
            if auth_request.ca_chain:
                ca_chain_path = os.path.join(temp_dir, "ca-chain.cert.pem")
                with open(ca_chain_path, 'wb') as f:
                    f.write(base64.b64decode(auth_request.ca_chain))
            
            # Extract username from certificate
            username = self._extract_username_from_cert(client_cert_path)
            
            # Create PKI auth object
            if ca_chain_path:
                auth_obj = xgt.PKIAuth(ssl_root_dir=temp_dir)
            else:
                auth_obj = xgt.PKIAuth(
                    ssl_client_cert=client_cert_path,
                    ssl_client_key=client_key_path,
                    ssl_server_cert=auth_request.ssl_server_cert
                )
            
            # Store auth data for credentials
            auth_data = {
                'client_cert': auth_request.client_cert,
                'client_key': auth_request.client_key,
                'ca_chain': auth_request.ca_chain,
                'ssl_server_cert': auth_request.ssl_server_cert,
                'ssl_server_cn': auth_request.ssl_server_cn,
                'extracted_username': username,
                'temp_dir': temp_dir  # Keep track for cleanup
            }
            
            return auth_obj, username, auth_data
            
        except Exception as e:
            # Cleanup temp directory on error
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise XGTOperationError(f"PKI authentication setup failed: {e}")
    
    def _create_proxy_pki_auth(self, auth_request: XGTProxyPKIAuthRequest) -> tuple:
        """Create XGT Proxy PKI auth object."""
        # For proxy PKI, we validate the proxy signature and certificate hash
        if not self._validate_proxy_pki_signature(auth_request):
            raise XGTOperationError("Proxy PKI signature validation failed")
        
        # Create ProxyPKIAuth object
        auth_obj = xgt.ProxyPKIAuth(
            user_id=auth_request.user_id,
            proxy_host=auth_request.proxy_host
        )
        
        auth_data = {
            'user_id': auth_request.user_id,
            'proxy_host': auth_request.proxy_host,
            'certificate_hash': auth_request.certificate_hash,
            'proxy_signature': auth_request.proxy_signature
        }
        
        return auth_obj, auth_request.user_id, auth_data
    
    def _get_connection_flags(self, auth_request) -> Dict[str, Any]:
        """Get connection flags based on auth type."""
        flags = {}
        
        if isinstance(auth_request, (XGTPKIAuthRequest, XGTProxyPKIAuthRequest)):
            # PKI requires SSL
            flags['ssl'] = True
            if hasattr(auth_request, 'ssl_server_cn') and auth_request.ssl_server_cn:
                flags['ssl_server_cn'] = auth_request.ssl_server_cn
        elif self.settings.XGT_USE_SSL:
            # Basic auth with SSL if configured
            flags = {
                'ssl': True,
                'ssl_server_cert': self.settings.XGT_SSL_CERT,
                'ssl_server_cn': self.settings.XGT_SERVER_CN
            }
        
        return flags
    
    def _extract_username_from_cert(self, cert_path: str) -> str:
        """Extract username/userId from PKI certificate."""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Look for userId in certificate subject
            for attribute in certificate.subject:
                if attribute.oid._name == 'userId' or attribute.oid.dotted_string == '0.9.2342.19200300.100.1.1':
                    return attribute.value
            
            # Fallback to common name if userId not found
            for attribute in certificate.subject:
                if attribute.oid._name == 'commonName':
                    return attribute.value
            
            raise XGTOperationError("No userId or commonName found in certificate")
            
        except ImportError:
            raise XGTOperationError("cryptography library required for PKI authentication")
        except Exception as e:
            raise XGTOperationError(f"Failed to extract username from certificate: {e}")
    
    def _validate_proxy_pki_signature(self, auth_request: XGTProxyPKIAuthRequest) -> bool:
        """Validate proxy PKI signature."""
        # Implementation would depend on your proxy PKI validation logic
        # For now, return True as placeholder
        logger.warning("Proxy PKI signature validation not implemented - accepting all requests")
        return True
    
    def validate_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate JWT token and extract XGT credentials.
        
        Args:
            token: JWT token to validate
            
        Returns:
            Token validation result with user info and credentials
        """
        # Get JWT module dynamically
        jwt_module = _get_jwt_module()
        if jwt_module is None:
            return None
            
        try:
            # Decode JWT token using PyJWT with reasonable clock skew tolerance
            payload = jwt_module.decode(
                token,
                self.settings.JWT_SECRET_KEY,
                algorithms=[self.settings.JWT_ALGORITHM],
                options={"verify_iat": True},
                leeway=timedelta(seconds=30)  # Allow 30 seconds clock skew tolerance
            )
            
            username = payload.get('sub')
            encrypted_credentials = payload.get('xgt_credentials')
            
            if not username or not encrypted_credentials:
                return None
            
            # Decrypt XGT credentials
            credentials = XGTCredentials.decrypt(encrypted_credentials, self.settings.SECRET_KEY)
            
            # Validate credentials are still valid (with caching)
            # Create cache key using auth data hash instead of password
            cache_key = f"{username}:{hash(str(credentials.auth_data))}"
            if cache_key not in self._connection_cache:
                is_valid = self._test_xgt_connection(credentials)
                self._connection_cache[cache_key] = is_valid
            else:
                is_valid = self._connection_cache[cache_key]
            
            if not is_valid:
                logger.warning(f"XGT credentials no longer valid for user {username}")
                return None
            
            return {
                'valid': True,
                'username': username,
                'credentials': credentials,
                'namespace': payload.get('namespace'),
                'authenticated_at': payload.get('iat'),
                'expires_at': payload.get('exp')
            }
            
        except Exception as e:
            if 'ExpiredSignatureError' in str(type(e)):
                logger.warning("JWT token has expired")
                return None
            elif 'InvalidTokenError' in str(type(e)) or 'InvalidToken' in str(type(e)):
                logger.warning(f"Invalid JWT token: {e}")
                return None
            else:
                logger.error(f"Token validation error: {e}")
                return None
    
    def _get_xgt_user_info(self, connection, username: str) -> Dict[str, Any]:
        """Get user information from XGT connection."""
        try:
            # Get default namespace (usually matches username)
            namespace = getattr(connection, 'get_default_namespace', lambda: username)()
            
            return {
                'namespace': namespace
            }
            
        except Exception as e:
            logger.warning(f"Could not get full user info from XGT: {e}")
            return {
                'namespace': username  # Fallback to username
            }
    
    def _test_xgt_connection(self, credentials: XGTCredentials) -> bool:
        """Test if XGT credentials are still valid."""
        if xgt is None:
            return False
        
        connection = None
        try:
            # Get password from auth_data for BasicAuth
            if credentials.auth_type == XGTAuthType.BASIC:
                auth = xgt.BasicAuth(
                    username=credentials.auth_data.get('username'),
                    password=credentials.auth_data.get('password')
                )
            else:
                # For PKI auth, we'd need different handling
                logger.debug("PKI credential validation not implemented")
                return True  # Skip validation for PKI for now
            
            conn_flags = {}
            if self.settings.XGT_USE_SSL:
                conn_flags = {
                    'ssl': True,
                    'ssl_server_cert': self.settings.XGT_SSL_CERT,
                    'ssl_server_cn': self.settings.XGT_SERVER_CN
                }
            
            connection = xgt.Connection(
                host=self.settings.XGT_HOST,
                port=self.settings.XGT_PORT,
                auth=auth,
                flags=conn_flags
            )
            
            # Simple test operation - just creating connection is enough
            return True
            
        except Exception as e:
            logger.debug(f"XGT credentials test failed: {e}")
            return False
        finally:
            # Close connection safely
            if connection:
                try:
                    if hasattr(connection, 'close'):
                        connection.close()
                    elif hasattr(connection, '__del__'):
                        del connection
                except:
                    pass  # Ignore close errors
    
    def _generate_jwt_token(self, username: str, credentials: XGTCredentials, user_info: Dict[str, Any]) -> str:
        """Generate JWT token with encrypted XGT credentials."""
        # Get JWT module dynamically
        jwt_module = _get_jwt_module()
        if jwt_module is None:
            raise XGTOperationError("JWT library not available")
            
        try:
            # Use current time for token generation (ensure UTC)
            import time
            now_timestamp = int(time.time())  # Current Unix timestamp in UTC
            payload = {
                'sub': username,
                'iat': now_timestamp,
                'exp': now_timestamp + self.settings.JWT_EXPIRY_SECONDS,
                'xgt_credentials': credentials.encrypt(),
                'namespace': user_info.get('namespace'),
                'auth_type': 'xgt_passthrough'
            }
            
            logger.debug(f"Generating JWT token for user: {username}")
            
            # Use PyJWT encode method
            token = jwt_module.encode(
                payload,
                self.settings.JWT_SECRET_KEY,
                algorithm=self.settings.JWT_ALGORITHM
            )
            
            # Ensure token is a string (PyJWT 2.x returns string, older versions might return bytes)
            if isinstance(token, bytes):
                token = token.decode('utf-8')
                
            logger.debug("JWT token generated successfully")
            return token
            
        except Exception as e:
            logger.error(f"JWT token generation failed: {e}")
            raise XGTOperationError(f"Token generation error: {e}")
    
    def create_xgt_connection(self, credentials: XGTCredentials):
        """
        Create XGT connection using user credentials.
        
        Args:
            credentials: Decrypted XGT credentials
            
        Returns:
            XGT connection object
            
        Raises:
            XGTConnectionError: If connection fails
        """
        if xgt is None:
            raise XGTConnectionError("XGT library not available")
        
        try:
            # Create auth object based on credential type
            if credentials.auth_type == XGTAuthType.BASIC:
                auth = xgt.BasicAuth(
                    username=credentials.auth_data.get('username'),
                    password=credentials.auth_data.get('password')
                )
            else:
                raise XGTConnectionError(f"Unsupported auth type for connection: {credentials.auth_type}")
            
            conn_flags = {}
            if self.settings.XGT_USE_SSL:
                conn_flags = {
                    'ssl': True,
                    'ssl_server_cert': self.settings.XGT_SSL_CERT,
                    'ssl_server_cn': self.settings.XGT_SERVER_CN
                }
            
            connection = xgt.Connection(
                host=self.settings.XGT_HOST,
                port=self.settings.XGT_PORT,
                auth=auth,
                flags=conn_flags
            )
            
            logger.debug(f"Created XGT connection for user {credentials.username}")
            return connection
            
        except Exception as e:
            logger.error(f"Failed to create XGT connection for user {credentials.username}: {e}")
            raise XGTConnectionError(f"XGT connection failed: {str(e)}")


# Global service instance
_passthrough_auth_service = None

def get_passthrough_auth_service() -> PassthroughAuthService:
    """Get the global pass-through authentication service instance."""
    global _passthrough_auth_service
    if _passthrough_auth_service is None:
        _passthrough_auth_service = PassthroughAuthService()
    return _passthrough_auth_service