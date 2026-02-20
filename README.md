# 🔐 Mock Authentication Server

A production-ready mock authentication server for testing all authentication type configurations. Perfect for development, testing, and CI/CD pipelines.

## 🎯 Features

- **Multiple Authentication Types**
  - API Key Authentication (Header, Query, Form Data, JSON Body)
  - Basic Authentication
  - OAuth 1.0 (Request Token, Access Token, Signature Validation)
  - OAuth 2.0 (Authorization Code, PKCE, Client Credentials)

- **Flexible Configuration**
  - JSON/YAML config files
  - Runtime configuration via Admin API
  - Environment variable overrides

- **Comprehensive Validation**
  - Parameter count validation
  - Dynamic parameter support
  - Scope validation with multiple delimiters
  - Client authentication method validation

- **Developer Experience**
  - Swagger/OpenAPI documentation
  - Interactive Test UI
  - Postman collection
  - Detailed logging

## 🚀 Quick Start

### Local Development

```bash
# Clone the repository
git clone <repository-url>
cd mock-auth-server

# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Start the server
npm start
```

The server will start on `http://localhost:3000`

### Using Docker

```bash
# Build the image
docker build -t mock-auth-server .

# Run the container
docker run -p 3000:3000 mock-auth-server
```

## 📚 API Documentation

- **Swagger UI**: `http://localhost:3000/api-docs`
- **Test UI**: `http://localhost:3000/ui`
- **Health Check**: `http://localhost:3000/health`

## ⚙️ Configuration

### Config File (config/default.json)

```json
{
  "authType": "OAuth2",
  "grantType": "Authorization Code",
  "configurationType": "Auto",
  "clientAuthMethod": "Client Secret Basic",
  "scopeDelimiter": "space",
  "paramLocation": "header",
  "totalParams": 50,
  "dynamicParams": 10,
  "totalScopes": 50
}
```

### Runtime Configuration

```bash
# Get current config
curl http://localhost:3000/config

# Update config
curl -X POST http://localhost:3000/config \
  -H "Content-Type: application/json" \
  -d '{"authType": "OAuth2", "grantType": "Client Credentials"}'

# Reset to defaults
curl -X POST http://localhost:3000/config/reset
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3000 |
| `NODE_ENV` | Environment | production |
| `DEFAULT_AUTH_TYPE` | Default auth type | OAuth2 |
| `DEFAULT_GRANT_TYPE` | OAuth2 grant type | Authorization Code |
| `MOCK_CLIENT_ID` | OAuth2 client ID | test_client_id |
| `MOCK_CLIENT_SECRET` | OAuth2 client secret | test_client_secret |
| `MOCK_API_KEY` | API Key value | test_api_key_12345 |
| `MOCK_USERNAME` | Basic auth username | testuser |
| `MOCK_PASSWORD` | Basic auth password | testpass123 |

## 🧪 Test Examples

### API Key Authentication

```bash
# Test with header
curl -H "X-API-Key: test_api_key_12345" \
  http://localhost:3000/api-key/test

# Test with query parameter
curl "http://localhost:3000/api-key/test?X-API-Key=test_api_key_12345"

# Test with form-data (multipart)
curl -X POST http://localhost:3000/api-key/test-form \
  -F "X-API-Key=test_api_key_12345"

# Test with JSON body
curl -X POST http://localhost:3000/api-key/test \
  -H "Content-Type: application/json" \
  -d '{"X-API-Key": "test_api_key_12345"}'

# Test invalid key (expect 401)
curl -H "X-API-Key: invalid_key" \
  http://localhost:3000/api-key/test

# Test with dynamic parameters
curl -X POST http://localhost:3000/api-key/test-params \
  -H "X-API-Key: test_api_key_12345" \
  -H "Content-Type: application/json" \
  -d '{"timestamp": 1234567890, "nonce": "abc123def456"}'

# Test multiple keys
curl -X POST http://localhost:3000/api-key/multi \
  -H "X-API-Key-1: key1" \
  -H "X-Key-2: key2" \
  -H "Content-Type: application/json" \
  -d '{"api_key_3": "key3"}'
```

### Basic Authentication

```bash
# Test valid credentials
curl -u testuser:testpass123 \
  http://localhost:3000/basic/test

# Test invalid credentials (expect 401)
curl -u wrong:credentials \
  http://localhost:3000/basic/test

# Test with parameters
curl -u testuser:testpass123 \
  -X POST http://localhost:3000/basic/test-params \
  -H "Content-Type: application/json" \
  -d '{"timestamp": 1234567890, "param1": "value1"}'

# Validate credentials via body
curl -X POST http://localhost:3000/basic/validate \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass123"}'

# Test with 50 parameters
curl -u testuser:testpass123 \
  -X POST http://localhost:3000/basic/multi-params \
  -H "Content-Type: application/json" \
  -d '{"param_0": "v0", "param_1": "v1", "param_2": "v2"}'
```

### OAuth 1.0 Authentication

#### OAuth 1.0 Flow Explanation

OAuth 1.0 is a three-legged authentication flow that uses signatures to verify requests. Here's how it works:

```
┌──────────┐                              ┌──────────┐                              ┌──────────┐
│  Client  │                              │  Server  │                              │   User   │
└────┬─────┘                              └────┬─────┘                              └────┬─────┘
     │                                         │                                         │
     │  1. Request Token                       │                                         │
     │  POST /oauth1/request-token             │                                         │
     │  Authorization: OAuth oauth_consumer_key,│                                         │
     │  oauth_signature, oauth_timestamp,      │                                         │
     │  oauth_nonce, oauth_signature_method    │                                         │
     │────────────────────────────────────────>│                                         │
     │                                         │                                         │
     │  oauth_token, oauth_token_secret        │                                         │
     │<────────────────────────────────────────│                                         │
     │                                         │                                         │
     │  2. User Authorization                  │                                         │
     │  Redirect to /oauth1/authorize?oauth_token=...                                    │
     │─────────────────────────────────────────────────────────────────────────────────>│
     │                                         │                                         │
     │                                         │         User approves access            │
     │                                         │<────────────────────────────────────────│
     │                                         │                                         │
     │  oauth_token + oauth_verifier (callback)│                                         │
     │<────────────────────────────────────────────────────────────────────────────────│
     │                                         │                                         │
     │  3. Access Token                        │                                         │
     │  POST /oauth1/access-token              │                                         │
     │  Authorization: OAuth oauth_token,      │                                         │
     │  oauth_verifier, oauth_signature...     │                                         │
     │────────────────────────────────────────>│                                         │
     │                                         │                                         │
     │  oauth_token (access), oauth_token_secret                                         │
     │<────────────────────────────────────────│                                         │
     │                                         │                                         │
     │  4. Access Protected Resources          │                                         │
     │  GET /oauth1/test                       │                                         │
     │  Authorization: OAuth oauth_token,      │                                         │
     │  oauth_signature...                     │                                         │
     │────────────────────────────────────────>│                                         │
     │                                         │                                         │
     │  Protected Resource                     │                                         │
     │<────────────────────────────────────────│                                         │
     │                                         │                                         │
```

#### OAuth 1.0 Signature Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `oauth_consumer_key` | Your application's identifier | `mock_consumer_key` |
| `oauth_token` | Request token or access token | `rt_abc123...` |
| `oauth_signature_method` | Signature algorithm | `HMAC-SHA1`, `HMAC-SHA256` |
| `oauth_signature` | Request signature (base64) | `kYjzVBB8Y0ZFabxSWbWovY...` |
| `oauth_timestamp` | Unix timestamp (seconds) | `1708365122` |
| `oauth_nonce` | Unique random string | `abc123xyz789` |
| `oauth_version` | OAuth version | `1.0` |
| `oauth_verifier` | Verification code (step 3) | `ver_xyz789` |

#### OAuth 1.0 Authorization Header Format

```
Authorization: OAuth 
  oauth_consumer_key="mock_consumer_key",
  oauth_nonce="random_nonce_string",
  oauth_timestamp="1708365122",
  oauth_signature_method="HMAC-SHA1",
  oauth_signature="base64_encoded_signature",
  oauth_version="1.0"
```

#### Mock Server OAuth 1.0 Endpoints

**Note:** OAuth 1.0 only supports Authorization header for OAuth parameters.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth1/header` | POST | Test OAuth1 authentication (header only) |
| `/oauth1/request-token` | POST | Get temporary request token |
| `/oauth1/authorize` | GET | User authorization (returns verifier) |
| `/oauth1/access-token` | POST | Exchange request token for access token |
| `/oauth1/test` | POST | Test OAuth1 authentication |
| `/oauth1/echo` | POST | Debug endpoint (echoes OAuth params) |

#### Test Commands

```bash
# Get request token
curl -X POST http://localhost:3000/oauth1/request-token \
  -H 'Authorization: OAuth oauth_consumer_key="mock_consumer_key", oauth_nonce="abc123", oauth_timestamp="'$(date +%s)'", oauth_signature_method="HMAC-SHA1", oauth_signature="mock_sig", oauth_version="1.0"'

# Test with valid signature
curl -X POST http://localhost:3000/oauth1/test \
  -H 'Authorization: OAuth oauth_consumer_key="mock_consumer_key", oauth_nonce="xyz789", oauth_timestamp="'$(date +%s)'", oauth_signature_method="HMAC-SHA1", oauth_signature="valid_sig", oauth_version="1.0"'

# Test expired timestamp (expect 401)
curl -X POST http://localhost:3000/oauth1/test \
  -H 'Authorization: OAuth oauth_consumer_key="mock_consumer_key", oauth_nonce="abc", oauth_timestamp="1000000000", oauth_signature_method="HMAC-SHA1", oauth_signature="sig", oauth_version="1.0"'

# Test invalid consumer key (expect 401)
curl -X POST http://localhost:3000/oauth1/test \
  -H 'Authorization: OAuth oauth_consumer_key="wrong_key", oauth_nonce="abc", oauth_timestamp="'$(date +%s)'", oauth_signature_method="HMAC-SHA1", oauth_signature="sig", oauth_version="1.0"'

# Echo request for debugging
curl -X POST http://localhost:3000/oauth1/echo \
  -H 'Authorization: OAuth oauth_consumer_key="mock_consumer_key", oauth_nonce="test", oauth_timestamp="'$(date +%s)'", oauth_signature_method="HMAC-SHA1", oauth_signature="test", oauth_version="1.0"'
```

### OAuth 2.0 Token Endpoints

The server provides **separate endpoints** for each client authentication method with **strict validation**:

| Endpoint | Auth Method | Accepts | Rejects |
|----------|-------------|---------|---------|
| `/token/basic` | Client Secret Basic | Authorization header only | Body credentials |
| `/token/post` | Client Secret Post | Body credentials only | Authorization header |
| `/token/jwt` | Client Secret JWT | client_assertion only | Basic auth, client_secret |
| `/token/pkce` | None (PKCE) | client_id + code_verifier | client_secret, Basic auth |
| `/token` | Auto-detect | Any method | - |

#### Example: Client Credentials with Basic Auth
```bash
curl -X POST http://localhost:3000/token/basic \
  -u test_client_id:test_client_secret \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=read write"
```

#### Example: Client Credentials with Post Body
```bash
curl -X POST http://localhost:3000/token/post \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test_client_id&client_secret=test_client_secret&scope=read,write"
```

#### Error Examples

Using wrong auth method on `/token/basic`:
```bash
# This will fail - /token/basic requires Authorization header
curl -X POST http://localhost:3000/token/basic \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test_client_id&client_secret=test_client_secret"

# Response: 401 - "This endpoint requires Client Secret Basic authentication"
```

Using wrong auth method on `/token/post`:
```bash
# This will fail - /token/post requires credentials in body
curl -X POST http://localhost:3000/token/post \
  -u test_client_id:test_client_secret \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials"

# Response: 400 - "Authorization header not allowed for this endpoint"
```

# Get Authorization Code
curl "http://localhost:3000/authorize?response_type=code&client_id=test_client_id&redirect_uri=http://localhost:3000/callback&scope=read%20write&state=xyz"

# Exchange Auth Code for Token
curl -X POST http://localhost:3000/token \
  -u test_client_id:test_client_secret \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=YOUR_AUTH_CODE&redirect_uri=http://localhost:3000/callback"

# PKCE Flow - Get Auth Code with Challenge
curl "http://localhost:3000/authorize?response_type=code&client_id=test_client_id&redirect_uri=http://localhost:3000/callback&scope=read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"

# Token Introspection
curl -X POST http://localhost:3000/oauth2/introspect \
  -u test_client_id:test_client_secret \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=YOUR_ACCESS_TOKEN"

# Invalid client (expect 401)
curl -X POST http://localhost:3000/token \
  -u wrong_client:wrong_secret \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials"
```

### Protected Endpoint Tests

```bash
# With Bearer token
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:3000/protected

# With query token
curl "http://localhost:3000/protected?access_token=YOUR_ACCESS_TOKEN"

# With API Key (when configured)
curl -H "X-API-Key: test_api_key_12345" \
  http://localhost:3000/protected

# Echo request
curl -X POST http://localhost:3000/protected/echo \
  -H "X-API-Key: test_api_key_12345" \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

## 🌐 Render Deployment

### Option 1: Deploy via GitHub

1. Push code to GitHub repository
2. Connect repository to Render
3. Create new Web Service
4. Configure:
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Environment Variables**: Add from `.env.example`

### Option 2: Deploy via render.yaml

1. Push code with `render.yaml` to GitHub
2. In Render dashboard, click "New Blueprint Instance"
3. Select your repository
4. Review and deploy

### Environment Variables for Render

| Variable | Required | Description |
|----------|----------|-------------|
| `NODE_ENV` | Yes | Set to `production` |
| `PORT` | Auto | Set automatically by Render |
| `ADMIN_API_KEY` | Yes | Generate secure value |
| `MOCK_CLIENT_SECRET` | Yes | Generate secure value |
| `MOCK_API_KEY` | Yes | Generate secure value |
| `MOCK_PASSWORD` | Yes | Generate secure value |

### Manual Deployment Steps

1. Create account at [render.com](https://render.com)
2. Click "New +" → "Web Service"
3. Connect your GitHub/GitLab repository
4. Configure service:
   ```
   Name: mock-auth-server
   Region: Oregon (or nearest)
   Branch: main
   Runtime: Node
   Build Command: npm install
   Start Command: npm start
   ```
5. Add environment variables
6. Click "Create Web Service"

## 📁 Project Structure

```
mock-auth-server/
├── src/
│   ├── server.js              # Main application entry
│   ├── config/
│   │   └── configManager.js   # Configuration management
│   ├── middleware/
│   │   ├── errorHandler.js    # Error handling
│   │   ├── requestLogger.js   # Request logging
│   │   └── validationEngine.js # Auth validation
│   ├── routes/
│   │   ├── apiKeyRoutes.js    # API Key endpoints
│   │   ├── basicAuthRoutes.js # Basic Auth endpoints
│   │   ├── oauth1Routes.js    # OAuth1 endpoints
│   │   ├── oauth2Routes.js    # OAuth2 endpoints
│   │   ├── protectedRoutes.js # Protected endpoints
│   │   ├── configRoutes.js    # Config endpoints
│   │   └── healthRoutes.js    # Health checks
│   ├── docs/
│   │   └── swagger.js         # API documentation
│   ├── public/
│   │   └── index.html         # Test UI
│   └── utils/
│       └── logger.js          # Logging utility
├── config/
│   ├── default.json           # Default configuration
│   └── default.yaml           # YAML configuration
├── postman/
│   └── Mock_Auth_Server.postman_collection.json
├── Dockerfile
├── render.yaml
├── package.json
└── README.md
```

## 🔧 Supported Configurations

### Authentication Types
- `API Key` - API Key in header, query, form-data, or JSON body
- `Basic Authentication` - Username/password
- `OAuth1` - OAuth 1.0 signature-based
- `OAuth2` - OAuth 2.0 with multiple grants

### API Key Endpoints
| Endpoint | Method | Supported Key Locations |
|----------|--------|------------------------|
| `/api-key/test` | GET | Header, Query |
| `/api-key/test` | POST | Header, Query, JSON Body |
| `/api-key/test-form` | POST | Header, Query, Form Data |
| `/api-key/test-params` | POST | Header + additional params |
| `/api-key/multi` | POST | Multiple keys in various locations |

### OAuth2 Grant Types
- `Authorization Code` - Standard auth code flow
- `Authorization Code with PKCE` - PKCE extension
- `Client Credentials` - Machine-to-machine

### Client Authentication Methods
- `Client Secret Basic` - Basic auth header
- `Client Secret Post` - Credentials in body
- `Client Secret JWT` - JWT assertion
- `None` - For PKCE public clients

### Scope Delimiters
- `space` - `scope=read write`
- `comma` - `scope=read,write`
- `plus` - `scope=read+write`

## 🐛 Edge Case Testing

The server simulates various error scenarios:

| Scenario | Expected Response |
|----------|------------------|
| Invalid scope delimiter | 400 Bad Request |
| Wrong client auth method | 401 Unauthorized |
| Missing dynamic params | Warning in response |
| Invalid PKCE verifier | 400 Bad Request |
| Expired token | 401 Unauthorized |
| Invalid OAuth1 signature | 401 Unauthorized |
| Invalid API key | 401 Unauthorized |
| Expired OAuth1 timestamp | 401 Unauthorized |

## 📝 Response Format

All responses follow this structure:

```json
{
  "status": "success | failure",
  "message": "Human-readable message",
  "details": {
    // Additional context
  }
}
```

OAuth2 token responses follow RFC 6749:

```json
{
  "access_token": "at_xxx...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "rt_xxx...",
  "scope": "read write"
}
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙋 Support

- Open an issue for bugs or features
- Check existing issues before creating new ones
- Provide detailed reproduction steps for bugs

