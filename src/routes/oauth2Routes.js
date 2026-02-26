/**
 * OAuth 2.0 Routes
 *
 * Comprehensive OAuth 2.0 implementation supporting:
 * - Multiple grant types (Authorization Code, PKCE, Client Credentials)
 * - Multiple client authentication methods
 * - Configurable scope delimiters
 * - Token introspection and revocation
 */

const express = require('express');
const router = express.Router();
const configManager = require('../config/configManager');
const logger = require('../utils/logger');
const crypto = require('crypto-js');

// In-memory token store
const tokenStore = {
  authCodes: new Map(),
  accessTokens: new Map(),
  refreshTokens: new Map(),
  pkceStore: new Map()
};

// =============================================================================
// AUTHORIZATION ENDPOINT
// =============================================================================

/**
 * @swagger
 * /authorize:
 *   get:
 *     summary: OAuth2 Authorization endpoint
 *     tags: [OAuth2]
 *     parameters:
 *       - name: response_type
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *           enum: [code, token]
 *       - name: client_id
 *         in: query
 *         required: true
 *       - name: redirect_uri
 *         in: query
 *         required: true
 *       - name: scope
 *         in: query
 *       - name: state
 *         in: query
 *       - name: code_challenge
 *         in: query
 *         description: PKCE code challenge
 *       - name: code_challenge_method
 *         in: query
 *         description: PKCE method (S256 or plain)
 */
router.get('/authorize', (req, res) => {
  const config = configManager.getConfig();

  // Check if Auto configuration is enabled
  if (config.configurationType === 'Manual') {
    return res.status(400).json({
      status: 'failure',
      message: 'Authorization endpoint not available in Manual configuration mode',
      details: {
        configurationType: config.configurationType,
        hint: 'Switch to Auto configuration to use authorization endpoint'
      }
    });
  }

  const {
    response_type,
    client_id,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method,
    nonce
  } = req.query;

  const errors = [];

  // Validate required parameters
  if (!response_type) {
    errors.push('Missing response_type parameter');
  } else if (response_type !== 'code' && response_type !== 'token') {
    errors.push('Invalid response_type. Must be "code" or "token"');
  }

  if (!client_id) {
    errors.push('Missing client_id parameter');
  } else if (client_id !== config.credentials.oauth2.clientId) {
    errors.push('Invalid client_id');
  }

  if (!redirect_uri) {
    errors.push('Missing redirect_uri parameter');
  }

  // Validate PKCE for PKCE grant type
  if (config.grantType === 'Authorization Code with PKCE') {
    if (!code_challenge) {
      errors.push('Missing code_challenge (required for PKCE)');
    }
    if (code_challenge_method && code_challenge_method !== 'S256' && code_challenge_method !== 'plain') {
      errors.push('Invalid code_challenge_method. Must be "S256" or "plain"');
    }
  }

  if (errors.length > 0) {
    return res.status(400).json({
      status: 'failure',
      message: 'Authorization request validation failed',
      details: { errors }
    });
  }

  // Parse and validate scopes
  const scopes = scope ? configManager.parseScopes(scope) : ['read'];

  // Generate authorization code
  const authCode = generateToken('code');

  // Store auth code with metadata
  const codeData = {
    code: authCode,
    clientId: client_id,
    redirectUri: redirect_uri,
    scopes,
    state,
    nonce,
    created: Date.now(),
    expiresAt: Date.now() + 600000 // 10 minutes
  };

  // Store PKCE data if present
  if (code_challenge) {
    codeData.codeChallenge = code_challenge;
    codeData.codeChallengeMethod = code_challenge_method || 'plain';
    tokenStore.pkceStore.set(authCode, {
      challenge: code_challenge,
      method: code_challenge_method || 'plain'
    });
  }

  tokenStore.authCodes.set(authCode, codeData);

  // Build redirect URL
  if (redirect_uri) {
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', authCode);
    if (state) {
      redirectUrl.searchParams.set('state', state);
    }

    logger.info('Authorization code issued', {
      clientId: client_id,
      code: authCode.substring(0, 10) + '...'
    });

    // Return redirect or JSON based on Accept header
    if (req.accepts('html')) {
      return res.redirect(redirectUrl.toString());
    }
  }

  // Return JSON response
  res.json({
    status: 'success',
    message: 'Authorization code generated',
    details: {
      code: authCode,
      state,
      redirect_uri,
      scope: configManager.formatScopes(scopes),
      expires_in: 600
    }
  });
});

// =============================================================================
// TOKEN ENDPOINTS - Separate endpoints for each auth method
// =============================================================================

/**
 * @swagger
 * /token/basic:
 *   post:
 *     summary: Token endpoint - Client Secret Basic (Authorization header only)
 *     tags: [OAuth2]
 *     security:
 *       - basicAuth: []
 */
router.post('/token/basic', (req, res) => {
  const config = configManager.getConfig();
  const authHeader = req.headers.authorization;

  // STRICT: Only accept Basic Auth header
  if (!authHeader || !authHeader.toLowerCase().startsWith('basic ')) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'This endpoint requires Client Secret Basic authentication (Authorization header)',
      status: 'failure',
      message: 'Missing or invalid Authorization header',
      details: {
        endpoint: '/token/basic',
        requiredAuth: 'Client Secret Basic',
        hint: 'Use Authorization: Basic base64(client_id:client_secret)',
        example: 'Authorization: Basic dGVzdF9jbGllbnRfaWQ6dGVzdF9jbGllbnRfc2VjcmV0'
      }
    });
  }

  // Note: client_secret in body is allowed alongside Basic auth header

  const clientAuth = validateBasicAuth(req, config);
  if (!clientAuth.valid) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: clientAuth.error,
      status: 'failure',
      message: clientAuth.error,
      details: { clientAuthMethod: 'Client Secret Basic' }
    });
  }

  handleTokenRequest(req, res, config, clientAuth);
});

/**
 * @swagger
 * /token/post:
 *   post:
 *     summary: Token endpoint - Client Secret Post (credentials in body only)
 *     tags: [OAuth2]
 */
router.post('/token/post', (req, res) => {
  const config = configManager.getConfig();
  const authHeader = req.headers.authorization;

  // STRICT: Reject if Basic Auth header is present
  if (authHeader && authHeader.toLowerCase().startsWith('basic ')) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'This endpoint requires Client Secret Post (credentials in body, not header)',
      status: 'failure',
      message: 'Authorization header not allowed for this endpoint',
      details: {
        endpoint: '/token/post',
        requiredAuth: 'Client Secret Post',
        hint: 'Remove Authorization header, use client_id and client_secret in request body'
      }
    });
  }

  // STRICT: Require credentials in body
  const { client_id, client_secret } = req.body;
  if (!client_id || !client_secret) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'This endpoint requires client_id and client_secret in request body',
      status: 'failure',
      message: 'Missing client_id or client_secret in body',
      details: {
        endpoint: '/token/post',
        requiredAuth: 'Client Secret Post',
        hint: 'Include client_id and client_secret in the request body'
      }
    });
  }

  const clientAuth = validatePostAuth(req, config);
  if (!clientAuth.valid) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: clientAuth.error,
      status: 'failure',
      message: clientAuth.error,
      details: { clientAuthMethod: 'Client Secret Post' }
    });
  }

  handleTokenRequest(req, res, config, clientAuth);
});

/**
 * @swagger
 * /token/jwt:
 *   post:
 *     summary: Token endpoint - Client Secret JWT (client_assertion only)
 *     tags: [OAuth2]
 */
router.post('/token/jwt', (req, res) => {
  const config = configManager.getConfig();
  const authHeader = req.headers.authorization;

  // STRICT: Reject if Basic Auth header is present
  if (authHeader && authHeader.toLowerCase().startsWith('basic ')) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'This endpoint requires Client Secret JWT authentication',
      status: 'failure',
      message: 'Authorization header not allowed for JWT endpoint',
      details: {
        endpoint: '/token/jwt',
        requiredAuth: 'Client Secret JWT',
        hint: 'Remove Authorization header, use client_assertion and client_assertion_type in body'
      }
    });
  }

  // STRICT: Reject if client_secret is in body
  if (req.body.client_secret) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'This endpoint requires client_assertion, not client_secret',
      status: 'failure',
      message: 'Use client_assertion instead of client_secret',
      details: {
        endpoint: '/token/jwt',
        requiredAuth: 'Client Secret JWT'
      }
    });
  }

  // STRICT: Require JWT assertion
  const { client_assertion, client_assertion_type } = req.body;
  if (!client_assertion || !client_assertion_type) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'This endpoint requires client_assertion and client_assertion_type',
      status: 'failure',
      message: 'Missing client_assertion or client_assertion_type',
      details: {
        endpoint: '/token/jwt',
        requiredAuth: 'Client Secret JWT',
        hint: 'Include client_assertion (JWT) and client_assertion_type in body',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      }
    });
  }

  const clientAuth = validateJWTAuth(req, config);
  if (!clientAuth.valid) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: clientAuth.error,
      status: 'failure',
      message: clientAuth.error,
      details: { clientAuthMethod: 'Client Secret JWT' }
    });
  }

  handleTokenRequest(req, res, config, clientAuth);
});

/**
 * @swagger
 * /token/pkce:
 *   post:
 *     summary: Token endpoint - PKCE (no client secret, code_verifier required)
 *     tags: [OAuth2]
 */
router.post('/token/pkce', (req, res) => {
  const config = configManager.getConfig();
  const authHeader = req.headers.authorization;

  // STRICT: Reject if Basic Auth header is present
  if (authHeader && authHeader.toLowerCase().startsWith('basic ')) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'PKCE endpoint does not use client authentication',
      status: 'failure',
      message: 'Authorization header not allowed for PKCE endpoint',
      details: {
        endpoint: '/token/pkce',
        requiredAuth: 'None (PKCE)',
        hint: 'Remove Authorization header, use client_id and code_verifier only'
      }
    });
  }

  // STRICT: Reject if client_secret is in body
  if (req.body.client_secret) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'PKCE flow does not use client_secret',
      status: 'failure',
      message: 'client_secret not allowed for PKCE',
      details: {
        endpoint: '/token/pkce',
        hint: 'Remove client_secret, use code_verifier instead'
      }
    });
  }

  // STRICT: Require client_id
  const { client_id, code_verifier, grant_type } = req.body;
  if (!client_id) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Missing client_id',
      status: 'failure',
      message: 'client_id is required',
      details: { endpoint: '/token/pkce' }
    });
  }

  // STRICT: Require code_verifier for authorization_code grant
  if (grant_type === 'authorization_code' && !code_verifier) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'PKCE requires code_verifier',
      status: 'failure',
      message: 'Missing code_verifier',
      details: {
        endpoint: '/token/pkce',
        hint: 'Include code_verifier that matches the code_challenge from authorization request'
      }
    });
  }

  const clientAuth = validatePKCEAuth(req, config);
  if (!clientAuth.valid) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: clientAuth.error,
      status: 'failure',
      message: clientAuth.error,
      details: { clientAuthMethod: 'None (PKCE)' }
    });
  }

  handleTokenRequest(req, res, config, clientAuth);
});

/**
 * @swagger
 * /token:
 *   post:
 *     summary: Generic Token endpoint - Auto-detects authentication method
 *     tags: [OAuth2]
 *     description: Accepts any client authentication method (for backward compatibility)
 */
router.post('/token', (req, res) => {
  const config = configManager.getConfig();

  // Auto-detect and validate client authentication
  const clientAuth = validateClientAuthentication(req, config);
  if (!clientAuth.valid) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: clientAuth.error,
      status: 'failure',
      message: clientAuth.error,
      details: {
        detectedMethod: clientAuth.method,
        hint: 'Use specific endpoints for strict validation: /token/basic, /token/post, /token/jwt, /token/pkce'
      }
    });
  }

  handleTokenRequest(req, res, config, clientAuth);
});

/**
 * Common handler for all token requests
 */
function handleTokenRequest(req, res, config, clientAuth) {
  const { grant_type } = req.body;

  switch (grant_type) {
    case 'authorization_code':
      return handleAuthorizationCodeGrant(req, res, config, clientAuth);
    case 'client_credentials':
      return handleClientCredentialsGrant(req, res, config, clientAuth);
    case 'refresh_token':
      return handleRefreshTokenGrant(req, res, config, clientAuth);
    default:
      return res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: `Unsupported grant_type: ${grant_type}`,
        status: 'failure',
        message: `Unsupported grant_type: ${grant_type}`,
        details: {
          supported: ['authorization_code', 'client_credentials', 'refresh_token']
        }
      });
  }
}

/**
 * Handle Authorization Code Grant
 */
function handleAuthorizationCodeGrant(req, res, config, clientAuth) {
  const { code, redirect_uri, code_verifier } = req.body;

  if (!code) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing authorization code',
      status: 'failure',
      message: 'Missing authorization code',
      details: {}
    });
  }

  // Validate authorization code
  const codeData = tokenStore.authCodes.get(code);

  if (!codeData) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Invalid or expired authorization code',
      status: 'failure',
      message: 'Invalid or expired authorization code',
      details: {}
    });
  }

  // Check code expiration
  if (Date.now() > codeData.expiresAt) {
    tokenStore.authCodes.delete(code);
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code expired',
      status: 'failure',
      message: 'Authorization code expired',
      details: {}
    });
  }

  // Validate redirect_uri
  if (redirect_uri && redirect_uri !== codeData.redirectUri) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'redirect_uri mismatch',
      status: 'failure',
      message: 'redirect_uri mismatch',
      details: {}
    });
  }

  // Validate PKCE if required
  if (config.grantType === 'Authorization Code with PKCE' || codeData.codeChallenge) {
    const pkceValidation = validatePKCE(code_verifier, codeData.codeChallenge, codeData.codeChallengeMethod);
    if (!pkceValidation.valid) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: pkceValidation.error,
        status: 'failure',
        message: pkceValidation.error,
        details: {
          hint: 'Ensure code_verifier matches the code_challenge used in authorization request'
        }
      });
    }
  }

  // Generate tokens
  const tokens = generateTokens(codeData.clientId, codeData.scopes);

  // Remove used authorization code (single use)
  tokenStore.authCodes.delete(code);
  tokenStore.pkceStore.delete(code);

  logger.info('Access token issued via authorization code', {
    clientId: codeData.clientId,
    method: clientAuth.method
  });

  res.json({
    access_token: tokens.accessToken,
    token_type: 'Bearer',
    expires_in: parseInt(process.env.TOKEN_EXPIRY_SECONDS) || 3600,
    refresh_token: tokens.refreshToken,
    scope: configManager.formatScopes(codeData.scopes),
    status: 'success',
    message: 'Token issued successfully',
    details: {
      grantType: 'Authorization Code',
      clientAuthMethod: clientAuth.method,
      validatedParams: Object.keys(req.body).length,
      scopeCount: codeData.scopes.length
    }
  });
}

/**
 * Handle Client Credentials Grant
 */
function handleClientCredentialsGrant(req, res, config, clientAuth) {
  const { scope } = req.body;

  // Parse scopes
  const scopes = scope ? configManager.parseScopes(scope) : ['read'];

  // Generate tokens (no refresh token for client credentials)
  const tokens = generateTokens(clientAuth.clientId, scopes, false);

  logger.info('Access token issued via client credentials', {
    clientId: clientAuth.clientId,
    method: clientAuth.method
  });

  res.json({
    access_token: tokens.accessToken,
    token_type: 'Bearer',
    expires_in: parseInt(process.env.TOKEN_EXPIRY_SECONDS) || 3600,
    scope: configManager.formatScopes(scopes),
    status: 'success',
    message: 'Token issued successfully',
    details: {
      grantType: 'Client Credentials',
      clientAuthMethod: clientAuth.method,
      validatedParams: Object.keys(req.body).length,
      scopeCount: scopes.length
    }
  });
}

/**
 * Handle Refresh Token Grant
 */
function handleRefreshTokenGrant(req, res, config, clientAuth) {
  const { refresh_token, scope } = req.body;

  if (!refresh_token) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing refresh_token',
      status: 'failure',
      message: 'Missing refresh_token',
      details: {}
    });
  }

  // Validate refresh token
  const tokenData = tokenStore.refreshTokens.get(refresh_token);

  if (!tokenData) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Invalid or expired refresh token',
      status: 'failure',
      message: 'Invalid or expired refresh token',
      details: {}
    });
  }

  // Check expiration
  if (Date.now() > tokenData.expiresAt) {
    tokenStore.refreshTokens.delete(refresh_token);
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Refresh token expired',
      status: 'failure',
      message: 'Refresh token expired',
      details: {}
    });
  }

  // Parse new scopes or use original
  const scopes = scope ? configManager.parseScopes(scope) : tokenData.scopes;

  // Generate new tokens
  const tokens = generateTokens(tokenData.clientId, scopes);

  // Optionally revoke old refresh token (rotation)
  tokenStore.refreshTokens.delete(refresh_token);

  res.json({
    access_token: tokens.accessToken,
    token_type: 'Bearer',
    expires_in: parseInt(process.env.TOKEN_EXPIRY_SECONDS) || 3600,
    refresh_token: tokens.refreshToken,
    scope: configManager.formatScopes(scopes),
    status: 'success',
    message: 'Token refreshed successfully',
    details: {
      grantType: 'Refresh Token',
      validatedParams: Object.keys(req.body).length,
      scopeCount: scopes.length
    }
  });
}

// =============================================================================
// TOKEN INTROSPECTION
// =============================================================================

/**
 * @swagger
 * /oauth2/introspect:
 *   post:
 *     summary: Token introspection endpoint
 *     tags: [OAuth2]
 */
router.post('/introspect', (req, res) => {
  const config = configManager.getConfig();
  const { token, token_type_hint } = req.body;

  // Validate client authentication
  const clientAuth = validateClientAuthentication(req, config);
  if (!clientAuth.valid) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: clientAuth.error
    });
  }

  if (!token) {
    return res.json({ active: false });
  }

  // Check access tokens
  const accessTokenData = tokenStore.accessTokens.get(token);
  if (accessTokenData && Date.now() < accessTokenData.expiresAt) {
    return res.json({
      active: true,
      scope: configManager.formatScopes(accessTokenData.scopes),
      client_id: accessTokenData.clientId,
      token_type: 'Bearer',
      exp: Math.floor(accessTokenData.expiresAt / 1000),
      iat: Math.floor(accessTokenData.created / 1000)
    });
  }

  // Check refresh tokens
  const refreshTokenData = tokenStore.refreshTokens.get(token);
  if (refreshTokenData && Date.now() < refreshTokenData.expiresAt) {
    return res.json({
      active: true,
      scope: configManager.formatScopes(refreshTokenData.scopes),
      client_id: refreshTokenData.clientId,
      token_type: 'refresh_token',
      exp: Math.floor(refreshTokenData.expiresAt / 1000),
      iat: Math.floor(refreshTokenData.created / 1000)
    });
  }

  res.json({ active: false });
});

// =============================================================================
// TOKEN REVOCATION
// =============================================================================

/**
 * @swagger
 * /oauth2/revoke:
 *   post:
 *     summary: Token revocation endpoint
 *     tags: [OAuth2]
 */
router.post('/revoke', (req, res) => {
  const config = configManager.getConfig();
  const { token, token_type_hint } = req.body;

  // Validate client authentication
  const clientAuth = validateClientAuthentication(req, config);
  if (!clientAuth.valid) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: clientAuth.error
    });
  }

  if (token) {
    // Try to revoke from both stores
    tokenStore.accessTokens.delete(token);
    tokenStore.refreshTokens.delete(token);
  }

  // Always return success per RFC 7009
  res.status(200).json({
    status: 'success',
    message: 'Token revoked'
  });
});

// =============================================================================
// TEST ENDPOINTS
// =============================================================================

/**
 * @swagger
 * /oauth2/test:
 *   get:
 *     summary: Test OAuth2 access token
 *     tags: [OAuth2]
 */
router.get('/test', validateAccessToken, (req, res) => {
  const config = configManager.getConfig();

  res.json({
    status: 'success',
    message: 'OAuth2 authentication successful',
    details: {
      authType: 'OAuth2',
      grantType: config.grantType,
      clientAuthMethod: config.clientAuthMethod,
      tokenType: 'Bearer',
      tokenLocation: req.tokenLocation,
      validatedParams: 1,
      scopes: req.tokenData.scopes,
      scopeCount: req.tokenData.scopes.length,
      expiresIn: Math.floor((req.tokenData.expiresAt - Date.now()) / 1000)
    }
  });
});

/**
 * @swagger
 * /oauth2/userinfo:
 *   get:
 *     summary: Get user info (mock)
 *     tags: [OAuth2]
 */
router.get('/userinfo', validateAccessToken, (req, res) => {
  res.json({
    sub: 'mock_user_id_12345',
    name: 'Test User',
    email: 'testuser@example.com',
    email_verified: true,
    preferred_username: 'testuser'
  });
});

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Validate Basic Auth only (for /token/basic endpoint)
 */
function validateBasicAuth(req, config) {
  const oauth2Config = config.credentials.oauth2;
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.toLowerCase().startsWith('basic ')) {
    return { valid: false, error: 'Missing Basic authentication header' };
  }

  try {
    const base64 = authHeader.split(' ')[1];
    const decoded = Buffer.from(base64, 'base64').toString('utf8');
    const [clientId, clientSecret] = decoded.split(':');

    if (clientId !== oauth2Config.clientId || clientSecret !== oauth2Config.clientSecret) {
      return { valid: false, error: 'Invalid client credentials' };
    }

    return { valid: true, clientId, method: 'Client Secret Basic' };
  } catch (e) {
    return { valid: false, error: 'Invalid Basic auth format' };
  }
}

/**
 * Validate Post Body auth only (for /token/post endpoint)
 */
function validatePostAuth(req, config) {
  const oauth2Config = config.credentials.oauth2;
  const { client_id, client_secret } = req.body;

  if (!client_id || !client_secret) {
    return { valid: false, error: 'Missing client_id or client_secret in body' };
  }

  if (client_id !== oauth2Config.clientId || client_secret !== oauth2Config.clientSecret) {
    return { valid: false, error: 'Invalid client credentials' };
  }

  return { valid: true, clientId: client_id, method: 'Client Secret Post' };
}

/**
 * Validate JWT auth only (for /token/jwt endpoint)
 */
function validateJWTAuth(req, config) {
  const oauth2Config = config.credentials.oauth2;
  const { client_assertion, client_assertion_type } = req.body;

  if (client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
    return { valid: false, error: 'Invalid client_assertion_type' };
  }

  if (!client_assertion) {
    return { valid: false, error: 'Missing client_assertion' };
  }

  // Mock JWT validation - check format
  const jwtParts = client_assertion.split('.');
  if (jwtParts.length !== 3) {
    return { valid: false, error: 'Invalid JWT format (expected 3 parts)' };
  }

  try {
    const payload = JSON.parse(Buffer.from(jwtParts[1], 'base64').toString('utf8'));
    if (payload.sub !== oauth2Config.clientId && payload.iss !== oauth2Config.clientId) {
      return { valid: false, error: 'Invalid client in JWT (sub or iss must match client_id)' };
    }
    return { valid: true, clientId: payload.sub || payload.iss, method: 'Client Secret JWT' };
  } catch (e) {
    return { valid: false, error: 'Failed to decode JWT payload' };
  }
}

/**
 * Validate PKCE auth only (for /token/pkce endpoint)
 */
function validatePKCEAuth(req, config) {
  const oauth2Config = config.credentials.oauth2;
  const { client_id } = req.body;

  if (!client_id) {
    return { valid: false, error: 'Missing client_id' };
  }

  if (client_id !== oauth2Config.clientId) {
    return { valid: false, error: 'Invalid client_id' };
  }

  return { valid: true, clientId: client_id, method: 'None (PKCE)' };
}

/**
 * Validate client authentication - Auto-detects the method being used
 * Supports: Client Secret Basic, Client Secret Post, Client Secret JWT, None
 */
function validateClientAuthentication(req, config) {
  const oauth2Config = config.credentials.oauth2;
  const authHeader = req.headers.authorization;
  const { client_id, client_secret, client_assertion, client_assertion_type } = req.body;

  // Auto-detect authentication method based on what's provided in the request

  // 1. Check for Basic Auth header first
  if (authHeader && authHeader.toLowerCase().startsWith('basic ')) {
    try {
      const base64 = authHeader.split(' ')[1];
      const decoded = Buffer.from(base64, 'base64').toString('utf8');
      const [headerClientId, headerClientSecret] = decoded.split(':');

      if (headerClientId !== oauth2Config.clientId || headerClientSecret !== oauth2Config.clientSecret) {
        return { valid: false, error: 'Invalid client credentials', method: 'Client Secret Basic' };
      }

      return { valid: true, clientId: headerClientId, method: 'Client Secret Basic' };
    } catch (e) {
      return { valid: false, error: 'Invalid Basic auth format', method: 'Client Secret Basic' };
    }
  }

  // 2. Check for Client Secret JWT
  if (client_assertion && client_assertion_type) {
    if (client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
      return { valid: false, error: 'Invalid client_assertion_type', method: 'Client Secret JWT' };
    }

    // Mock JWT validation - just check format
    const jwtParts = client_assertion.split('.');
    if (jwtParts.length !== 3) {
      return { valid: false, error: 'Invalid JWT format', method: 'Client Secret JWT' };
    }

    // Decode payload to get client_id
    try {
      const payload = JSON.parse(Buffer.from(jwtParts[1], 'base64').toString('utf8'));
      if (payload.sub !== oauth2Config.clientId && payload.iss !== oauth2Config.clientId) {
        return { valid: false, error: 'Invalid client in JWT', method: 'Client Secret JWT' };
      }
      return { valid: true, clientId: payload.sub || payload.iss, method: 'Client Secret JWT' };
    } catch (e) {
      return { valid: false, error: 'Failed to decode JWT', method: 'Client Secret JWT' };
    }
  }

  // 3. Check for Client Secret Post (credentials in body)
  if (client_id && client_secret) {
    if (client_id !== oauth2Config.clientId || client_secret !== oauth2Config.clientSecret) {
      return { valid: false, error: 'Invalid client credentials', method: 'Client Secret Post' };
    }

    return { valid: true, clientId: client_id, method: 'Client Secret Post' };
  }

  // 4. Check for None (PKCE flow - client_id only, no secret)
  if (client_id && !client_secret) {
    if (client_id !== oauth2Config.clientId) {
      return { valid: false, error: 'Invalid client_id', method: 'None' };
    }
    return { valid: true, clientId: client_id, method: 'None' };
  }

  // No valid authentication method detected
  return {
    valid: false,
    error: 'No client authentication provided. Use Basic Auth header, or include client_id/client_secret in body.',
    method: 'Unknown'
  };
}

/**
 * Validate PKCE code verifier
 */
function validatePKCE(codeVerifier, codeChallenge, method = 'S256') {
  if (!codeVerifier) {
    return { valid: false, error: 'Missing code_verifier' };
  }

  if (codeVerifier.length < 43 || codeVerifier.length > 128) {
    return { valid: false, error: 'code_verifier must be between 43 and 128 characters' };
  }

  // Validate characters
  const validChars = /^[A-Za-z0-9\-._~]+$/;
  if (!validChars.test(codeVerifier)) {
    return { valid: false, error: 'Invalid code_verifier format' };
  }

  if (method === 'plain') {
    // Plain comparison
    if (codeVerifier !== codeChallenge) {
      return { valid: false, error: 'code_verifier does not match code_challenge' };
    }
  } else if (method === 'S256') {
    // SHA256 hash comparison
    const hash = crypto.SHA256(codeVerifier);
    const computedChallenge = hash.toString(crypto.enc.Base64)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    if (computedChallenge !== codeChallenge) {
      return { valid: false, error: 'code_verifier does not match code_challenge (S256)' };
    }
  }

  return { valid: true };
}

/**
 * Generate access and refresh tokens
 */
function generateTokens(clientId, scopes, includeRefresh = true) {
  const accessToken = generateToken('at');
  const now = Date.now();
  const accessExpiry = now + (parseInt(process.env.TOKEN_EXPIRY_SECONDS) || 3600) * 1000;

  // Store access token
  tokenStore.accessTokens.set(accessToken, {
    clientId,
    scopes,
    created: now,
    expiresAt: accessExpiry
  });

  const result = { accessToken };

  if (includeRefresh) {
    const refreshToken = generateToken('rt');
    const refreshExpiry = now + (parseInt(process.env.REFRESH_TOKEN_EXPIRY_SECONDS) || 86400) * 1000;

    // Store refresh token
    tokenStore.refreshTokens.set(refreshToken, {
      clientId,
      scopes,
      created: now,
      expiresAt: refreshExpiry
    });

    result.refreshToken = refreshToken;
  }

  return result;
}

/**
 * Generate random token
 */
function generateToken(prefix = 'tok') {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = prefix + '_';
  for (let i = 0; i < 40; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

/**
 * Middleware to validate access token
 */
function validateAccessToken(req, res, next) {
  const config = configManager.getConfig();
  let token = null;
  let tokenLocation = null;

  // Check header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
    tokenLocation = 'header';
  }

  // Check query string
  if (!token && req.query.access_token) {
    token = req.query.access_token;
    tokenLocation = 'query';
  }

  if (!token) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Missing access token',
      status: 'failure',
      message: 'Missing access token',
      details: {
        hint: 'Provide token in Authorization header (Bearer) or query parameter (access_token)'
      }
    });
  }

  // Validate token
  const tokenData = tokenStore.accessTokens.get(token);

  if (!tokenData) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid access token',
      status: 'failure',
      message: 'Invalid access token',
      details: {}
    });
  }

  // Check expiration
  if (Date.now() > tokenData.expiresAt) {
    tokenStore.accessTokens.delete(token);
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Access token expired',
      status: 'failure',
      message: 'Access token expired',
      details: {}
    });
  }

  req.tokenData = tokenData;
  req.tokenLocation = tokenLocation;
  next();
}

/**
 * Get hint for client auth method
 */
function getClientAuthHint(method) {
  const hints = {
    'Client Secret Basic': 'Use Authorization header with Basic base64(client_id:client_secret)',
    'Client Secret Post': 'Include client_id and client_secret in request body',
    'Client Secret JWT': 'Include client_assertion and client_assertion_type in request body',
    'None': 'Include only client_id in request body (for PKCE flows)'
  };
  return hints[method] || 'Unknown authentication method';
}

// Clean up expired tokens periodically
setInterval(() => {
  const now = Date.now();

  for (const [token, data] of tokenStore.authCodes) {
    if (now > data.expiresAt) tokenStore.authCodes.delete(token);
  }

  for (const [token, data] of tokenStore.accessTokens) {
    if (now > data.expiresAt) tokenStore.accessTokens.delete(token);
  }

  for (const [token, data] of tokenStore.refreshTokens) {
    if (now > data.expiresAt) tokenStore.refreshTokens.delete(token);
  }
}, 60000); // Every minute

module.exports = router;

