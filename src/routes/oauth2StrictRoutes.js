/**
 * OAuth 2.0 Strict Endpoints
 *
 * Dedicated endpoints for each OAuth2 configuration combination:
 * - Grant Type: Authorization Code, Authorization Code + PKCE, Client Credentials
 * - Client Auth: Basic, Post, JWT, None (PKCE only)
 * - Scope Delimiter: Comma, Space, Plus
 * - Token Placement: Header, Query
 *
 * Endpoint Pattern:
 *   /oauth2/{grantType}/{clientAuth}/{scopeDelimiter}/authorize
 *   /oauth2/{grantType}/{clientAuth}/{scopeDelimiter}/token
 *   /oauth2/{grantType}/{clientAuth}/{scopeDelimiter}/test/header
 *   /oauth2/{grantType}/{clientAuth}/{scopeDelimiter}/test/query
 */

const express = require('express');
const router = express.Router();
const configManager = require('../config/configManager');
const logger = require('../utils/logger');

// In-memory token store (shared)
const tokenStore = {
  authCodes: new Map(),
  accessTokens: new Map(),
  refreshTokens: new Map(),
  pkceStore: new Map()
};

// =============================================================================
// REDIRECT URI STORE
// =============================================================================
const redirectUriStore = {
  uris: new Set([
    'http://localhost:3000/callback',
    'http://localhost:8080/callback',
    'http://127.0.0.1:3000/callback',
    'https://oauth.pstmn.io/v1/callback',
    'urn:ietf:wg:oauth:2.0:oob',
    'https://shyam-nts0023.csez.zohocorpin.com/applicationOauthRedirect'
  ])
};

// =============================================================================
// SCOPE STORE
// =============================================================================
const scopeStore = {
  scopes: new Set([
    'read',
    'write',
    'delete',
    'admin',
    'profile',
    'email',
    'openid',
    'offline_access'
  ]),
  strictValidation: true // Set to false to allow any scope
};

// =============================================================================
// REDIRECT URI CRUD ENDPOINTS
// =============================================================================

/**
 * GET /oauth2/redirect-uris - List all registered redirect URIs
 */
router.get('/redirect-uris', (req, res) => {
  res.json({
    status: 'success',
    message: 'Registered redirect URIs',
    data: {
      redirectUris: Array.from(redirectUriStore.uris),
      count: redirectUriStore.uris.size
    }
  });
});

/**
 * POST /oauth2/redirect-uris - Add a new redirect URI
 */
router.post('/redirect-uris', (req, res) => {
  const { redirect_uri } = req.body;

  if (!redirect_uri) {
    return res.status(400).json({
      status: 'failure',
      message: 'Missing redirect_uri in request body',
      hint: 'Send { "redirect_uri": "https://example.com/callback" }'
    });
  }

  // Validate URI format
  if (!isValidRedirectUri(redirect_uri)) {
    return res.status(400).json({
      status: 'failure',
      message: 'Invalid redirect_uri format',
      details: {
        provided: redirect_uri,
        hint: 'Must be a valid URL (http://, https://) or urn:ietf:wg:oauth:2.0:oob'
      }
    });
  }

  if (redirectUriStore.uris.has(redirect_uri)) {
    return res.status(409).json({
      status: 'failure',
      message: 'Redirect URI already exists',
      data: { redirect_uri }
    });
  }

  redirectUriStore.uris.add(redirect_uri);

  res.status(201).json({
    status: 'success',
    message: 'Redirect URI added successfully',
    data: {
      redirect_uri,
      totalUris: redirectUriStore.uris.size
    }
  });
});

/**
 * DELETE /oauth2/redirect-uris - Remove a redirect URI
 */
router.delete('/redirect-uris', (req, res) => {
  const { redirect_uri } = req.body;

  if (!redirect_uri) {
    return res.status(400).json({
      status: 'failure',
      message: 'Missing redirect_uri in request body'
    });
  }

  if (!redirectUriStore.uris.has(redirect_uri)) {
    return res.status(404).json({
      status: 'failure',
      message: 'Redirect URI not found',
      data: { redirect_uri }
    });
  }

  redirectUriStore.uris.delete(redirect_uri);

  res.json({
    status: 'success',
    message: 'Redirect URI removed successfully',
    data: {
      redirect_uri,
      totalUris: redirectUriStore.uris.size
    }
  });
});

/**
 * PUT /oauth2/redirect-uris - Update/replace a redirect URI
 */
router.put('/redirect-uris', (req, res) => {
  const { old_redirect_uri, new_redirect_uri } = req.body;

  if (!old_redirect_uri || !new_redirect_uri) {
    return res.status(400).json({
      status: 'failure',
      message: 'Missing old_redirect_uri or new_redirect_uri in request body',
      hint: 'Send { "old_redirect_uri": "...", "new_redirect_uri": "..." }'
    });
  }

  if (!redirectUriStore.uris.has(old_redirect_uri)) {
    return res.status(404).json({
      status: 'failure',
      message: 'Old redirect URI not found',
      data: { old_redirect_uri }
    });
  }

  if (!isValidRedirectUri(new_redirect_uri)) {
    return res.status(400).json({
      status: 'failure',
      message: 'Invalid new_redirect_uri format'
    });
  }

  redirectUriStore.uris.delete(old_redirect_uri);
  redirectUriStore.uris.add(new_redirect_uri);

  res.json({
    status: 'success',
    message: 'Redirect URI updated successfully',
    data: {
      old_redirect_uri,
      new_redirect_uri,
      totalUris: redirectUriStore.uris.size
    }
  });
});

/**
 * POST /oauth2/redirect-uris/reset - Reset to default redirect URIs
 */
router.post('/redirect-uris/reset', (req, res) => {
  redirectUriStore.uris.clear();
  redirectUriStore.uris.add('http://localhost:3000/callback');
  redirectUriStore.uris.add('http://localhost:8080/callback');
  redirectUriStore.uris.add('http://127.0.0.1:3000/callback');
  redirectUriStore.uris.add('https://oauth.pstmn.io/v1/callback');
  redirectUriStore.uris.add('urn:ietf:wg:oauth:2.0:oob');
  redirectUriStore.uris.add('https://shyam-nts0023.csez.zohocorpin.com/applicationOauthRedirect');

  res.json({
    status: 'success',
    message: 'Redirect URIs reset to defaults',
    data: {
      redirectUris: Array.from(redirectUriStore.uris),
      count: redirectUriStore.uris.size
    }
  });
});

// =============================================================================
// SCOPE CRUD ENDPOINTS
// =============================================================================

/**
 * GET /oauth2/scopes - List all registered scopes
 */
router.get('/scopes', (req, res) => {
  res.json({
    status: 'success',
    message: 'Registered scopes',
    data: {
      scopes: Array.from(scopeStore.scopes),
      count: scopeStore.scopes.size,
      strictValidation: scopeStore.strictValidation
    }
  });
});

/**
 * POST /oauth2/scopes - Add a new scope
 */
router.post('/scopes', (req, res) => {
  const { scope } = req.body;

  if (!scope) {
    return res.status(400).json({
      status: 'failure',
      message: 'Missing scope in request body',
      hint: 'Send { "scope": "custom_scope" }'
    });
  }

  // Validate scope format (alphanumeric, underscores, hyphens, dots)
  if (!/^[a-zA-Z0-9_\-.:]+$/.test(scope)) {
    return res.status(400).json({
      status: 'failure',
      message: 'Invalid scope format',
      details: {
        provided: scope,
        hint: 'Scope must contain only alphanumeric characters, underscores, hyphens, dots, and colons'
      }
    });
  }

  if (scopeStore.scopes.has(scope)) {
    return res.status(409).json({
      status: 'failure',
      message: 'Scope already exists',
      data: { scope }
    });
  }

  scopeStore.scopes.add(scope);

  res.status(201).json({
    status: 'success',
    message: 'Scope added successfully',
    data: {
      scope,
      totalScopes: scopeStore.scopes.size
    }
  });
});

/**
 * POST /oauth2/scopes/bulk - Add multiple scopes at once
 */
router.post('/scopes/bulk', (req, res) => {
  const { scopes } = req.body;

  if (!scopes || !Array.isArray(scopes)) {
    return res.status(400).json({
      status: 'failure',
      message: 'Missing or invalid scopes array in request body',
      hint: 'Send { "scopes": ["scope1", "scope2", "scope3"] }'
    });
  }

  const added = [];
  const skipped = [];
  const invalid = [];

  for (const scope of scopes) {
    if (!/^[a-zA-Z0-9_\-.:]+$/.test(scope)) {
      invalid.push(scope);
    } else if (scopeStore.scopes.has(scope)) {
      skipped.push(scope);
    } else {
      scopeStore.scopes.add(scope);
      added.push(scope);
    }
  }

  res.status(201).json({
    status: 'success',
    message: 'Bulk scope operation completed',
    data: {
      added,
      skipped,
      invalid,
      totalScopes: scopeStore.scopes.size
    }
  });
});

/**
 * DELETE /oauth2/scopes - Remove a scope
 */
router.delete('/scopes', (req, res) => {
  const { scope } = req.body;

  if (!scope) {
    return res.status(400).json({
      status: 'failure',
      message: 'Missing scope in request body'
    });
  }

  if (!scopeStore.scopes.has(scope)) {
    return res.status(404).json({
      status: 'failure',
      message: 'Scope not found',
      data: { scope }
    });
  }

  scopeStore.scopes.delete(scope);

  res.json({
    status: 'success',
    message: 'Scope removed successfully',
    data: {
      scope,
      totalScopes: scopeStore.scopes.size
    }
  });
});

/**
 * PUT /oauth2/scopes - Update/replace a scope
 */
router.put('/scopes', (req, res) => {
  const { old_scope, new_scope } = req.body;

  if (!old_scope || !new_scope) {
    return res.status(400).json({
      status: 'failure',
      message: 'Missing old_scope or new_scope in request body',
      hint: 'Send { "old_scope": "...", "new_scope": "..." }'
    });
  }

  if (!scopeStore.scopes.has(old_scope)) {
    return res.status(404).json({
      status: 'failure',
      message: 'Old scope not found',
      data: { old_scope }
    });
  }

  if (!/^[a-zA-Z0-9_\-.:]+$/.test(new_scope)) {
    return res.status(400).json({
      status: 'failure',
      message: 'Invalid new_scope format'
    });
  }

  scopeStore.scopes.delete(old_scope);
  scopeStore.scopes.add(new_scope);

  res.json({
    status: 'success',
    message: 'Scope updated successfully',
    data: {
      old_scope,
      new_scope,
      totalScopes: scopeStore.scopes.size
    }
  });
});

/**
 * POST /oauth2/scopes/reset - Reset to default scopes
 */
router.post('/scopes/reset', (req, res) => {
  scopeStore.scopes.clear();
  scopeStore.scopes.add('read');
  scopeStore.scopes.add('write');
  scopeStore.scopes.add('delete');
  scopeStore.scopes.add('admin');
  scopeStore.scopes.add('profile');
  scopeStore.scopes.add('email');
  scopeStore.scopes.add('openid');
  scopeStore.scopes.add('offline_access');

  res.json({
    status: 'success',
    message: 'Scopes reset to defaults',
    data: {
      scopes: Array.from(scopeStore.scopes),
      count: scopeStore.scopes.size
    }
  });
});

/**
 * PUT /oauth2/scopes/validation - Toggle strict scope validation
 */
router.put('/scopes/validation', (req, res) => {
  const { strict } = req.body;

  if (typeof strict !== 'boolean') {
    return res.status(400).json({
      status: 'failure',
      message: 'Missing or invalid strict value in request body',
      hint: 'Send { "strict": true } or { "strict": false }'
    });
  }

  scopeStore.strictValidation = strict;

  res.json({
    status: 'success',
    message: `Strict scope validation ${strict ? 'enabled' : 'disabled'}`,
    data: {
      strictValidation: scopeStore.strictValidation,
      registeredScopes: Array.from(scopeStore.scopes)
    }
  });
});

// =============================================================================
// OAUTH2 LOGIN UI ENDPOINTS
// =============================================================================

/**
 * POST /oauth2/authorize/login - Handle login form submission
 */
router.post('/authorize/login', (req, res) => {
  const config = configManager.getConfig();
  const basicCreds = config.credentials.basic;
  const oauth2Config = config.credentials.oauth2;

  const {
    username,
    password,
    client_id,
    redirect_uri,
    scope,
    state,
    response_type,
    code_challenge,
    code_challenge_method,
    scope_delimiter
  } = req.body;

  // Validate user credentials
  if (username !== basicCreds.username || password !== basicCreds.password) {
    return res.status(401).json({
      status: 'failure',
      message: 'Invalid username or password'
    });
  }

  // Validate client_id
  if (client_id !== oauth2Config.clientId) {
    return res.status(400).json({
      status: 'failure',
      message: 'Invalid client_id'
    });
  }

  // Validate redirect_uri
  const redirectUriResult = validateRedirectUri(redirect_uri);
  if (!redirectUriResult.valid) {
    return res.status(400).json({
      status: 'failure',
      message: redirectUriResult.error
    });
  }

  // Parse scopes
  const delimiterChar = scope_delimiter === 'comma' ? ',' : (scope_delimiter === 'plus' ? '+' : ' ');
  const scopes = scope ? scope.split(delimiterChar).map(s => s.trim()).filter(s => s) : [];

  // Validate scopes if strict validation enabled
  if (scopeStore.strictValidation && scopes.length > 0) {
    const scopeValidation = validateScopes(scopes);
    if (!scopeValidation.valid) {
      return res.status(400).json({
        status: 'failure',
        message: scopeValidation.error,
        details: scopeValidation.details
      });
    }
  }

  // Generate authorization code
  const authCode = generateAuthCode();

  // Store auth code
  const codeData = {
    code: authCode,
    clientId: client_id,
    redirectUri: redirect_uri,
    scopes,
    scopeDelimiter: scope_delimiter || 'space',
    state,
    userId: username,
    created: Date.now(),
    expiresAt: Date.now() + 600000 // 10 minutes
  };

  if (code_challenge) {
    codeData.codeChallenge = code_challenge;
    codeData.codeChallengeMethod = code_challenge_method || 'plain';
  }

  tokenStore.authCodes.set(authCode, codeData);

  res.json({
    status: 'success',
    message: 'Authorization successful',
    code: authCode
  });
});

/**
 * Validate redirect URI format
 */
function isValidRedirectUri(uri) {
  if (!uri) return false;

  // Allow special OAuth OOB URI
  if (uri === 'urn:ietf:wg:oauth:2.0:oob') return true;

  // Allow custom schemes for mobile apps (e.g., myapp://callback)
  if (/^[a-z][a-z0-9+.-]*:\/\/.+/i.test(uri)) return true;

  return false;
}

/**
 * Validate redirect URI is registered - STRICT
 */
function validateRedirectUri(uri) {
  if (!uri) {
    return { valid: false, error: 'Missing redirect_uri parameter' };
  }

  if (!redirectUriStore.uris.has(uri)) {
    return {
      valid: false,
      error: 'Unregistered redirect_uri',
      details: {
        provided: uri,
        hint: 'Register this URI first via POST /oauth2/redirect-uris',
        registeredUris: Array.from(redirectUriStore.uris)
      }
    };
  }

  return { valid: true };
}

/**
 * Validate scopes are registered - STRICT (when enabled)
 */
function validateScopes(scopes) {
  if (!scopeStore.strictValidation) {
    return { valid: true, scopes };
  }

  const invalidScopes = scopes.filter(s => !scopeStore.scopes.has(s));

  if (invalidScopes.length > 0) {
    return {
      valid: false,
      error: 'Unregistered scope(s) requested',
      details: {
        invalidScopes,
        registeredScopes: Array.from(scopeStore.scopes),
        hint: 'Register scopes via POST /oauth2/scopes or disable strict validation via PUT /oauth2/scopes/validation'
      }
    };
  }

  return { valid: true, scopes };
}

// =============================================================================
// SCOPE DELIMITER DEFINITIONS
// =============================================================================
const SCOPE_DELIMITERS = {
  comma: ',',
  space: ' ',
  plus: '+'
};

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Parse scopes with specific delimiter - STRICT validation
 */
function parseScopes(scopeString, expectedDelimiter) {
  if (!scopeString) return { valid: true, scopes: [] };

  const delimiterChar = SCOPE_DELIMITERS[expectedDelimiter];
  const otherDelimiters = Object.entries(SCOPE_DELIMITERS)
    .filter(([key]) => key !== expectedDelimiter)
    .map(([, char]) => char);

  // Check if wrong delimiter is used
  for (const wrongDelim of otherDelimiters) {
    if (scopeString.includes(wrongDelim) && wrongDelim !== delimiterChar) {
      // Special case: space in URL might be encoded as +, but + delimiter is different
      if (wrongDelim === ' ' && expectedDelimiter === 'plus') continue;
      if (wrongDelim === '+' && expectedDelimiter === 'space') continue;

      return {
        valid: false,
        error: `Invalid scope delimiter. This endpoint requires "${expectedDelimiter}" delimiter (${delimiterChar}), but found "${wrongDelim}"`,
        expectedDelimiter,
        foundDelimiter: wrongDelim
      };
    }
  }

  const scopes = scopeString.split(delimiterChar).map(s => s.trim()).filter(s => s);
  return { valid: true, scopes };
}

/**
 * Format scopes with specific delimiter
 */
function formatScopes(scopes, delimiter) {
  return scopes.join(SCOPE_DELIMITERS[delimiter]);
}

/**
 * Validate Basic Auth - STRICT (header only, no body)
 */
function validateBasicAuth(req) {
  const authHeader = req.headers.authorization;
  const config = configManager.getConfig();
  const oauth2Config = config.credentials.oauth2;

  // Reject if credentials in body
  if (req.body.client_secret) {
    return { valid: false, error: 'Client Secret Basic requires credentials in Authorization header, not body' };
  }

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return { valid: false, error: 'Missing Basic Authorization header' };
  }

  try {
    const base64 = authHeader.split(' ')[1];
    const decoded = Buffer.from(base64, 'base64').toString('utf8');
    const [clientId, clientSecret] = decoded.split(':');

    if (clientId !== oauth2Config.clientId || clientSecret !== oauth2Config.clientSecret) {
      return { valid: false, error: 'Invalid client credentials' };
    }

    return { valid: true, clientId, method: 'client_secret_basic' };
  } catch (e) {
    return { valid: false, error: 'Invalid Basic auth format' };
  }
}

/**
 * Validate Post Auth - STRICT (body only, no header)
 */
function validatePostAuth(req) {
  const authHeader = req.headers.authorization;
  const config = configManager.getConfig();
  const oauth2Config = config.credentials.oauth2;

  // Reject if Basic auth header present
  if (authHeader && authHeader.startsWith('Basic ')) {
    return { valid: false, error: 'Client Secret Post requires credentials in body, not Authorization header' };
  }

  const { client_id, client_secret } = req.body;

  if (!client_id || !client_secret) {
    return { valid: false, error: 'Missing client_id or client_secret in request body' };
  }

  if (client_id !== oauth2Config.clientId || client_secret !== oauth2Config.clientSecret) {
    return { valid: false, error: 'Invalid client credentials' };
  }

  return { valid: true, clientId: client_id, method: 'client_secret_post' };
}

/**
 * Validate JWT Auth - STRICT (JWT only, no basic/post)
 */
function validateJWTAuth(req) {
  const authHeader = req.headers.authorization;
  const config = configManager.getConfig();
  const oauth2Config = config.credentials.oauth2;

  // Reject if Basic auth header present
  if (authHeader && authHeader.startsWith('Basic ')) {
    return { valid: false, error: 'Client Secret JWT requires client_assertion, not Basic Authorization header' };
  }

  // Reject if client_secret in body
  if (req.body.client_secret) {
    return { valid: false, error: 'Client Secret JWT requires client_assertion, not client_secret' };
  }

  const { client_assertion, client_assertion_type } = req.body;

  if (!client_assertion_type || client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
    return { valid: false, error: 'Invalid or missing client_assertion_type' };
  }

  if (!client_assertion) {
    return { valid: false, error: 'Missing client_assertion (JWT)' };
  }

  // Validate JWT format
  const jwtParts = client_assertion.split('.');
  if (jwtParts.length !== 3) {
    return { valid: false, error: 'Invalid JWT format' };
  }

  try {
    const payload = JSON.parse(Buffer.from(jwtParts[1], 'base64').toString('utf8'));
    const clientId = payload.sub || payload.iss;

    if (clientId !== oauth2Config.clientId) {
      return { valid: false, error: 'Invalid client_id in JWT' };
    }

    return { valid: true, clientId, method: 'client_secret_jwt' };
  } catch (e) {
    return { valid: false, error: 'Failed to decode JWT' };
  }
}

/**
 * Validate None Auth (PKCE only) - STRICT (no secret, requires PKCE)
 */
function validateNoneAuth(req, requirePKCE = true) {
  const authHeader = req.headers.authorization;
  const config = configManager.getConfig();
  const oauth2Config = config.credentials.oauth2;

  // Reject if any authentication is present
  if (authHeader && authHeader.startsWith('Basic ')) {
    return { valid: false, error: 'None authentication does not allow Authorization header' };
  }

  if (req.body.client_secret) {
    return { valid: false, error: 'None authentication does not allow client_secret' };
  }

  if (req.body.client_assertion) {
    return { valid: false, error: 'None authentication does not allow client_assertion' };
  }

  const { client_id, code_verifier } = req.body;

  if (!client_id) {
    return { valid: false, error: 'Missing client_id' };
  }

  if (client_id !== oauth2Config.clientId) {
    return { valid: false, error: 'Invalid client_id' };
  }

  if (requirePKCE && !code_verifier) {
    return { valid: false, error: 'None authentication requires PKCE (code_verifier)' };
  }

  return { valid: true, clientId: client_id, method: 'none' };
}

/**
 * Validate token in header - STRICT
 */
function validateTokenHeader(req) {
  const authHeader = req.headers.authorization;

  // Reject if token in query
  if (req.query.access_token) {
    return { valid: false, error: 'This endpoint requires token in Authorization header, not query string' };
  }

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { valid: false, error: 'Missing Bearer token in Authorization header' };
  }

  const token = authHeader.split(' ')[1];
  const tokenData = tokenStore.accessTokens.get(token);

  if (!tokenData) {
    return { valid: false, error: 'Invalid or expired access token' };
  }

  return { valid: true, token, tokenData };
}

/**
 * Validate token in query - STRICT
 */
function validateTokenQuery(req) {
  const authHeader = req.headers.authorization;

  // Reject if token in header
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return { valid: false, error: 'This endpoint requires token in query string, not Authorization header' };
  }

  const token = req.query.access_token;

  if (!token) {
    return { valid: false, error: 'Missing access_token in query string' };
  }

  const tokenData = tokenStore.accessTokens.get(token);

  if (!tokenData) {
    return { valid: false, error: 'Invalid or expired access token' };
  }

  return { valid: true, token, tokenData };
}

/**
 * Generate authorization code
 */
function generateAuthCode() {
  return 'auth_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

/**
 * Generate access token
 */
function generateAccessToken() {
  return 'access_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + '_' + Date.now();
}

/**
 * Generate refresh token
 */
function generateRefreshToken() {
  return 'refresh_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// =============================================================================
// ENDPOINT GENERATOR FUNCTIONS
// =============================================================================

/**
 * Create authorize endpoint for specific scope delimiter
 */
function createAuthorizeEndpoint(scopeDelimiter, requirePKCE = false) {
  return (req, res) => {
    const config = configManager.getConfig();
    const oauth2Config = config.credentials.oauth2;

    const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = req.query;

    // Check for direct/skip_login mode (for API testing without UI)
    const skipLogin = req.query.skip_login === 'true' || req.query.direct === 'true';

    // Validate required params
    if (response_type !== 'code') {
      return res.status(400).json({
        status: 'failure',
        message: 'response_type must be "code"',
        details: { endpoint: req.path }
      });
    }

    if (client_id !== oauth2Config.clientId) {
      return res.status(400).json({
        status: 'failure',
        message: 'Invalid client_id',
        details: { endpoint: req.path }
      });
    }

    // STRICT: Validate redirect_uri is registered
    const redirectUriResult = validateRedirectUri(redirect_uri);
    if (!redirectUriResult.valid) {
      return res.status(400).json({
        status: 'failure',
        message: redirectUriResult.error,
        details: redirectUriResult.details || { endpoint: req.path }
      });
    }

    // STRICT: Validate scope delimiter
    if (scope) {
      const scopeResult = parseScopes(scope, scopeDelimiter);
      if (!scopeResult.valid) {
        return res.status(400).json({
          status: 'failure',
          message: scopeResult.error,
          details: {
            endpoint: req.path,
            expectedDelimiter: scopeDelimiter,
            delimiterChar: SCOPE_DELIMITERS[scopeDelimiter],
            example: `scope=read${SCOPE_DELIMITERS[scopeDelimiter]}write${SCOPE_DELIMITERS[scopeDelimiter]}profile`
          }
        });
      }

      // STRICT: Validate scopes are registered
      const scopeValidation = validateScopes(scopeResult.scopes);
      if (!scopeValidation.valid) {
        return res.status(400).json({
          status: 'failure',
          message: scopeValidation.error,
          details: scopeValidation.details
        });
      }
    }

    // PKCE validation
    if (requirePKCE) {
      if (!code_challenge) {
        return res.status(400).json({
          status: 'failure',
          message: 'PKCE required: missing code_challenge',
          details: { endpoint: req.path }
        });
      }
    }

    // If skip_login is true, generate code directly (for API testing)
    if (skipLogin) {
      const authCode = generateAuthCode();
      const scopes = scope ? parseScopes(scope, scopeDelimiter).scopes : [];

      const codeData = {
        code: authCode,
        clientId: client_id,
        redirectUri: redirect_uri,
        scopes,
        scopeDelimiter,
        state,
        userId: 'api_test_user',
        created: Date.now(),
        expiresAt: Date.now() + 600000
      };

      if (code_challenge) {
        codeData.codeChallenge = code_challenge;
        codeData.codeChallengeMethod = code_challenge_method || 'plain';
      }

      tokenStore.authCodes.set(authCode, codeData);

      return res.json({
        status: 'success',
        message: 'Authorization code generated (skip_login mode)',
        details: {
          code: authCode,
          state,
          scope: formatScopes(scopes, scopeDelimiter),
          scopeDelimiter,
          expires_in: 600,
          redirect_uri
        }
      });
    }

    // Redirect to login UI page
    const loginUrl = new URL('/oauth2-login.html', `${req.protocol}://${req.get('host')}`);
    loginUrl.searchParams.set('response_type', response_type);
    loginUrl.searchParams.set('client_id', client_id);
    loginUrl.searchParams.set('redirect_uri', redirect_uri);
    if (scope) loginUrl.searchParams.set('scope', scope);
    if (state) loginUrl.searchParams.set('state', state);
    if (code_challenge) loginUrl.searchParams.set('code_challenge', code_challenge);
    if (code_challenge_method) loginUrl.searchParams.set('code_challenge_method', code_challenge_method);
    loginUrl.searchParams.set('scope_delimiter', scopeDelimiter);
    loginUrl.searchParams.set('auth_endpoint', req.path);

    res.redirect(loginUrl.toString());
  };
}

/**
 * Create token endpoint for specific auth method and scope delimiter
 */
function createTokenEndpoint(clientAuthMethod, scopeDelimiter, requirePKCE = false) {
  return (req, res) => {
    const { grant_type, code, redirect_uri, scope, code_verifier, refresh_token } = req.body;

    // Validate client authentication based on method
    let clientAuth;
    switch (clientAuthMethod) {
      case 'basic':
        clientAuth = validateBasicAuth(req);
        break;
      case 'post':
        clientAuth = validatePostAuth(req);
        break;
      case 'jwt':
        clientAuth = validateJWTAuth(req);
        break;
      case 'none':
        clientAuth = validateNoneAuth(req, requirePKCE);
        break;
      default:
        return res.status(400).json({ status: 'failure', message: 'Invalid auth method' });
    }

    if (!clientAuth.valid) {
      return res.status(401).json({
        status: 'failure',
        message: clientAuth.error,
        details: {
          endpoint: req.path,
          expectedAuthMethod: clientAuthMethod,
          hint: getAuthMethodHint(clientAuthMethod)
        }
      });
    }

    // STRICT: Validate scope delimiter if scope provided
    if (scope) {
      const scopeResult = parseScopes(scope, scopeDelimiter);
      if (!scopeResult.valid) {
        return res.status(400).json({
          status: 'failure',
          message: scopeResult.error,
          details: {
            endpoint: req.path,
            expectedDelimiter: scopeDelimiter,
            delimiterChar: SCOPE_DELIMITERS[scopeDelimiter]
          }
        });
      }

      // STRICT: Validate scopes are registered
      const scopeValidation = validateScopes(scopeResult.scopes);
      if (!scopeValidation.valid) {
        return res.status(400).json({
          status: 'failure',
          message: scopeValidation.error,
          details: scopeValidation.details
        });
      }
    }

    // Handle different grant types
    if (grant_type === 'authorization_code') {
      return handleAuthCodeGrant(req, res, clientAuth, scopeDelimiter, code_verifier);
    } else if (grant_type === 'client_credentials') {
      return handleClientCredentialsGrant(req, res, clientAuth, scopeDelimiter);
    } else if (grant_type === 'refresh_token') {
      return handleRefreshTokenGrant(req, res, clientAuth, scopeDelimiter);
    } else {
      return res.status(400).json({
        status: 'failure',
        message: `Unsupported grant_type: ${grant_type}`,
        details: { supported: ['authorization_code', 'client_credentials', 'refresh_token'] }
      });
    }
  };
}

/**
 * Handle Authorization Code Grant
 */
function handleAuthCodeGrant(req, res, clientAuth, scopeDelimiter, code_verifier) {
  const { code, redirect_uri } = req.body;

  if (!code) {
    return res.status(400).json({ status: 'failure', message: 'Missing authorization code' });
  }

  const codeData = tokenStore.authCodes.get(code);

  if (!codeData) {
    return res.status(400).json({ status: 'failure', message: 'Invalid or expired authorization code' });
  }

  // STRICT: Validate redirect_uri matches the one used during authorization
  if (codeData.redirectUri && redirect_uri !== codeData.redirectUri) {
    return res.status(400).json({
      status: 'failure',
      message: 'redirect_uri mismatch',
      details: {
        error: 'The redirect_uri must match the one used during authorization',
        expected: codeData.redirectUri,
        provided: redirect_uri
      }
    });
  }

  // Validate PKCE if code was issued with challenge
  if (codeData.codeChallenge) {
    if (!code_verifier) {
      return res.status(400).json({ status: 'failure', message: 'Missing code_verifier (PKCE required)' });
    }
    // Mock PKCE validation (in production, would verify challenge)
  }

  // Generate tokens
  const accessToken = generateAccessToken();
  const refreshToken = generateRefreshToken();

  // Store tokens
  tokenStore.accessTokens.set(accessToken, {
    clientId: clientAuth.clientId,
    scopes: codeData.scopes,
    scopeDelimiter,
    authMethod: clientAuth.method,
    created: Date.now(),
    expiresAt: Date.now() + 3600000
  });

  tokenStore.refreshTokens.set(refreshToken, {
    clientId: clientAuth.clientId,
    scopes: codeData.scopes,
    scopeDelimiter,
    accessToken
  });

  // Remove used auth code
  tokenStore.authCodes.delete(code);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: formatScopes(codeData.scopes, scopeDelimiter),
    scope_delimiter: scopeDelimiter
  });
}

/**
 * Handle Client Credentials Grant
 */
function handleClientCredentialsGrant(req, res, clientAuth, scopeDelimiter) {
  const { scope } = req.body;

  const scopes = scope ? parseScopes(scope, scopeDelimiter).scopes : ['read'];
  const accessToken = generateAccessToken();

  tokenStore.accessTokens.set(accessToken, {
    clientId: clientAuth.clientId,
    scopes,
    scopeDelimiter,
    authMethod: clientAuth.method,
    created: Date.now(),
    expiresAt: Date.now() + 3600000
  });

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: formatScopes(scopes, scopeDelimiter),
    scope_delimiter: scopeDelimiter
  });
}

/**
 * Handle Refresh Token Grant
 */
function handleRefreshTokenGrant(req, res, clientAuth, scopeDelimiter) {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(400).json({ status: 'failure', message: 'Missing refresh_token' });
  }

  const tokenData = tokenStore.refreshTokens.get(refresh_token);

  if (!tokenData) {
    return res.status(400).json({ status: 'failure', message: 'Invalid refresh_token' });
  }

  // Generate new access token
  const newAccessToken = generateAccessToken();

  tokenStore.accessTokens.set(newAccessToken, {
    clientId: clientAuth.clientId,
    scopes: tokenData.scopes,
    scopeDelimiter,
    authMethod: clientAuth.method,
    created: Date.now(),
    expiresAt: Date.now() + 3600000
  });

  // Update refresh token reference
  tokenStore.refreshTokens.set(refresh_token, {
    ...tokenData,
    accessToken: newAccessToken
  });

  res.json({
    access_token: newAccessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: formatScopes(tokenData.scopes, scopeDelimiter),
    scope_delimiter: scopeDelimiter
  });
}

/**
 * Create test endpoint for header token placement
 */
function createTestHeaderEndpoint(scopeDelimiter) {
  return (req, res) => {
    const tokenResult = validateTokenHeader(req);

    if (!tokenResult.valid) {
      return res.status(401).json({
        status: 'failure',
        message: tokenResult.error,
        details: {
          endpoint: req.path,
          tokenPlacement: 'header',
          hint: 'Use Authorization: Bearer <token>'
        }
      });
    }

    res.json({
      status: 'success',
      message: 'Token validated successfully',
      details: {
        tokenPlacement: 'header',
        scopeDelimiter,
        scopes: formatScopes(tokenResult.tokenData.scopes, scopeDelimiter),
        authMethod: tokenResult.tokenData.authMethod,
        expiresIn: Math.floor((tokenResult.tokenData.expiresAt - Date.now()) / 1000)
      }
    });
  };
}

/**
 * Create test endpoint for query token placement
 */
function createTestQueryEndpoint(scopeDelimiter) {
  return (req, res) => {
    const tokenResult = validateTokenQuery(req);

    if (!tokenResult.valid) {
      return res.status(401).json({
        status: 'failure',
        message: tokenResult.error,
        details: {
          endpoint: req.path,
          tokenPlacement: 'query',
          hint: 'Use ?access_token=<token>'
        }
      });
    }

    res.json({
      status: 'success',
      message: 'Token validated successfully',
      details: {
        tokenPlacement: 'query',
        scopeDelimiter,
        scopes: formatScopes(tokenResult.tokenData.scopes, scopeDelimiter),
        authMethod: tokenResult.tokenData.authMethod,
        expiresIn: Math.floor((tokenResult.tokenData.expiresAt - Date.now()) / 1000)
      }
    });
  };
}

/**
 * Get hint for auth method
 */
function getAuthMethodHint(method) {
  switch (method) {
    case 'basic':
      return 'Use Authorization: Basic base64(client_id:client_secret)';
    case 'post':
      return 'Include client_id and client_secret in request body';
    case 'jwt':
      return 'Include client_assertion and client_assertion_type in request body';
    case 'none':
      return 'Include only client_id (and code_verifier for PKCE) in request body';
    default:
      return '';
  }
}

// =============================================================================
// REGISTER ALL ENDPOINTS
// =============================================================================

// Scope delimiters
const delimiters = ['comma', 'space', 'plus'];

// Client auth methods
const authMethods = ['basic', 'post', 'jwt'];

// =============================================================================
// 1. AUTHORIZATION CODE ENDPOINTS
// =============================================================================

delimiters.forEach(delimiter => {
  // Authorize endpoint (one per delimiter)
  router.get(`/auth-code/${delimiter}/authorize`, createAuthorizeEndpoint(delimiter, false));

  authMethods.forEach(authMethod => {
    // Token endpoint
    router.post(`/auth-code/${authMethod}/${delimiter}/token`, createTokenEndpoint(authMethod, delimiter, false));

    // Test endpoints
    router.get(`/auth-code/${authMethod}/${delimiter}/test/header`, createTestHeaderEndpoint(delimiter));
    router.get(`/auth-code/${authMethod}/${delimiter}/test/query`, createTestQueryEndpoint(delimiter));
  });
});

// =============================================================================
// 2. AUTHORIZATION CODE + PKCE ENDPOINTS
// =============================================================================

delimiters.forEach(delimiter => {
  // Authorize endpoint with PKCE required
  router.get(`/auth-code-pkce/${delimiter}/authorize`, createAuthorizeEndpoint(delimiter, true));

  // All auth methods including 'none' for PKCE
  [...authMethods, 'none'].forEach(authMethod => {
    // Token endpoint
    router.post(`/auth-code-pkce/${authMethod}/${delimiter}/token`, createTokenEndpoint(authMethod, delimiter, true));

    // Test endpoints
    router.get(`/auth-code-pkce/${authMethod}/${delimiter}/test/header`, createTestHeaderEndpoint(delimiter));
    router.get(`/auth-code-pkce/${authMethod}/${delimiter}/test/query`, createTestQueryEndpoint(delimiter));
  });
});

// =============================================================================
// 3. CLIENT CREDENTIALS ENDPOINTS
// =============================================================================

delimiters.forEach(delimiter => {
  authMethods.forEach(authMethod => {
    // Token endpoint (no authorize needed)
    router.post(`/client-creds/${authMethod}/${delimiter}/token`, createTokenEndpoint(authMethod, delimiter, false));

    // Test endpoints
    router.get(`/client-creds/${authMethod}/${delimiter}/test/header`, createTestHeaderEndpoint(delimiter));
    router.get(`/client-creds/${authMethod}/${delimiter}/test/query`, createTestQueryEndpoint(delimiter));
  });
});

// =============================================================================
// ENDPOINT LISTING
// =============================================================================

router.get('/endpoints', (req, res) => {
  const endpoints = {
    redirectUriManagement: {
      list: 'GET /oauth2/redirect-uris',
      add: 'POST /oauth2/redirect-uris { "redirect_uri": "..." }',
      update: 'PUT /oauth2/redirect-uris { "old_redirect_uri": "...", "new_redirect_uri": "..." }',
      remove: 'DELETE /oauth2/redirect-uris { "redirect_uri": "..." }',
      reset: 'POST /oauth2/redirect-uris/reset'
    },
    scopeManagement: {
      list: 'GET /oauth2/scopes',
      add: 'POST /oauth2/scopes { "scope": "..." }',
      addBulk: 'POST /oauth2/scopes/bulk { "scopes": ["...", "..."] }',
      update: 'PUT /oauth2/scopes { "old_scope": "...", "new_scope": "..." }',
      remove: 'DELETE /oauth2/scopes { "scope": "..." }',
      reset: 'POST /oauth2/scopes/reset',
      toggleValidation: 'PUT /oauth2/scopes/validation { "strict": true/false }'
    },
    authorizationCode: {},
    authorizationCodePKCE: {},
    clientCredentials: {}
  };

  delimiters.forEach(delimiter => {
    endpoints.authorizationCode[delimiter] = {
      authorize: `/oauth2/auth-code/${delimiter}/authorize`,
      token: authMethods.map(auth => `/oauth2/auth-code/${auth}/${delimiter}/token`),
      testHeader: authMethods.map(auth => `/oauth2/auth-code/${auth}/${delimiter}/test/header`),
      testQuery: authMethods.map(auth => `/oauth2/auth-code/${auth}/${delimiter}/test/query`)
    };

    endpoints.authorizationCodePKCE[delimiter] = {
      authorize: `/oauth2/auth-code-pkce/${delimiter}/authorize`,
      token: [...authMethods, 'none'].map(auth => `/oauth2/auth-code-pkce/${auth}/${delimiter}/token`),
      testHeader: [...authMethods, 'none'].map(auth => `/oauth2/auth-code-pkce/${auth}/${delimiter}/test/header`),
      testQuery: [...authMethods, 'none'].map(auth => `/oauth2/auth-code-pkce/${auth}/${delimiter}/test/query`)
    };

    endpoints.clientCredentials[delimiter] = {
      token: authMethods.map(auth => `/oauth2/client-creds/${auth}/${delimiter}/token`),
      testHeader: authMethods.map(auth => `/oauth2/client-creds/${auth}/${delimiter}/test/header`),
      testQuery: authMethods.map(auth => `/oauth2/client-creds/${auth}/${delimiter}/test/query`)
    };
  });

  res.json({
    status: 'success',
    message: 'OAuth2 strict endpoints',
    totalEndpoints:
      (3 * 3 * 3 * 3) + // auth-code: 3 delimiters × 3 auth × (token + 2 test) + 3 authorize
      (3 * 4 * 3 * 3) + // auth-code-pkce: 3 delimiters × 4 auth × 3 + 3 authorize
      (3 * 3 * 3),      // client-creds: 3 delimiters × 3 auth × 3
    registeredRedirectUris: Array.from(redirectUriStore.uris),
    registeredScopes: Array.from(scopeStore.scopes),
    strictScopeValidation: scopeStore.strictValidation,
    endpoints,
    scopeDelimiters: {
      comma: 'scope=read,write,profile',
      space: 'scope=read write profile',
      plus: 'scope=read+write+profile'
    },
    clientAuthMethods: {
      basic: 'Authorization: Basic base64(client_id:client_secret)',
      post: 'client_id & client_secret in body',
      jwt: 'client_assertion & client_assertion_type in body',
      none: 'Only client_id in body (PKCE only)'
    },
    tokenPlacement: {
      header: 'Authorization: Bearer <token>',
      query: '?access_token=<token>'
    }
  });
});

module.exports = router;

