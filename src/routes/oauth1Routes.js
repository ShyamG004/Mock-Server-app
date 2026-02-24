/**
 * OAuth 1.0 Routes
 *
 * OAuth1 ONLY supports Authorization header for OAuth parameters.
 * All endpoints require: Authorization: OAuth oauth_consumer_key="...", ...
 *
 * Endpoints:
 * - /oauth1/request-token - Get request token
 * - /oauth1/authorize - User authorization
 * - /oauth1/access-token - Exchange for access token
 * - /oauth1/test - Test OAuth1 signature
 * - /oauth1/echo - Debug endpoint
 */

const express = require('express');
const router = express.Router();
const configManager = require('../config/configManager');
const logger = require('../utils/logger');
const crypto = require('crypto-js');

// In-memory token store
const tokenStore = {
  requestTokens: new Map(),
  accessTokens: new Map()
};

// =============================================================================
// OAuth1 FLOW ENDPOINTS (All require Authorization header)
// =============================================================================

/**
 * @swagger
 * /oauth1/request-token:
 *   post:
 *     summary: Get OAuth1 request token
 *     tags: [OAuth1]
 *     responses:
 *       200:
 *         description: Request token issued
 */
router.post('/request-token', validateOAuth1Signature, (req, res) => {
  const requestToken = generateToken('rt');
  const requestTokenSecret = generateToken('rts');

  // Get oauth_callback from OAuth params (from Authorization header)
  const oauthCallback = req.oauth1Params.oauth_callback || req.body.oauth_callback || req.query.oauth_callback;

  // Store request token with callback (NO validation - accept any callback)
  tokenStore.requestTokens.set(requestToken, {
    secret: requestTokenSecret,
    created: Date.now(),
    consumerKey: req.oauth1Params.oauth_consumer_key,
    callback: oauthCallback || null
  });

  // Clean up old tokens
  cleanupExpiredTokens();

  // OAuth1 standard response format: URL-encoded form
  res.set('Content-Type', 'application/x-www-form-urlencoded');
  res.send(`oauth_token=${encodeURIComponent(requestToken)}&oauth_token_secret=${encodeURIComponent(requestTokenSecret)}&oauth_callback_confirmed=true`);
});

/**
 * @swagger
 * /oauth1/authorize:
 *   get:
 *     summary: OAuth1 authorization endpoint - Shows login UI
 *     tags: [OAuth1]
 */
router.get('/authorize', (req, res) => {
  const { oauth_token, skip_login } = req.query;
  // oauth_callback can come from query OR from stored token data
  let oauth_callback = req.query.oauth_callback;

  if (!oauth_token) {
    return res.status(400).json({
      status: 'failure',
      message: 'Missing oauth_token parameter',
      details: {
        hint: 'First call /oauth1/request-token to get an oauth_token'
      }
    });
  }

  const tokenData = tokenStore.requestTokens.get(oauth_token);
  if (!tokenData) {
    return res.status(400).json({
      status: 'failure',
      message: 'Invalid or expired request token',
      details: {}
    });
  }

  // Use stored callback if not provided in query (OAuth1.0a standard)
  if (!oauth_callback && tokenData.callback) {
    oauth_callback = tokenData.callback;
  }

  // Skip login mode for API testing
  if (skip_login === 'true') {
    const verifier = generateToken('ver');
    tokenData.verifier = verifier;
    tokenData.authorized = true;

    if (oauth_callback && oauth_callback !== 'oob') {
      try {
        const callbackUrl = new URL(oauth_callback);
        callbackUrl.searchParams.set('oauth_token', oauth_token);
        callbackUrl.searchParams.set('oauth_verifier', verifier);
        return res.redirect(callbackUrl.toString());
      } catch (e) {
        // If URL parsing fails, append params manually
        const separator = oauth_callback.includes('?') ? '&' : '?';
        return res.redirect(`${oauth_callback}${separator}oauth_token=${encodeURIComponent(oauth_token)}&oauth_verifier=${encodeURIComponent(verifier)}`);
      }
    }

    return res.json({
      status: 'success',
      message: 'Authorization successful (skip_login mode)',
      details: {
        oauth_token,
        oauth_verifier: verifier
      }
    });
  }

  // Redirect to login UI page
  const loginUrl = new URL('/oauth1-login.html', `${req.protocol}://${req.get('host')}`);
  loginUrl.searchParams.set('oauth_token', oauth_token);
  if (oauth_callback && oauth_callback !== 'oob') {
    loginUrl.searchParams.set('oauth_callback', oauth_callback);
  }

  res.redirect(loginUrl.toString());
});

/**
 * @swagger
 * /oauth1/authorize/submit:
 *   post:
 *     summary: Handle OAuth1 authorization form submission (like Tumblr)
 *     tags: [OAuth1]
 */
router.post('/authorize/submit', (req, res) => {
  const config = configManager.getConfig();
  const basicCreds = config.credentials.basic;
  const isJsonRequest = req.headers['content-type']?.includes('application/json');

  const { username, password, oauth_token, oauth_callback } = req.body;

  logger.info('OAuth1 authorize/submit called', {
    oauth_token: oauth_token ? oauth_token.substring(0, 10) + '...' : '[MISSING]',
    oauth_callback: oauth_callback ? '[PRESENT]' : '[MISSING]',
    username: username || '[MISSING]',
    isJsonRequest
  });

  // Get token data first to retrieve stored callback
  const tokenData = oauth_token ? tokenStore.requestTokens.get(oauth_token) : null;

  // Use callback from form or from stored token data
  const finalCallback = oauth_callback || (tokenData ? tokenData.callback : null);

  // Validate user credentials
  if (username !== basicCreds.username || password !== basicCreds.password) {
    logger.info('Invalid credentials');
    if (isJsonRequest) {
      return res.status(401).json({
        status: 'failure',
        message: 'Invalid username or password'
      });
    }
    // Redirect back to login page with error
    const loginUrl = `/oauth1-login.html?oauth_token=${encodeURIComponent(oauth_token || '')}&error=${encodeURIComponent('Invalid username or password')}`;
    if (finalCallback) {
      return res.redirect(loginUrl + `&oauth_callback=${encodeURIComponent(finalCallback)}`);
    }
    return res.redirect(loginUrl);
  }

  // Validate oauth_token
  if (!oauth_token || !tokenData) {
    logger.info('Invalid or missing oauth_token');
    if (isJsonRequest) {
      return res.status(400).json({
        status: 'failure',
        message: 'Invalid or expired request token. Please start the OAuth flow again.'
      });
    }
    return res.status(400).send('Invalid or expired request token. Please start the OAuth flow again.');
  }

  // Generate verifier
  const verifier = generateToken('ver');
  tokenData.verifier = verifier;
  tokenData.authorized = true;
  tokenData.userId = username;

  logger.info('Authorization successful', {
    verifier: verifier.substring(0, 10) + '...',
    callback: finalCallback ? 'YES' : 'NO'
  });

  // For JSON requests (fetch API), return JSON response
  if (isJsonRequest) {
    if (finalCallback && finalCallback !== 'oob') {
      const separator = finalCallback.indexOf('?') >= 0 ? '&' : '?';
      const redirectUrl = `${finalCallback}${separator}oauth_token=${encodeURIComponent(oauth_token)}&oauth_verifier=${encodeURIComponent(verifier)}`;
      return res.json({
        status: 'success',
        message: 'Authorization successful',
        oauth_token: oauth_token,
        oauth_verifier: verifier,
        redirect_url: redirectUrl
      });
    }
    return res.json({
      status: 'success',
      message: 'Authorization successful',
      oauth_token: oauth_token,
      oauth_verifier: verifier
    });
  }

  // For form submissions, redirect to callback
  if (finalCallback && finalCallback !== 'oob') {
    const separator = finalCallback.indexOf('?') >= 0 ? '&' : '?';
    const redirectUrl = `${finalCallback}${separator}oauth_token=${encodeURIComponent(oauth_token)}&oauth_verifier=${encodeURIComponent(verifier)}`;
    logger.info('Sending 302 redirect to callback', { redirectUrl });

    // Use explicit 302 redirect
    res.writeHead(302, { 'Location': redirectUrl });
    res.end();
    return;
  }

  // No callback - show verifier code (OOB flow)
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Authorization Successful</title></head>
    <body style="font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f0f0f0;">
      <div style="background: white; padding: 40px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
        <h2 style="color: #38a169;">✅ Authorization Successful</h2>
        <p>Your verification code:</p>
        <code style="display: block; background: #edf2f7; padding: 15px; border-radius: 5px; font-size: 18px; margin: 20px 0;">${verifier}</code>
        <p style="color: #718096; font-size: 14px;">Copy this code to your application to complete authorization.</p>
      </div>
    </body>
    </html>
  `);
});

/**
 * @swagger
 * /oauth1/authorize/login:
 *   post:
 *     summary: Handle OAuth1 login form submission (legacy endpoint)
 *     tags: [OAuth1]
 */
router.post('/authorize/login', (req, res) => {
  const config = configManager.getConfig();
  const basicCreds = config.credentials.basic;

  const { username, password, oauth_token, oauth_callback } = req.body;

  logger.info('OAuth1 authorize/login called', {
    oauth_token: oauth_token ? '[PRESENT]' : '[MISSING]',
    oauth_callback: oauth_callback ? '[PRESENT]' : '[MISSING]',
    username: username ? '[PRESENT]' : '[MISSING]'
  });

  // Validate user credentials
  if (username !== basicCreds.username || password !== basicCreds.password) {
    logger.info('Invalid credentials');
    // For form submission, redirect back with error
    if (req.headers['content-type']?.includes('application/x-www-form-urlencoded')) {
      const loginUrl = new URL('/oauth1-login.html', `${req.protocol}://${req.get('host')}`);
      loginUrl.searchParams.set('oauth_token', oauth_token || '');
      if (oauth_callback) loginUrl.searchParams.set('oauth_callback', oauth_callback);
      loginUrl.searchParams.set('error', 'Invalid username or password');
      return res.redirect(loginUrl.toString());
    }
    return res.status(401).json({
      status: 'failure',
      message: 'Invalid username or password'
    });
  }

  // Validate oauth_token
  if (!oauth_token) {
    logger.info('Missing oauth_token');
    return res.status(400).json({
      status: 'failure',
      message: 'Missing oauth_token'
    });
  }

  const tokenData = tokenStore.requestTokens.get(oauth_token);
  if (!tokenData) {
    logger.info('Invalid or expired request token');
    return res.status(400).json({
      status: 'failure',
      message: 'Invalid or expired request token'
    });
  }

  // Use callback from request body or from stored token data
  const finalCallback = oauth_callback || tokenData.callback;
  logger.info('Final callback URL', { finalCallback });

  // Generate verifier and authorize token
  const verifier = generateToken('ver');
  tokenData.verifier = verifier;
  tokenData.authorized = true;
  tokenData.userId = username;

  logger.info('Generated verifier', { verifier });

  // If callback exists, redirect directly (like Tumblr does)
  if (finalCallback && finalCallback !== 'oob') {
    // Build redirect URL by appending oauth params
    let redirectUrl;

    // Check if callback already has query params
    if (finalCallback.indexOf('?') !== -1) {
      // Append with &
      redirectUrl = finalCallback + '&oauth_token=' + encodeURIComponent(oauth_token) + '&oauth_verifier=' + encodeURIComponent(verifier);
    } else {
      // Append with ?
      redirectUrl = finalCallback + '?oauth_token=' + encodeURIComponent(oauth_token) + '&oauth_verifier=' + encodeURIComponent(verifier);
    }

    logger.info('Redirecting to callback', { redirectUrl });
    return res.redirect(redirectUrl);
  }

  // No callback (oob flow) - return JSON with verifier
  logger.info('OOB flow - returning JSON');
  res.json({
    status: 'success',
    message: 'Authorization successful',
    oauth_token,
    oauth_verifier: verifier,
    oauth_callback: null
  });
});

/**
 * @swagger
 * /oauth1/access-token:
 *   post:
 *     summary: Exchange request token for access token
 *     tags: [OAuth1]
 */
router.post('/access-token', validateOAuth1Signature, (req, res) => {
  const oauthParams = req.oauth1Params;
  const oauthToken = oauthParams.oauth_token;
  const oauthVerifier = oauthParams.oauth_verifier || req.body.oauth_verifier;

  if (!oauthToken) {
    return res.status(400).json({
      status: 'failure',
      message: 'Missing oauth_token',
      details: {}
    });
  }

  const requestTokenData = tokenStore.requestTokens.get(oauthToken);

  if (!requestTokenData) {
    return res.status(400).json({
      status: 'failure',
      message: 'Invalid request token',
      details: {}
    });
  }

  if (!requestTokenData.authorized) {
    return res.status(400).json({
      status: 'failure',
      message: 'Request token not authorized',
      details: {}
    });
  }

  if (requestTokenData.verifier !== oauthVerifier) {
    return res.status(400).json({
      status: 'failure',
      message: 'Invalid oauth_verifier',
      details: {}
    });
  }

  // Generate access token
  const accessToken = generateToken('at');
  const accessTokenSecret = generateToken('ats');

  // Store access token
  tokenStore.accessTokens.set(accessToken, {
    secret: accessTokenSecret,
    created: Date.now(),
    consumerKey: requestTokenData.consumerKey
  });

  // Remove used request token
  tokenStore.requestTokens.delete(oauthToken);

  // OAuth1 standard response format: URL-encoded form
  res.set('Content-Type', 'application/x-www-form-urlencoded');
  res.send(`oauth_token=${encodeURIComponent(accessToken)}&oauth_token_secret=${encodeURIComponent(accessTokenSecret)}`);
});

/**
 * @swagger
 * /oauth1/test:
 *   get:
 *     summary: Test OAuth1 authentication
 *     tags: [OAuth1]
 */
router.get('/test', validateOAuth1Signature, validateAccessToken, (req, res) => {
  const config = configManager.getConfig();

  res.json({
    status: 'success',
    message: 'OAuth1 authentication successful',
    details: {
      authType: 'OAuth1',
      validatedParams: Object.keys(req.oauth1Params).length,
      dynamicParams: 3, // nonce, timestamp, signature
      consumerKey: req.oauth1Params.oauth_consumer_key,
      signatureMethod: req.oauth1Params.oauth_signature_method,
      params: {
        oauth_consumer_key: req.oauth1Params.oauth_consumer_key,
        oauth_nonce: req.oauth1Params.oauth_nonce,
        oauth_timestamp: req.oauth1Params.oauth_timestamp,
        oauth_signature_method: req.oauth1Params.oauth_signature_method,
        oauth_version: req.oauth1Params.oauth_version
      }
    }
  });
});

/**
 * @swagger
 * /oauth1/test:
 *   post:
 *     summary: Test OAuth1 authentication with body
 *     tags: [OAuth1]
 */
router.post('/test', validateOAuth1Signature, (req, res) => {
  const config = configManager.getConfig();
  const dynamicParams = identifyDynamicParams(req, config);

  res.json({
    status: 'success',
    message: 'OAuth1 authentication successful',
    details: {
      authType: 'OAuth1',
      validatedParams: Object.keys(req.oauth1Params).length + Object.keys(req.body || {}).length,
      dynamicParams: dynamicParams.length + 3, // +3 for nonce, timestamp, signature
      expectedParams: config.totalParams,
      expectedDynamicParams: config.dynamicParams,
      oauthParams: req.oauth1Params,
      bodyParams: Object.keys(req.body || {}).length
    }
  });
});

/**
 * @swagger
 * /oauth1/test-params:
 *   post:
 *     summary: Test OAuth1 with additional parameters
 *     tags: [OAuth1]
 */
router.post('/test-params', validateOAuth1Signature, (req, res) => {
  const config = configManager.getConfig();

  // Count all parameters
  const oauthParamCount = Object.keys(req.oauth1Params).length;
  const bodyParamCount = Object.keys(req.body || {}).length;
  const queryParamCount = Object.keys(req.query).length;

  const dynamicParams = identifyDynamicParams(req, config);

  res.json({
    status: 'success',
    message: 'OAuth1 with parameters successful',
    details: {
      authType: 'OAuth1',
      totalParams: oauthParamCount + bodyParamCount + queryParamCount,
      oauthParams: oauthParamCount,
      bodyParams: bodyParamCount,
      queryParams: queryParamCount,
      dynamicParams: dynamicParams.length + 3,
      expectedParams: config.totalParams,
      expectedDynamicParams: config.dynamicParams,
      validation: {
        signatureValid: true,
        timestampValid: validateTimestamp(req.oauth1Params.oauth_timestamp),
        nonceValid: req.oauth1Params.oauth_nonce && req.oauth1Params.oauth_nonce.length >= 8
      }
    }
  });
});

/**
 * @swagger
 * /oauth1/echo:
 *   post:
 *     summary: Echo OAuth1 parameters for debugging
 *     tags: [OAuth1]
 */
router.post('/echo', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const oauthParams = parseOAuth1Header(authHeader);

  res.json({
    status: 'success',
    message: 'OAuth1 echo response',
    details: {
      receivedHeader: authHeader,
      parsedParams: oauthParams,
      queryParams: req.query,
      bodyParams: req.body,
      method: req.method,
      url: req.originalUrl
    }
  });
});

/**
 * Middleware to validate OAuth1 signature
 */
function validateOAuth1Signature(req, res, next) {
  const config = configManager.getConfig();
  const oauth1Config = config.credentials.oauth1;

  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('OAuth ')) {
    return res.status(401).json({
      status: 'failure',
      message: 'Missing OAuth1 Authorization header',
      details: {
        expected: 'Authorization: OAuth oauth_consumer_key="...", oauth_nonce="...", ...'
      }
    });
  }

  const oauthParams = parseOAuth1Header(authHeader);
  const errors = [];

  // Validate required parameters
  const requiredParams = [
    'oauth_consumer_key',
    'oauth_nonce',
    'oauth_timestamp',
    'oauth_signature',
    'oauth_signature_method'
  ];

  for (const param of requiredParams) {
    if (!oauthParams[param]) {
      errors.push(`Missing required parameter: ${param}`);
    }
  }

  // Validate consumer key
  if (oauthParams.oauth_consumer_key && oauthParams.oauth_consumer_key !== oauth1Config.consumerKey) {
    errors.push('Invalid consumer key');
  }

  // Validate timestamp
  if (oauthParams.oauth_timestamp && !validateTimestamp(oauthParams.oauth_timestamp)) {
    errors.push('OAuth1 timestamp expired (must be within 5 minutes)');
  }

  // Validate nonce length
  if (oauthParams.oauth_nonce && oauthParams.oauth_nonce.length < 8) {
    errors.push('OAuth1 nonce too short (minimum 8 characters)');
  }

  // Validate signature method
  const validMethods = ['HMAC-SHA1', 'HMAC-SHA256', 'PLAINTEXT'];
  if (oauthParams.oauth_signature_method && !validMethods.includes(oauthParams.oauth_signature_method)) {
    errors.push(`Invalid signature method. Valid: ${validMethods.join(', ')}`);
  }

  // Mock signature validation (accept any non-empty signature)
  if (!oauthParams.oauth_signature || oauthParams.oauth_signature.length === 0) {
    errors.push('Invalid signature');
  }

  if (errors.length > 0) {
    return res.status(401).json({
      status: 'failure',
      message: 'OAuth1 signature validation failed',
      details: {
        errors,
        providedParams: Object.keys(oauthParams)
      }
    });
  }

  req.oauth1Params = oauthParams;
  next();
}

/**
 * Middleware to validate access token
 */
function validateAccessToken(req, res, next) {
  const oauthToken = req.oauth1Params.oauth_token;

  if (!oauthToken) {
    return res.status(401).json({
      status: 'failure',
      message: 'Missing oauth_token',
      details: {}
    });
  }

  const tokenData = tokenStore.accessTokens.get(oauthToken);

  if (!tokenData) {
    return res.status(401).json({
      status: 'failure',
      message: 'Invalid or expired access token',
      details: {}
    });
  }

  req.tokenData = tokenData;
  next();
}

/**
 * Parse OAuth1 Authorization header
 */
function parseOAuth1Header(header) {
  const params = {};

  if (!header || !header.startsWith('OAuth ')) {
    return params;
  }

  const oauthPart = header.replace('OAuth ', '');
  const pairs = oauthPart.split(',').map(p => p.trim());

  for (const pair of pairs) {
    const eqIndex = pair.indexOf('=');
    if (eqIndex > 0) {
      const key = pair.substring(0, eqIndex).trim();
      let value = pair.substring(eqIndex + 1).trim();
      // Remove surrounding quotes
      value = value.replace(/^["']|["']$/g, '');
      // URL decode
      try {
        value = decodeURIComponent(value);
      } catch (e) {
        // Keep original value if decode fails
      }
      params[key] = value;
    }
  }

  return params;
}

/**
 * Validate OAuth1 timestamp
 */
function validateTimestamp(timestamp) {
  if (!timestamp) return false;

  const ts = parseInt(timestamp, 10);
  const now = Math.floor(Date.now() / 1000);

  // Allow 5 minutes tolerance
  return Math.abs(now - ts) <= 300;
}

/**
 * Generate random token
 */
function generateToken(prefix = 'tok') {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = prefix + '_';
  for (let i = 0; i < 32; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

/**
 * Cleanup expired tokens
 */
function cleanupExpiredTokens() {
  const now = Date.now();
  const maxAge = 600000; // 10 minutes for request tokens

  for (const [token, data] of tokenStore.requestTokens) {
    if (now - data.created > maxAge) {
      tokenStore.requestTokens.delete(token);
    }
  }
}

/**
 * Identify dynamic parameters
 */
function identifyDynamicParams(req, config) {
  const dynamicParams = [];
  const allParams = { ...req.query, ...req.body };

  for (const [key, value] of Object.entries(allParams)) {
    if (typeof value === 'string' || typeof value === 'number') {
      const strValue = String(value);

      if (/^\d{10,13}$/.test(strValue)) {
        dynamicParams.push({ name: key, type: 'timestamp' });
      } else if (/^[a-f0-9]{32}$/i.test(strValue)) {
        dynamicParams.push({ name: key, type: 'nonce' });
      } else if (/^[a-f0-9-]{36}$/i.test(strValue)) {
        dynamicParams.push({ name: key, type: 'uuid' });
      }
    }
  }

  return dynamicParams;
}

module.exports = router;

