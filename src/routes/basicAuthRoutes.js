/**
 * Basic Authentication Routes
 *
 * Basic Authentication ONLY supports Authorization header.
 * Format: Authorization: Basic base64(username:password)
 *
 * Endpoints:
 * - /basic/header - Strict endpoint (Authorization header only)
 * - /basic/test - Test endpoint with additional params support
 */

const express = require('express');
const router = express.Router();
const configManager = require('../config/configManager');
const logger = require('../utils/logger');

// =============================================================================
// STRICT ENDPOINT - Authorization Header ONLY
// =============================================================================

/**
 * @swagger
 * /basic/header:
 *   get:
 *     summary: Test Basic Auth - Authorization Header ONLY
 *     tags: [Basic Auth]
 *     description: Basic Authentication only supports Authorization header
 */
router.get('/header', (req, res) => {
  const config = configManager.getConfig();
  const basicConfig = config.credentials.basic;
  const authHeader = req.headers.authorization;

  // STRICT: Check Authorization header
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return res.status(401).json({
      status: 'failure',
      message: 'Missing Basic Authorization header',
      details: {
        endpoint: '/basic/header',
        hint: 'Add header: Authorization: Basic base64(username:password)',
        example: 'Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3MxMjM='
      }
    });
  }

  try {
    const base64 = authHeader.split(' ')[1];
    const decoded = Buffer.from(base64, 'base64').toString('utf8');
    const [username, password] = decoded.split(':');

    if (username !== basicConfig.username || password !== basicConfig.password) {
      return res.status(401).json({
        status: 'failure',
        message: 'Invalid credentials',
        details: { endpoint: '/basic/header' }
      });
    }

    res.json({
      status: 'success',
      message: 'Basic authentication successful',
      details: {
        authType: 'Basic Authentication',
        location: 'header',
        username: username,
        endpoint: '/basic/header'
      }
    });
  } catch (e) {
    return res.status(401).json({
      status: 'failure',
      message: 'Invalid Basic auth format',
      details: { endpoint: '/basic/header', error: e.message }
    });
  }
});

// =============================================================================
// STANDARD ENDPOINTS
// =============================================================================

/**
 * @swagger
 * /basic/test:
 *   get:
 *     summary: Test Basic Authentication - Auto-detect
 *     tags: [Basic Auth]
 *     security:
 *       - basicAuth: []
 *     responses:
 *       200:
 *         description: Authentication successful
 *       401:
 *         description: Authentication failed
 */
router.get('/test', validateBasicAuth, (req, res) => {
  res.json({
    status: 'success',
    message: 'Basic authentication successful',
    details: req.basicAuthResult
  });
});

/**
 * @swagger
 * /basic/test:
 *   post:
 *     summary: Test Basic Authentication with body parameters
 *     tags: [Basic Auth]
 */
router.post('/test', validateBasicAuth, (req, res) => {
  const config = configManager.getConfig();

  // Count additional parameters
  const bodyParams = Object.keys(req.body || {}).length;
  const queryParams = Object.keys(req.query).length;
  const dynamicParams = identifyDynamicParams(req, config);

  res.json({
    status: 'success',
    message: 'Basic authentication successful',
    details: {
      ...req.basicAuthResult,
      additionalParams: {
        body: bodyParams,
        query: queryParams,
        total: bodyParams + queryParams
      },
      dynamicParams: dynamicParams.length,
      expectedParams: config.totalParams,
      expectedDynamicParams: config.dynamicParams
    }
  });
});

/**
 * @swagger
 * /basic/validate:
 *   post:
 *     summary: Validate Basic Auth credentials explicitly
 *     tags: [Basic Auth]
 */
router.post('/validate', (req, res) => {
  const { username, password } = req.body;
  const config = configManager.getConfig();
  const basicConfig = config.credentials.basic;

  const errors = [];

  if (!username) {
    errors.push('Missing username');
  } else if (username !== basicConfig.username) {
    errors.push('Invalid username');
  }

  if (!password) {
    errors.push('Missing password');
  } else if (password !== basicConfig.password) {
    errors.push('Invalid password');
  }

  const isValid = errors.length === 0;

  res.status(isValid ? 200 : 401).json({
    status: isValid ? 'success' : 'failure',
    message: isValid ? 'Credentials validated' : 'Credential validation failed',
    details: {
      authType: 'Basic Authentication',
      validatedParams: isValid ? 2 : 0,
      errors
    }
  });
});

/**
 * @swagger
 * /basic/test-params:
 *   post:
 *     summary: Test Basic Auth with additional parameters
 *     tags: [Basic Auth]
 */
router.post('/test-params', validateBasicAuth, (req, res) => {
  const config = configManager.getConfig();

  // Count all parameters
  const allParams = { ...req.query, ...req.body };
  const paramCount = Object.keys(allParams).length;
  const dynamicParams = identifyDynamicParams(req, config);

  // Validate parameter count
  const expectedParams = config.totalParams;
  const expectedDynamic = config.dynamicParams;

  const paramsValid = paramCount >= expectedParams || expectedParams === 0;
  const dynamicValid = dynamicParams.length >= expectedDynamic || expectedDynamic === 0;

  res.json({
    status: 'success',
    message: 'Basic authentication with parameters successful',
    details: {
      authType: 'Basic Authentication',
      validatedParams: paramCount + 2, // +2 for username/password
      dynamicParams: dynamicParams.length,
      expectedParams,
      expectedDynamicParams: expectedDynamic,
      paramValidation: paramsValid ? 'passed' : 'insufficient',
      dynamicValidation: dynamicValid ? 'passed' : 'insufficient',
      paramDetails: dynamicParams
    }
  });
});

/**
 * @swagger
 * /basic/multi-params:
 *   post:
 *     summary: Test Basic Auth with 50 parameters
 *     tags: [Basic Auth]
 */
router.post('/multi-params', validateBasicAuth, (req, res) => {
  const config = configManager.getConfig();

  // Validate 50 parameters
  const expectedCount = 50;
  const allParams = { ...req.query, ...req.body };
  const paramCount = Object.keys(allParams).length;

  // Check for specific param pattern
  const numberedParams = [];
  for (let i = 0; i < expectedCount; i++) {
    const paramName = `param_${i}`;
    if (allParams[paramName]) {
      numberedParams.push(paramName);
    }
  }

  const dynamicParams = identifyDynamicParams(req, config);

  res.json({
    status: 'success',
    message: 'Basic authentication with multiple parameters',
    details: {
      authType: 'Basic Authentication',
      totalParamsProvided: paramCount,
      numberedParamsFound: numberedParams.length,
      expectedParams: expectedCount,
      validatedParams: paramCount + 2,
      dynamicParams: dynamicParams.length,
      validation: {
        paramsComplete: numberedParams.length >= expectedCount,
        dynamicComplete: dynamicParams.length >= config.dynamicParams
      }
    }
  });
});

/**
 * Middleware to validate Basic Authentication
 */
function validateBasicAuth(req, res, next) {
  const config = configManager.getConfig();
  const basicConfig = config.credentials.basic;

  const authHeader = req.headers.authorization;

  const result = {
    authType: 'Basic Authentication',
    status: 'success',
    errors: []
  };

  if (!authHeader) {
    result.status = 'failure';
    result.errors.push('Missing Authorization header');
    return res.status(401).json({
      status: 'failure',
      message: 'Basic authentication failed',
      details: result
    });
  }

  if (!authHeader.startsWith('Basic ')) {
    result.status = 'failure';
    result.errors.push('Invalid Authorization header format');
    return res.status(401).json({
      status: 'failure',
      message: 'Basic authentication failed',
      details: result
    });
  }

  try {
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
    const [username, password] = credentials.split(':');

    if (username !== basicConfig.username) {
      result.status = 'failure';
      result.errors.push('Invalid username');
    }

    if (password !== basicConfig.password) {
      result.status = 'failure';
      result.errors.push('Invalid password');
    }

    if (result.status === 'failure') {
      return res.status(401).json({
        status: 'failure',
        message: 'Basic authentication failed',
        details: result
      });
    }

    result.validatedParams = 2;
    result.username = username;
    req.basicAuthResult = result;
    next();

  } catch (error) {
    result.status = 'failure';
    result.errors.push('Failed to decode credentials');
    return res.status(401).json({
      status: 'failure',
      message: 'Basic authentication failed',
      details: result
    });
  }
}

/**
 * Identify dynamic parameters
 */
function identifyDynamicParams(req, config) {
  const dynamicParams = [];
  const allParams = { ...req.query, ...req.body };
  const dynamicDefs = config.dynamicParamDefinitions || [];
  const dynamicNames = dynamicDefs.map(d => d.name.toLowerCase());

  for (const [key, value] of Object.entries(allParams)) {
    const lowerKey = key.toLowerCase();

    if (dynamicNames.includes(lowerKey)) {
      dynamicParams.push({ name: key, value, type: 'named' });
      continue;
    }

    if (typeof value === 'string' || typeof value === 'number') {
      const strValue = String(value);

      if (/^\d{10,13}$/.test(strValue)) {
        dynamicParams.push({ name: key, value: strValue, type: 'timestamp' });
      } else if (/^[a-f0-9]{32}$/i.test(strValue)) {
        dynamicParams.push({ name: key, value: strValue, type: 'nonce' });
      } else if (/^[a-f0-9-]{36}$/i.test(strValue)) {
        dynamicParams.push({ name: key, value: strValue, type: 'uuid' });
      }
    }
  }

  return dynamicParams;
}

module.exports = router;

