/**
 * API Key Authentication Routes
 *
 * STRICT ENDPOINTS (each accepts ONLY one location):
 * - /api-key/header - Header only (X-API-Key header)
 * - /api-key/query - Query string only
 * - /api-key/body - JSON body only
 * - /api-key/form - Form data only
 *
 * AUTO-DETECT ENDPOINTS (backward compatible):
 * - /api-key/test - Auto-detect location
 */

const express = require('express');
const router = express.Router();
const configManager = require('../config/configManager');
const logger = require('../utils/logger');

// =============================================================================
// STRICT ENDPOINTS - Each accepts ONLY one specific location
// =============================================================================

/**
 * @swagger
 * /api-key/header:
 *   get:
 *     summary: Test API Key - Header ONLY (strict)
 *     tags: [API Key]
 */
router.get('/header', (req, res) => {
  const config = configManager.getConfig();
  const apiKeyConfig = config.credentials.apiKey;
  const expectedKey = apiKeyConfig.keys[0];

  // STRICT: Reject if key is in query
  if (findKeyInsensitive(req.query, expectedKey.name)) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint accepts API key in header ONLY',
      details: {
        endpoint: '/api-key/header',
        error: 'API key found in query string - not allowed',
        hint: 'Remove API key from query, use X-API-Key header instead'
      }
    });
  }

  // STRICT: Check header only
  const headerKey = req.headers[expectedKey.name.toLowerCase()];
  if (!headerKey) {
    return res.status(401).json({
      status: 'failure',
      message: 'Missing API key in header',
      details: {
        endpoint: '/api-key/header',
        requiredHeader: expectedKey.name,
        hint: 'Add header: X-API-Key: your_api_key'
      }
    });
  }

  if (headerKey !== expectedKey.value) {
    return res.status(401).json({
      status: 'failure',
      message: 'Invalid API key',
      details: { endpoint: '/api-key/header', location: 'header' }
    });
  }

  res.json({
    status: 'success',
    message: 'API Key authentication successful (header only)',
    details: {
      authType: 'API Key',
      location: 'header',
      keyName: expectedKey.name,
      endpoint: '/api-key/header'
    }
  });
});

/**
 * @swagger
 * /api-key/query:
 *   get:
 *     summary: Test API Key - Query ONLY (strict)
 *     tags: [API Key]
 */
router.get('/query', (req, res) => {
  const config = configManager.getConfig();
  const apiKeyConfig = config.credentials.apiKey;
  const expectedKey = apiKeyConfig.keys[0];

  // STRICT: Reject if key is in header
  if (req.headers[expectedKey.name.toLowerCase()]) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint accepts API key in query string ONLY',
      details: {
        endpoint: '/api-key/query',
        error: 'API key found in header - not allowed',
        hint: 'Remove X-API-Key header, use query parameter instead',
        example: '/api-key/query?X-API-Key=your_api_key'
      }
    });
  }

  // STRICT: Check query only
  const queryKey = findKeyInsensitive(req.query, expectedKey.name);
  if (!queryKey) {
    return res.status(401).json({
      status: 'failure',
      message: 'Missing API key in query string',
      details: {
        endpoint: '/api-key/query',
        requiredParam: expectedKey.name,
        hint: 'Add ?X-API-Key=your_api_key to URL'
      }
    });
  }

  if (queryKey !== expectedKey.value) {
    return res.status(401).json({
      status: 'failure',
      message: 'Invalid API key',
      details: { endpoint: '/api-key/query', location: 'query' }
    });
  }

  res.json({
    status: 'success',
    message: 'API Key authentication successful (query only)',
    details: {
      authType: 'API Key',
      location: 'query',
      keyName: expectedKey.name,
      endpoint: '/api-key/query'
    }
  });
});

/**
 * @swagger
 * /api-key/body:
 *   post:
 *     summary: Test API Key - JSON Body ONLY (strict)
 *     tags: [API Key]
 */
router.post('/body', (req, res) => {
  const config = configManager.getConfig();
  const apiKeyConfig = config.credentials.apiKey;
  const expectedKey = apiKeyConfig.keys[0];

  // STRICT: Reject if key is in header
  if (req.headers[expectedKey.name.toLowerCase()]) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint accepts API key in JSON body ONLY',
      details: {
        endpoint: '/api-key/body',
        error: 'API key found in header - not allowed',
        hint: 'Remove X-API-Key header, include in JSON body'
      }
    });
  }

  // STRICT: Reject if key is in query
  if (findKeyInsensitive(req.query, expectedKey.name)) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint accepts API key in JSON body ONLY',
      details: {
        endpoint: '/api-key/body',
        error: 'API key found in query - not allowed',
        hint: 'Remove from query, include in JSON body'
      }
    });
  }

  // Check content-type
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/json')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/json',
      details: {
        endpoint: '/api-key/body',
        receivedContentType: contentType
      }
    });
  }

  // STRICT: Check body only
  const bodyKey = findKeyInsensitive(req.body, expectedKey.name);
  if (!bodyKey) {
    return res.status(401).json({
      status: 'failure',
      message: 'Missing API key in JSON body',
      details: {
        endpoint: '/api-key/body',
        requiredField: expectedKey.name,
        hint: 'Include {"X-API-Key": "your_api_key"} in body'
      }
    });
  }

  if (bodyKey !== expectedKey.value) {
    return res.status(401).json({
      status: 'failure',
      message: 'Invalid API key',
      details: { endpoint: '/api-key/body', location: 'body' }
    });
  }

  res.json({
    status: 'success',
    message: 'API Key authentication successful (body only)',
    details: {
      authType: 'API Key',
      location: 'body',
      keyName: expectedKey.name,
      endpoint: '/api-key/body'
    }
  });
});

/**
 * @swagger
 * /api-key/form:
 *   post:
 *     summary: Test API Key - Form Data ONLY (strict)
 *     tags: [API Key]
 */
router.post('/form', (req, res) => {
  const config = configManager.getConfig();
  const apiKeyConfig = config.credentials.apiKey;
  const expectedKey = apiKeyConfig.keys[0];

  // STRICT: Reject if key is in header
  if (req.headers[expectedKey.name.toLowerCase()]) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint accepts API key in form data ONLY',
      details: {
        endpoint: '/api-key/form',
        error: 'API key found in header - not allowed',
        hint: 'Remove X-API-Key header, include in form data'
      }
    });
  }

  // STRICT: Reject if key is in query
  if (findKeyInsensitive(req.query, expectedKey.name)) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint accepts API key in form data ONLY',
      details: {
        endpoint: '/api-key/form',
        error: 'API key found in query - not allowed'
      }
    });
  }

  // Check content-type is form data
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('multipart/form-data') && !contentType.includes('application/x-www-form-urlencoded')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires form data',
      details: {
        endpoint: '/api-key/form',
        receivedContentType: contentType,
        requiredContentType: 'multipart/form-data or application/x-www-form-urlencoded'
      }
    });
  }

  // STRICT: Check form body only
  const formKey = findKeyInsensitive(req.body, expectedKey.name);
  if (!formKey) {
    return res.status(401).json({
      status: 'failure',
      message: 'Missing API key in form data',
      details: {
        endpoint: '/api-key/form',
        requiredField: expectedKey.name
      }
    });
  }

  if (formKey !== expectedKey.value) {
    return res.status(401).json({
      status: 'failure',
      message: 'Invalid API key',
      details: { endpoint: '/api-key/form', location: 'form' }
    });
  }

  res.json({
    status: 'success',
    message: 'API Key authentication successful (form only)',
    details: {
      authType: 'API Key',
      location: 'form',
      keyName: expectedKey.name,
      endpoint: '/api-key/form',
      contentType: contentType.split(';')[0]
    }
  });
});

// =============================================================================
// AUTO-DETECT ENDPOINTS (backward compatible)
// =============================================================================

/**
 * @swagger
 * /api-key/test:
 *   get:
 *     summary: Test API Key - Auto-detect location
 *     tags: [API Key]
 *     description: Accepts API key in any location (header, query, body)
 */
router.get('/test', validateApiKey, (req, res) => {
  res.json({
    status: 'success',
    message: 'API Key authentication successful',
    details: req.apiKeyResult
  });
});

/**
 * @swagger
 * /api-key/test:
 *   post:
 *     summary: Test API Key authentication with POST body
 *     tags: [API Key]
 */
router.post('/test', validateApiKey, (req, res) => {
  res.json({
    status: 'success',
    message: 'API Key authentication successful',
    details: req.apiKeyResult
  });
});

/**
 * @swagger
 * /api-key/test-form:
 *   post:
 *     summary: Test API Key authentication with form-data
 *     tags: [API Key]
 *     requestBody:
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               X-API-Key:
 *                 type: string
 *     responses:
 *       200:
 *         description: API Key validated successfully
 *       401:
 *         description: Invalid API Key
 */
router.post('/test-form', validateApiKey, (req, res) => {
  res.json({
    status: 'success',
    message: 'API Key authentication via form-data successful',
    details: {
      ...req.apiKeyResult,
      contentType: req.headers['content-type'],
      receivedBody: Object.keys(req.body || {})
    }
  });
});

/**
 * @swagger
 * /api-key/validate:
 *   post:
 *     summary: Validate multiple API keys
 *     tags: [API Key]
 */
router.post('/validate', (req, res) => {
  const config = configManager.getConfig();
  const apiKeyConfig = config.credentials.apiKey;
  const results = [];
  let allValid = true;

  for (const keyDef of apiKeyConfig.keys) {
    const providedValue = getKeyValue(req, keyDef.name, keyDef.location);
    const isValid = providedValue === keyDef.value;

    if (!isValid) allValid = false;

    results.push({
      name: keyDef.name,
      location: keyDef.location,
      provided: !!providedValue,
      valid: isValid
    });
  }

  const statusCode = allValid ? 200 : 401;

  res.status(statusCode).json({
    status: allValid ? 'success' : 'failure',
    message: allValid ? 'All API keys validated' : 'API key validation failed',
    details: {
      authType: 'API Key',
      keyResults: results,
      totalKeys: results.length,
      validKeys: results.filter(r => r.valid).length
    }
  });
});

/**
 * @swagger
 * /api-key/test-params:
 *   post:
 *     summary: Test API Key with dynamic parameters
 *     tags: [API Key]
 */
router.post('/test-params', validateApiKey, (req, res) => {
  const config = configManager.getConfig();

  // Count provided parameters
  const queryParams = Object.keys(req.query).length;
  const bodyParams = Object.keys(req.body || {}).length;
  const headerParams = countApiHeaders(req.headers);

  // Identify dynamic parameters
  const dynamicParams = identifyDynamicParams(req, config);

  res.json({
    status: 'success',
    message: 'API Key authentication with parameters successful',
    details: {
      authType: 'API Key',
      validatedParams: queryParams + bodyParams + headerParams,
      dynamicParams: dynamicParams.length,
      expectedParams: config.totalParams,
      expectedDynamicParams: config.dynamicParams,
      paramLocations: {
        query: queryParams,
        body: bodyParams,
        header: headerParams
      },
      dynamicParamDetails: dynamicParams
    }
  });
});

/**
 * @swagger
 * /api-key/multi:
 *   post:
 *     summary: Test with multiple API keys (50 keys)
 *     tags: [API Key]
 */
router.post('/multi', (req, res) => {
  const config = configManager.getConfig();
  const totalExpected = config.totalParams || 50;

  // Validate all provided keys
  const providedKeys = [];

  // Check headers
  for (const [key, value] of Object.entries(req.headers)) {
    if (key.toLowerCase().startsWith('x-api-key') || key.toLowerCase().startsWith('x-key-')) {
      providedKeys.push({ name: key, value, location: 'header' });
    }
  }

  // Check query params
  for (const [key, value] of Object.entries(req.query)) {
    if (key.startsWith('api_key') || key.startsWith('key_')) {
      providedKeys.push({ name: key, value, location: 'query' });
    }
  }

  // Check body params
  if (req.body) {
    for (const [key, value] of Object.entries(req.body)) {
      if (key.startsWith('api_key') || key.startsWith('key_')) {
        providedKeys.push({ name: key, value, location: 'body' });
      }
    }
  }

  const isValid = providedKeys.length >= 1; // At least one key required

  res.status(isValid ? 200 : 401).json({
    status: isValid ? 'success' : 'failure',
    message: isValid ? 'Multi-key validation successful' : 'Multi-key validation failed',
    details: {
      authType: 'API Key',
      providedKeys: providedKeys.length,
      expectedKeys: totalExpected,
      validatedParams: providedKeys.length,
      keys: providedKeys.map(k => ({ name: k.name, location: k.location }))
    }
  });
});

/**
 * Middleware to validate API key
 * Checks all locations (header, query, body) for the API key
 */
function validateApiKey(req, res, next) {
  const config = configManager.getConfig();
  const apiKeyConfig = config.credentials.apiKey;

  const result = {
    authType: 'API Key',
    status: 'success',
    validatedKeys: [],
    errors: []
  };

  for (const keyDef of apiKeyConfig.keys) {
    // Check all locations for the key (header, query, body)
    // Pass null/undefined as location to search everywhere
    const providedValue = getKeyValue(req, keyDef.name, null);

    // Determine where the key was actually found
    let foundLocation = null;
    if (req.headers[keyDef.name.toLowerCase()]) {
      foundLocation = 'header';
    } else if (findKeyInsensitive(req.query, keyDef.name)) {
      foundLocation = 'query';
    } else if (findKeyInsensitive(req.body, keyDef.name)) {
      foundLocation = 'body';
    }

    if (!providedValue) {
      result.status = 'failure';
      result.errors.push(`Missing API key: ${keyDef.name}`);
    } else if (providedValue !== keyDef.value) {
      result.status = 'failure';
      result.errors.push(`Invalid API key: ${keyDef.name}`);
    } else {
      result.validatedKeys.push({
        name: keyDef.name,
        location: foundLocation || keyDef.location
      });
    }
  }

  if (result.status === 'failure') {
    return res.status(401).json({
      status: 'failure',
      message: 'API Key validation failed',
      details: result
    });
  }

  req.apiKeyResult = result;
  next();
}

/**
 * Helper to find key case-insensitively in an object
 */
function findKeyInsensitive(obj, keyName) {
  if (!obj) return undefined;
  const keyLower = keyName.toLowerCase();
  for (const [key, value] of Object.entries(obj)) {
    if (key.toLowerCase() === keyLower) {
      return value;
    }
  }
  return undefined;
}

/**
 * Get key value from specified location (case-insensitive)
 * If location is null/undefined, checks all locations
 */
function getKeyValue(req, name, location) {
  const nameLower = name.toLowerCase();

  switch (location) {
    case 'header':
      return req.headers[nameLower];
    case 'query':
      return findKeyInsensitive(req.query, name);
    case 'body':
    case 'form':
      return findKeyInsensitive(req.body, name);
    default:
      // Check all locations (header, query, body) case-insensitively
      return req.headers[nameLower] ||
             findKeyInsensitive(req.query, name) ||
             findKeyInsensitive(req.body, name);
  }
}

/**
 * Count API-related headers
 */
function countApiHeaders(headers) {
  let count = 0;
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase().startsWith('x-')) {
      count++;
    }
  }
  return count;
}

/**
 * Identify dynamic parameters in request
 */
function identifyDynamicParams(req, config) {
  const dynamicParams = [];
  const dynamicDefs = config.dynamicParamDefinitions || [];
  const dynamicNames = dynamicDefs.map(d => d.name.toLowerCase());

  // Check all locations
  const allParams = {
    ...req.query,
    ...req.body
  };

  for (const [key, value] of Object.entries(allParams)) {
    const lowerKey = key.toLowerCase();

    // Check if matches dynamic param name
    if (dynamicNames.includes(lowerKey)) {
      dynamicParams.push({ name: key, value, type: 'named' });
      continue;
    }

    // Check if value looks dynamic (timestamp, nonce, uuid)
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

