/**
 * Basic Authentication Routes
 *
 * Basic Authentication ONLY supports Authorization header.
 * Format: Authorization: Basic base64(username:password)
 *
 * Endpoints:
 * - /basic/header - Strict endpoint (Authorization header only)
 * - /basic/test - Test endpoint with additional params support
 *
 * HEADER + ADDITIONAL COMPULSORY PARAMS (validation matrix):
 * - /basic/header/with-headers          - Basic auth + extra required headers
 * - /basic/header/with-query            - Basic auth + extra required query params
 * - /basic/header/with-body-json        - Basic auth + required JSON body (flat)
 * - /basic/header/with-body-json-nested - Basic auth + required JSON body (nested)
 * - /basic/header/with-body-urlencoded  - Basic auth + required x-www-form-urlencoded body
 * - /basic/header/with-all-json         - Basic auth + headers + query + JSON body
 * - /basic/header/with-all-urlencoded   - Basic auth + headers + query + urlencoded body
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
  if (!authHeader || !authHeader.toLowerCase().startsWith('basic ')) {
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
// HEADER + ADDITIONAL COMPULSORY PARAMS
// Basic auth MUST be in the Authorization header. Additional required params
// are validated by presence + exact value match in the location specified by
// each endpoint.
// =============================================================================

const REQUIRED_ADDITIONAL_HEADERS = {
  'X-Request-ID': 'req-12345',
  'X-Client-Version': '1.0.0'
};

const REQUIRED_ADDITIONAL_QUERY = {
  department: 'engineering',
  region: 'us-west'
};

const REQUIRED_BODY_FLAT = {
  action: 'test',
  user_id: 'user_123'
};

const REQUIRED_BODY_NESTED = {
  user: {
    id: 'user_123',
    profile: {
      name: 'John Doe',
      email: 'john@example.com'
    }
  },
  metadata: {
    source: 'api',
    version: '1.0'
  }
};

/**
 * Validate the Basic auth Authorization header.
 * Returns { ok: true } on success or { error, hint, status } on failure.
 */
function validateBasicAuthHeader(req) {
  const config = configManager.getConfig();
  const basicConfig = config.credentials.basic;
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return {
      error: 'Missing Authorization header',
      hint: 'Add header: Authorization: Basic base64(username:password)',
      status: 401
    };
  }
  if (!authHeader.toLowerCase().startsWith('basic ')) {
    return {
      error: 'Invalid Authorization scheme — expected Basic',
      hint: 'Authorization header must start with "Basic "',
      status: 401
    };
  }

  try {
    const base64 = authHeader.split(' ')[1];
    const decoded = Buffer.from(base64, 'base64').toString('utf8');
    const idx = decoded.indexOf(':');
    if (idx === -1) {
      return { error: 'Invalid Basic auth payload — missing ":"', status: 401 };
    }
    const username = decoded.slice(0, idx);
    const password = decoded.slice(idx + 1);

    if (username !== basicConfig.username || password !== basicConfig.password) {
      return { error: 'Invalid credentials', status: 401 };
    }
    return { ok: true, username };
  } catch (e) {
    return { error: 'Failed to decode Basic auth header', status: 401 };
  }
}

function checkRequiredHeaders(req, required) {
  const missing = [];
  const wrong = [];
  for (const [name, expected] of Object.entries(required)) {
    const actual = req.headers[name.toLowerCase()];
    if (actual === undefined) missing.push(name);
    else if (actual !== expected) wrong.push({ name, expected, received: actual });
  }
  return { missing, wrong };
}

function checkRequiredQuery(req, required) {
  const missing = [];
  const wrong = [];
  for (const [name, expected] of Object.entries(required)) {
    const actual = findKeyInsensitive(req.query, name);
    if (actual === undefined) missing.push(name);
    else if (actual !== expected) wrong.push({ name, expected, received: actual });
  }
  return { missing, wrong };
}

function checkFlatBody(body, required) {
  const missing = [];
  const wrong = [];
  for (const [name, expected] of Object.entries(required)) {
    const actual = body && findKeyInsensitive(body, name);
    if (actual === undefined) missing.push(name);
    else if (String(actual) !== String(expected)) {
      wrong.push({ name, expected, received: actual });
    }
  }
  return { missing, wrong };
}

function checkNestedBody(body, expected, path = '') {
  const missing = [];
  const wrong = [];
  if (!body || typeof body !== 'object') {
    for (const key of Object.keys(expected)) missing.push(path ? `${path}.${key}` : key);
    return { missing, wrong };
  }
  for (const [key, value] of Object.entries(expected)) {
    const fieldPath = path ? `${path}.${key}` : key;
    const actual = body[key];
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      const nested = checkNestedBody(actual, value, fieldPath);
      missing.push(...nested.missing);
      wrong.push(...nested.wrong);
    } else if (actual === undefined) {
      missing.push(fieldPath);
    } else if (actual !== value) {
      wrong.push({ name: fieldPath, expected: value, received: actual });
    }
  }
  return { missing, wrong };
}

function findKeyInsensitive(obj, keyName) {
  if (!obj) return undefined;
  const keyLower = keyName.toLowerCase();
  for (const [key, value] of Object.entries(obj)) {
    if (key.toLowerCase() === keyLower) return value;
  }
  return undefined;
}

function requireContentType(req, expected) {
  const ct = req.headers['content-type'] || '';
  return ct.includes(expected);
}

function authFail(res, endpoint, auth) {
  return res.status(auth.status || 401).json({
    status: 'failure',
    message: auth.error,
    details: { endpoint, hint: auth.hint }
  });
}

function paramsFail(res, endpoint, location, expected, result) {
  return res.status(400).json({
    status: 'failure',
    message: `Missing or invalid required ${location} params`,
    details: {
      endpoint,
      location,
      expected,
      missing: result.missing,
      wrong: result.wrong
    }
  });
}

/**
 * @swagger
 * /basic/header/with-headers:
 *   get:
 *     summary: Basic auth + additional compulsory headers
 *     tags: [Basic Auth]
 */
router.get('/header/with-headers', (req, res) => {
  const endpoint = '/basic/header/with-headers';
  const auth = validateBasicAuthHeader(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const headerCheck = checkRequiredHeaders(req, REQUIRED_ADDITIONAL_HEADERS);
  if (headerCheck.missing.length || headerCheck.wrong.length) {
    return paramsFail(res, endpoint, 'header', REQUIRED_ADDITIONAL_HEADERS, headerCheck);
  }

  res.json({
    status: 'success',
    message: 'Basic auth + additional headers validated',
    details: {
      authType: 'Basic Authentication',
      username: auth.username,
      validated: ['basicAuth', ...Object.keys(REQUIRED_ADDITIONAL_HEADERS)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /basic/header/with-query:
 *   get:
 *     summary: Basic auth + additional compulsory query params
 *     tags: [Basic Auth]
 */
router.get('/header/with-query', (req, res) => {
  const endpoint = '/basic/header/with-query';
  const auth = validateBasicAuthHeader(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const queryCheck = checkRequiredQuery(req, REQUIRED_ADDITIONAL_QUERY);
  if (queryCheck.missing.length || queryCheck.wrong.length) {
    return paramsFail(res, endpoint, 'query', REQUIRED_ADDITIONAL_QUERY, queryCheck);
  }

  res.json({
    status: 'success',
    message: 'Basic auth + additional query params validated',
    details: {
      authType: 'Basic Authentication',
      username: auth.username,
      validated: ['basicAuth', ...Object.keys(REQUIRED_ADDITIONAL_QUERY)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /basic/header/with-body-json:
 *   post:
 *     summary: Basic auth + required JSON body (flat / single layer)
 *     tags: [Basic Auth]
 */
router.post('/header/with-body-json', (req, res) => {
  const endpoint = '/basic/header/with-body-json';
  if (!requireContentType(req, 'application/json')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/json',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateBasicAuthHeader(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const bodyCheck = checkFlatBody(req.body, REQUIRED_BODY_FLAT);
  if (bodyCheck.missing.length || bodyCheck.wrong.length) {
    return paramsFail(res, endpoint, 'body (json, flat)', REQUIRED_BODY_FLAT, bodyCheck);
  }

  res.json({
    status: 'success',
    message: 'Basic auth + flat JSON body validated',
    details: {
      authType: 'Basic Authentication',
      username: auth.username,
      bodyShape: 'flat',
      validated: ['basicAuth', ...Object.keys(REQUIRED_BODY_FLAT)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /basic/header/with-body-json-nested:
 *   post:
 *     summary: Basic auth + required JSON body (multi-layer / nested)
 *     tags: [Basic Auth]
 */
router.post('/header/with-body-json-nested', (req, res) => {
  const endpoint = '/basic/header/with-body-json-nested';
  if (!requireContentType(req, 'application/json')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/json',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateBasicAuthHeader(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const bodyCheck = checkNestedBody(req.body, REQUIRED_BODY_NESTED);
  if (bodyCheck.missing.length || bodyCheck.wrong.length) {
    return paramsFail(res, endpoint, 'body (json, nested)', REQUIRED_BODY_NESTED, bodyCheck);
  }

  res.json({
    status: 'success',
    message: 'Basic auth + nested JSON body validated',
    details: {
      authType: 'Basic Authentication',
      username: auth.username,
      bodyShape: 'nested',
      validatedPaths: [
        'basicAuth',
        'user.id',
        'user.profile.name',
        'user.profile.email',
        'metadata.source',
        'metadata.version'
      ],
      endpoint
    }
  });
});

/**
 * @swagger
 * /basic/header/with-body-urlencoded:
 *   post:
 *     summary: Basic auth + required x-www-form-urlencoded body
 *     tags: [Basic Auth]
 */
router.post('/header/with-body-urlencoded', (req, res) => {
  const endpoint = '/basic/header/with-body-urlencoded';
  if (!requireContentType(req, 'application/x-www-form-urlencoded')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/x-www-form-urlencoded',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateBasicAuthHeader(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const bodyCheck = checkFlatBody(req.body, REQUIRED_BODY_FLAT);
  if (bodyCheck.missing.length || bodyCheck.wrong.length) {
    return paramsFail(res, endpoint, 'body (urlencoded)', REQUIRED_BODY_FLAT, bodyCheck);
  }

  res.json({
    status: 'success',
    message: 'Basic auth + urlencoded body validated',
    details: {
      authType: 'Basic Authentication',
      username: auth.username,
      bodyShape: 'urlencoded',
      validated: ['basicAuth', ...Object.keys(REQUIRED_BODY_FLAT)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /basic/header/with-all-json:
 *   post:
 *     summary: Basic auth + headers + query + JSON body (all required)
 *     tags: [Basic Auth]
 */
router.post('/header/with-all-json', (req, res) => {
  const endpoint = '/basic/header/with-all-json';
  if (!requireContentType(req, 'application/json')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/json',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateBasicAuthHeader(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const headerCheck = checkRequiredHeaders(req, REQUIRED_ADDITIONAL_HEADERS);
  const queryCheck = checkRequiredQuery(req, REQUIRED_ADDITIONAL_QUERY);
  const bodyCheck = checkFlatBody(req.body, REQUIRED_BODY_FLAT);

  const failures = {};
  if (headerCheck.missing.length || headerCheck.wrong.length) failures.header = headerCheck;
  if (queryCheck.missing.length || queryCheck.wrong.length) failures.query = queryCheck;
  if (bodyCheck.missing.length || bodyCheck.wrong.length) failures.body = bodyCheck;

  if (Object.keys(failures).length) {
    return res.status(400).json({
      status: 'failure',
      message: 'Missing or invalid required params across one or more locations',
      details: {
        endpoint,
        expected: {
          header: REQUIRED_ADDITIONAL_HEADERS,
          query: REQUIRED_ADDITIONAL_QUERY,
          body: REQUIRED_BODY_FLAT
        },
        failures
      }
    });
  }

  res.json({
    status: 'success',
    message: 'Basic auth + headers + query + JSON body validated',
    details: {
      authType: 'Basic Authentication',
      username: auth.username,
      validated: {
        header: ['basicAuth', ...Object.keys(REQUIRED_ADDITIONAL_HEADERS)],
        query: Object.keys(REQUIRED_ADDITIONAL_QUERY),
        body: Object.keys(REQUIRED_BODY_FLAT)
      },
      endpoint
    }
  });
});

/**
 * @swagger
 * /basic/header/with-all-urlencoded:
 *   post:
 *     summary: Basic auth + headers + query + urlencoded body (all required)
 *     tags: [Basic Auth]
 */
router.post('/header/with-all-urlencoded', (req, res) => {
  const endpoint = '/basic/header/with-all-urlencoded';
  if (!requireContentType(req, 'application/x-www-form-urlencoded')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/x-www-form-urlencoded',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateBasicAuthHeader(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const headerCheck = checkRequiredHeaders(req, REQUIRED_ADDITIONAL_HEADERS);
  const queryCheck = checkRequiredQuery(req, REQUIRED_ADDITIONAL_QUERY);
  const bodyCheck = checkFlatBody(req.body, REQUIRED_BODY_FLAT);

  const failures = {};
  if (headerCheck.missing.length || headerCheck.wrong.length) failures.header = headerCheck;
  if (queryCheck.missing.length || queryCheck.wrong.length) failures.query = queryCheck;
  if (bodyCheck.missing.length || bodyCheck.wrong.length) failures.body = bodyCheck;

  if (Object.keys(failures).length) {
    return res.status(400).json({
      status: 'failure',
      message: 'Missing or invalid required params across one or more locations',
      details: {
        endpoint,
        expected: {
          header: REQUIRED_ADDITIONAL_HEADERS,
          query: REQUIRED_ADDITIONAL_QUERY,
          body: REQUIRED_BODY_FLAT
        },
        failures
      }
    });
  }

  res.json({
    status: 'success',
    message: 'Basic auth + headers + query + urlencoded body validated',
    details: {
      authType: 'Basic Authentication',
      username: auth.username,
      validated: {
        header: ['basicAuth', ...Object.keys(REQUIRED_ADDITIONAL_HEADERS)],
        query: Object.keys(REQUIRED_ADDITIONAL_QUERY),
        body: Object.keys(REQUIRED_BODY_FLAT)
      },
      endpoint
    }
  });
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

  if (!authHeader.toLowerCase().startsWith('basic ')) {
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

