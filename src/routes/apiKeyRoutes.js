/**
 * API Key Authentication Routes
 *
 * STRICT ENDPOINTS (each accepts ONLY one location):
 * - /api-key/header - Header only (X-API-Key header)
 * - /api-key/query - Query string only
 * - /api-key/body - JSON body only
 * - /api-key/form - Form data only
 *
 * HEADER + ADDITIONAL COMPULSORY PARAMS (validation matrix):
 * - /api-key/header/with-headers          - API key in header + extra required headers
 * - /api-key/header/with-query            - API key in header + extra required query params
 * - /api-key/header/with-body-json        - API key in header + required JSON body (flat)
 * - /api-key/header/with-body-json-nested - API key in header + required JSON body (nested)
 * - /api-key/header/with-body-urlencoded  - API key in header + required x-www-form-urlencoded body
 * - /api-key/header/with-all-json         - API key + headers + query + JSON body
 * - /api-key/header/with-all-urlencoded   - API key + headers + query + urlencoded body
 *
 * QUERY + ADDITIONAL COMPULSORY PARAMS (mirror of header matrix):
 * - /api-key/query/with-headers
 * - /api-key/query/with-query
 * - /api-key/query/with-body-json
 * - /api-key/query/with-body-json-nested
 * - /api-key/query/with-body-urlencoded
 * - /api-key/query/with-all-json
 * - /api-key/query/with-all-urlencoded
 *
 * FORM + ADDITIONAL COMPULSORY PARAMS (4 endpoints — body location is the form):
 * - /api-key/form/with-headers     - API key in form body + extra required headers
 * - /api-key/form/with-query       - API key in form body + extra required query params
 * - /api-key/form/with-body-extra  - API key in form body + additional required form fields
 * - /api-key/form/with-all         - API key in form + headers + query + extra form fields
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
// HEADER + ADDITIONAL COMPULSORY PARAMS
// API key MUST be in the header. Additional required params are validated by
// presence + exact value match in the location specified by each endpoint.
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
 * Validate that the API key is present in the header ONLY (not query/body).
 * Returns { ok: true } on success or { error, hint } on failure.
 */
function validateApiKeyInHeaderOnly(req) {
  const config = configManager.getConfig();
  const expectedKey = config.credentials.apiKey.keys[0];

  if (findKeyInsensitive(req.query, expectedKey.name)) {
    return {
      error: 'API key must be in header only — found in query string',
      hint: `Remove ${expectedKey.name} from query, send as header instead`
    };
  }
  if (findKeyInsensitive(req.body, expectedKey.name)) {
    return {
      error: 'API key must be in header only — found in body',
      hint: `Remove ${expectedKey.name} from body, send as header instead`
    };
  }

  const headerKey = req.headers[expectedKey.name.toLowerCase()];
  if (!headerKey) {
    return {
      error: `Missing API key in header: ${expectedKey.name}`,
      hint: `Add header: ${expectedKey.name}: ${expectedKey.value}`
    };
  }
  if (headerKey !== expectedKey.value) {
    return { error: 'Invalid API key value' };
  }
  return { ok: true, expectedKey };
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

function requireContentType(req, expected) {
  const ct = req.headers['content-type'] || '';
  return ct.includes(expected);
}

function authFail(res, endpoint, auth) {
  return res.status(auth.error.startsWith('Missing') ? 401 : 400).json({
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
 * /api-key/header/with-headers:
 *   get:
 *     summary: API key (header) + additional compulsory headers
 *     tags: [API Key]
 */
router.get('/header/with-headers', (req, res) => {
  const endpoint = '/api-key/header/with-headers';
  const auth = validateApiKeyInHeaderOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const headerCheck = checkRequiredHeaders(req, REQUIRED_ADDITIONAL_HEADERS);
  if (headerCheck.missing.length || headerCheck.wrong.length) {
    return paramsFail(res, endpoint, 'header', REQUIRED_ADDITIONAL_HEADERS, headerCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key + additional headers validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'header',
      validated: ['apiKey', ...Object.keys(REQUIRED_ADDITIONAL_HEADERS)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/header/with-query:
 *   get:
 *     summary: API key (header) + additional compulsory query params
 *     tags: [API Key]
 */
router.get('/header/with-query', (req, res) => {
  const endpoint = '/api-key/header/with-query';
  const auth = validateApiKeyInHeaderOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const queryCheck = checkRequiredQuery(req, REQUIRED_ADDITIONAL_QUERY);
  if (queryCheck.missing.length || queryCheck.wrong.length) {
    return paramsFail(res, endpoint, 'query', REQUIRED_ADDITIONAL_QUERY, queryCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key + additional query params validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'header',
      validated: ['apiKey', ...Object.keys(REQUIRED_ADDITIONAL_QUERY)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/header/with-body-json:
 *   post:
 *     summary: API key (header) + required JSON body (flat / single layer)
 *     tags: [API Key]
 */
router.post('/header/with-body-json', (req, res) => {
  const endpoint = '/api-key/header/with-body-json';
  if (!requireContentType(req, 'application/json')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/json',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateApiKeyInHeaderOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const bodyCheck = checkFlatBody(req.body, REQUIRED_BODY_FLAT);
  if (bodyCheck.missing.length || bodyCheck.wrong.length) {
    return paramsFail(res, endpoint, 'body (json, flat)', REQUIRED_BODY_FLAT, bodyCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key + flat JSON body validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'header',
      bodyShape: 'flat',
      validated: ['apiKey', ...Object.keys(REQUIRED_BODY_FLAT)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/header/with-body-json-nested:
 *   post:
 *     summary: API key (header) + required JSON body (multi-layer / nested)
 *     tags: [API Key]
 */
router.post('/header/with-body-json-nested', (req, res) => {
  const endpoint = '/api-key/header/with-body-json-nested';
  if (!requireContentType(req, 'application/json')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/json',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateApiKeyInHeaderOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const bodyCheck = checkNestedBody(req.body, REQUIRED_BODY_NESTED);
  if (bodyCheck.missing.length || bodyCheck.wrong.length) {
    return paramsFail(res, endpoint, 'body (json, nested)', REQUIRED_BODY_NESTED, bodyCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key + nested JSON body validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'header',
      bodyShape: 'nested',
      validatedPaths: [
        'apiKey',
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
 * /api-key/header/with-body-urlencoded:
 *   post:
 *     summary: API key (header) + required x-www-form-urlencoded body
 *     tags: [API Key]
 */
router.post('/header/with-body-urlencoded', (req, res) => {
  const endpoint = '/api-key/header/with-body-urlencoded';
  if (!requireContentType(req, 'application/x-www-form-urlencoded')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/x-www-form-urlencoded',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateApiKeyInHeaderOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const bodyCheck = checkFlatBody(req.body, REQUIRED_BODY_FLAT);
  if (bodyCheck.missing.length || bodyCheck.wrong.length) {
    return paramsFail(res, endpoint, 'body (urlencoded)', REQUIRED_BODY_FLAT, bodyCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key + urlencoded body validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'header',
      bodyShape: 'urlencoded',
      validated: ['apiKey', ...Object.keys(REQUIRED_BODY_FLAT)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/header/with-all-json:
 *   post:
 *     summary: API key (header) + headers + query + JSON body (all required)
 *     tags: [API Key]
 */
router.post('/header/with-all-json', (req, res) => {
  const endpoint = '/api-key/header/with-all-json';
  if (!requireContentType(req, 'application/json')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/json',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateApiKeyInHeaderOnly(req);
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
    message: 'API Key + headers + query + JSON body validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'header',
      validated: {
        header: ['apiKey', ...Object.keys(REQUIRED_ADDITIONAL_HEADERS)],
        query: Object.keys(REQUIRED_ADDITIONAL_QUERY),
        body: Object.keys(REQUIRED_BODY_FLAT)
      },
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/header/with-all-urlencoded:
 *   post:
 *     summary: API key (header) + headers + query + urlencoded body (all required)
 *     tags: [API Key]
 */
router.post('/header/with-all-urlencoded', (req, res) => {
  const endpoint = '/api-key/header/with-all-urlencoded';
  if (!requireContentType(req, 'application/x-www-form-urlencoded')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/x-www-form-urlencoded',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateApiKeyInHeaderOnly(req);
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
    message: 'API Key + headers + query + urlencoded body validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'header',
      validated: {
        header: ['apiKey', ...Object.keys(REQUIRED_ADDITIONAL_HEADERS)],
        query: Object.keys(REQUIRED_ADDITIONAL_QUERY),
        body: Object.keys(REQUIRED_BODY_FLAT)
      },
      endpoint
    }
  });
});

// =============================================================================
// QUERY + ADDITIONAL COMPULSORY PARAMS
// API key MUST be in the query string. Mirrors the header matrix.
// =============================================================================

function validateApiKeyInQueryOnly(req) {
  const config = configManager.getConfig();
  const expectedKey = config.credentials.apiKey.keys[0];

  if (req.headers[expectedKey.name.toLowerCase()]) {
    return {
      error: 'API key must be in query only — found in header',
      hint: `Remove ${expectedKey.name} header, send as query param instead`
    };
  }
  if (findKeyInsensitive(req.body, expectedKey.name)) {
    return {
      error: 'API key must be in query only — found in body',
      hint: `Remove ${expectedKey.name} from body, send as query param instead`
    };
  }

  const queryKey = findKeyInsensitive(req.query, expectedKey.name);
  if (queryKey === undefined) {
    return {
      error: `Missing API key in query: ${expectedKey.name}`,
      hint: `Add ?${expectedKey.name}=<value> to URL`,
      status: 401
    };
  }
  if (queryKey !== expectedKey.value) {
    return { error: 'Invalid API key value', status: 401 };
  }
  return { ok: true, expectedKey };
}

/**
 * @swagger
 * /api-key/query/with-headers:
 *   get:
 *     summary: API key (query) + additional compulsory headers
 *     tags: [API Key]
 */
router.get('/query/with-headers', (req, res) => {
  const endpoint = '/api-key/query/with-headers';
  const auth = validateApiKeyInQueryOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const headerCheck = checkRequiredHeaders(req, REQUIRED_ADDITIONAL_HEADERS);
  if (headerCheck.missing.length || headerCheck.wrong.length) {
    return paramsFail(res, endpoint, 'header', REQUIRED_ADDITIONAL_HEADERS, headerCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key (query) + additional headers validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'query',
      validated: ['apiKey', ...Object.keys(REQUIRED_ADDITIONAL_HEADERS)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/query/with-query:
 *   get:
 *     summary: API key (query) + additional compulsory query params
 *     tags: [API Key]
 */
router.get('/query/with-query', (req, res) => {
  const endpoint = '/api-key/query/with-query';
  const auth = validateApiKeyInQueryOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const queryCheck = checkRequiredQuery(req, REQUIRED_ADDITIONAL_QUERY);
  if (queryCheck.missing.length || queryCheck.wrong.length) {
    return paramsFail(res, endpoint, 'query', REQUIRED_ADDITIONAL_QUERY, queryCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key (query) + additional query params validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'query',
      validated: ['apiKey', ...Object.keys(REQUIRED_ADDITIONAL_QUERY)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/query/with-body-json:
 *   post:
 *     summary: API key (query) + required JSON body (flat / single layer)
 *     tags: [API Key]
 */
router.post('/query/with-body-json', (req, res) => {
  const endpoint = '/api-key/query/with-body-json';
  if (!requireContentType(req, 'application/json')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/json',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateApiKeyInQueryOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const bodyCheck = checkFlatBody(req.body, REQUIRED_BODY_FLAT);
  if (bodyCheck.missing.length || bodyCheck.wrong.length) {
    return paramsFail(res, endpoint, 'body (json, flat)', REQUIRED_BODY_FLAT, bodyCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key (query) + flat JSON body validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'query',
      bodyShape: 'flat',
      validated: ['apiKey', ...Object.keys(REQUIRED_BODY_FLAT)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/query/with-body-json-nested:
 *   post:
 *     summary: API key (query) + required JSON body (multi-layer / nested)
 *     tags: [API Key]
 */
router.post('/query/with-body-json-nested', (req, res) => {
  const endpoint = '/api-key/query/with-body-json-nested';
  if (!requireContentType(req, 'application/json')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/json',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateApiKeyInQueryOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const bodyCheck = checkNestedBody(req.body, REQUIRED_BODY_NESTED);
  if (bodyCheck.missing.length || bodyCheck.wrong.length) {
    return paramsFail(res, endpoint, 'body (json, nested)', REQUIRED_BODY_NESTED, bodyCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key (query) + nested JSON body validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'query',
      bodyShape: 'nested',
      validatedPaths: [
        'apiKey',
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
 * /api-key/query/with-body-urlencoded:
 *   post:
 *     summary: API key (query) + required x-www-form-urlencoded body
 *     tags: [API Key]
 */
router.post('/query/with-body-urlencoded', (req, res) => {
  const endpoint = '/api-key/query/with-body-urlencoded';
  if (!requireContentType(req, 'application/x-www-form-urlencoded')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/x-www-form-urlencoded',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateApiKeyInQueryOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const bodyCheck = checkFlatBody(req.body, REQUIRED_BODY_FLAT);
  if (bodyCheck.missing.length || bodyCheck.wrong.length) {
    return paramsFail(res, endpoint, 'body (urlencoded)', REQUIRED_BODY_FLAT, bodyCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key (query) + urlencoded body validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'query',
      bodyShape: 'urlencoded',
      validated: ['apiKey', ...Object.keys(REQUIRED_BODY_FLAT)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/query/with-all-json:
 *   post:
 *     summary: API key (query) + headers + query + JSON body (all required)
 *     tags: [API Key]
 */
router.post('/query/with-all-json', (req, res) => {
  const endpoint = '/api-key/query/with-all-json';
  if (!requireContentType(req, 'application/json')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/json',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateApiKeyInQueryOnly(req);
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
    message: 'API Key (query) + headers + query + JSON body validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'query',
      validated: {
        header: Object.keys(REQUIRED_ADDITIONAL_HEADERS),
        query: ['apiKey', ...Object.keys(REQUIRED_ADDITIONAL_QUERY)],
        body: Object.keys(REQUIRED_BODY_FLAT)
      },
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/query/with-all-urlencoded:
 *   post:
 *     summary: API key (query) + headers + query + urlencoded body (all required)
 *     tags: [API Key]
 */
router.post('/query/with-all-urlencoded', (req, res) => {
  const endpoint = '/api-key/query/with-all-urlencoded';
  if (!requireContentType(req, 'application/x-www-form-urlencoded')) {
    return res.status(400).json({
      status: 'failure',
      message: 'This endpoint requires Content-Type: application/x-www-form-urlencoded',
      details: { endpoint, receivedContentType: req.headers['content-type'] || '' }
    });
  }

  const auth = validateApiKeyInQueryOnly(req);
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
    message: 'API Key (query) + headers + query + urlencoded body validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'query',
      validated: {
        header: Object.keys(REQUIRED_ADDITIONAL_HEADERS),
        query: ['apiKey', ...Object.keys(REQUIRED_ADDITIONAL_QUERY)],
        body: Object.keys(REQUIRED_BODY_FLAT)
      },
      endpoint
    }
  });
});

// =============================================================================
// FORM + ADDITIONAL COMPULSORY PARAMS
// API key MUST be in the form body. Body location is consumed by the form, so
// only 4 endpoints: with-headers, with-query, with-body-extra, with-all.
// =============================================================================

function validateApiKeyInFormOnly(req) {
  const config = configManager.getConfig();
  const expectedKey = config.credentials.apiKey.keys[0];

  if (req.headers[expectedKey.name.toLowerCase()]) {
    return {
      error: 'API key must be in form body only — found in header',
      hint: `Remove ${expectedKey.name} header, send in form body instead`
    };
  }
  if (findKeyInsensitive(req.query, expectedKey.name)) {
    return {
      error: 'API key must be in form body only — found in query',
      hint: `Remove ${expectedKey.name} from query, send in form body instead`
    };
  }

  const ct = req.headers['content-type'] || '';
  if (!ct.includes('application/x-www-form-urlencoded') && !ct.includes('multipart/form-data')) {
    return {
      error: 'This endpoint requires form data',
      hint: 'Set Content-Type: application/x-www-form-urlencoded or multipart/form-data'
    };
  }

  const formKey = findKeyInsensitive(req.body, expectedKey.name);
  if (formKey === undefined) {
    return {
      error: `Missing API key in form body: ${expectedKey.name}`,
      hint: `Include ${expectedKey.name}=<value> in form data`,
      status: 401
    };
  }
  if (formKey !== expectedKey.value) {
    return { error: 'Invalid API key value', status: 401 };
  }
  return { ok: true, expectedKey };
}

/**
 * @swagger
 * /api-key/form/with-headers:
 *   post:
 *     summary: API key (form body) + additional compulsory headers
 *     tags: [API Key]
 */
router.post('/form/with-headers', (req, res) => {
  const endpoint = '/api-key/form/with-headers';
  const auth = validateApiKeyInFormOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const headerCheck = checkRequiredHeaders(req, REQUIRED_ADDITIONAL_HEADERS);
  if (headerCheck.missing.length || headerCheck.wrong.length) {
    return paramsFail(res, endpoint, 'header', REQUIRED_ADDITIONAL_HEADERS, headerCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key (form) + additional headers validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'form',
      validated: ['apiKey', ...Object.keys(REQUIRED_ADDITIONAL_HEADERS)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/form/with-query:
 *   post:
 *     summary: API key (form body) + additional compulsory query params
 *     tags: [API Key]
 */
router.post('/form/with-query', (req, res) => {
  const endpoint = '/api-key/form/with-query';
  const auth = validateApiKeyInFormOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const queryCheck = checkRequiredQuery(req, REQUIRED_ADDITIONAL_QUERY);
  if (queryCheck.missing.length || queryCheck.wrong.length) {
    return paramsFail(res, endpoint, 'query', REQUIRED_ADDITIONAL_QUERY, queryCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key (form) + additional query params validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'form',
      validated: ['apiKey', ...Object.keys(REQUIRED_ADDITIONAL_QUERY)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/form/with-body-extra:
 *   post:
 *     summary: API key (form body) + additional required form fields
 *     tags: [API Key]
 */
router.post('/form/with-body-extra', (req, res) => {
  const endpoint = '/api-key/form/with-body-extra';
  const auth = validateApiKeyInFormOnly(req);
  if (!auth.ok) return authFail(res, endpoint, auth);

  const bodyCheck = checkFlatBody(req.body, REQUIRED_BODY_FLAT);
  if (bodyCheck.missing.length || bodyCheck.wrong.length) {
    return paramsFail(res, endpoint, 'form body', REQUIRED_BODY_FLAT, bodyCheck);
  }

  res.json({
    status: 'success',
    message: 'API Key (form) + additional form fields validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'form',
      validated: ['apiKey', ...Object.keys(REQUIRED_BODY_FLAT)],
      endpoint
    }
  });
});

/**
 * @swagger
 * /api-key/form/with-all:
 *   post:
 *     summary: API key (form) + headers + query + extra form fields (all required)
 *     tags: [API Key]
 */
router.post('/form/with-all', (req, res) => {
  const endpoint = '/api-key/form/with-all';
  const auth = validateApiKeyInFormOnly(req);
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
    message: 'API Key (form) + headers + query + form body validated',
    details: {
      authType: 'API Key',
      apiKeyLocation: 'form',
      validated: {
        header: Object.keys(REQUIRED_ADDITIONAL_HEADERS),
        query: Object.keys(REQUIRED_ADDITIONAL_QUERY),
        body: ['apiKey', ...Object.keys(REQUIRED_BODY_FLAT)]
      },
      endpoint
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

