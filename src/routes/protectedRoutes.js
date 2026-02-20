/**
 * Protected Resource Routes
 *
 * Generic protected endpoint that validates authentication
 * based on current server configuration and returns detailed
 * validation report.
 */

const express = require('express');
const router = express.Router();
const configManager = require('../config/configManager');
const { validationEngine } = require('../middleware/validationEngine');
const logger = require('../utils/logger');

/**
 * @swagger
 * /protected:
 *   get:
 *     summary: Generic protected resource endpoint
 *     tags: [Protected]
 *     description: Validates authentication based on current configuration
 *     responses:
 *       200:
 *         description: Authentication successful
 *       401:
 *         description: Authentication failed
 */
router.get('/', validationEngine({ allowInvalid: false }), (req, res) => {
  const config = configManager.getConfig();
  const result = req.validationResult;

  res.json({
    authType: config.authType,
    grantType: config.grantType || null,
    status: 'success',
    validatedParams: result.validatedParams,
    dynamicParams: result.dynamicParams,
    message: 'Authentication validated successfully',
    details: {
      configurationType: config.configurationType,
      clientAuthMethod: config.clientAuthMethod,
      scopeDelimiter: config.scopeDelimiter,
      paramLocation: result.paramLocation,
      scopeCount: result.scopeCount,
      expectedParams: config.totalParams,
      expectedDynamicParams: config.dynamicParams,
      validation: {
        errors: result.errors,
        warnings: result.warnings
      }
    }
  });
});

/**
 * @swagger
 * /protected:
 *   post:
 *     summary: Protected POST endpoint with body
 *     tags: [Protected]
 */
router.post('/', validationEngine({ allowInvalid: false }), (req, res) => {
  const config = configManager.getConfig();
  const result = req.validationResult;

  // Additional body parameter counting
  const bodyParamCount = Object.keys(req.body || {}).length;
  const queryParamCount = Object.keys(req.query).length;

  res.json({
    authType: config.authType,
    grantType: config.grantType || null,
    status: 'success',
    validatedParams: result.validatedParams + bodyParamCount + queryParamCount,
    dynamicParams: result.dynamicParams,
    message: 'Authentication validated successfully',
    details: {
      bodyParams: bodyParamCount,
      queryParams: queryParamCount,
      totalParams: result.validatedParams + bodyParamCount + queryParamCount,
      expectedParams: config.totalParams,
      expectedDynamicParams: config.dynamicParams,
      configurationType: config.configurationType,
      clientAuthMethod: config.clientAuthMethod,
      scopeDelimiter: config.scopeDelimiter,
      validation: {
        errors: result.errors,
        warnings: result.warnings
      }
    }
  });
});

/**
 * @swagger
 * /protected/info:
 *   get:
 *     summary: Get protected resource info
 *     tags: [Protected]
 */
router.get('/info', validationEngine({ allowInvalid: false }), (req, res) => {
  const config = configManager.getConfig();

  res.json({
    status: 'success',
    message: 'Protected resource info',
    details: {
      authType: config.authType,
      grantType: config.grantType,
      configurationType: config.configurationType,
      clientAuthMethod: config.clientAuthMethod,
      scopeDelimiter: config.scopeDelimiter,
      paramLocation: config.paramLocation,
      totalParams: config.totalParams,
      dynamicParams: config.dynamicParams,
      totalScopes: config.totalScopes,
      validationResult: req.validationResult
    }
  });
});

/**
 * @swagger
 * /protected/validate:
 *   post:
 *     summary: Validate authentication without full validation
 *     tags: [Protected]
 */
router.post('/validate', validationEngine({ allowInvalid: true }), (req, res) => {
  const config = configManager.getConfig();
  const result = req.validationResult;

  const statusCode = result.valid ? 200 : 401;

  res.status(statusCode).json({
    status: result.valid ? 'success' : 'failure',
    message: result.valid ? 'Validation passed' : 'Validation failed',
    authType: config.authType,
    grantType: config.grantType,
    validatedParams: result.validatedParams,
    dynamicParams: result.dynamicParams,
    details: {
      valid: result.valid,
      errors: result.errors,
      warnings: result.warnings,
      paramLocation: result.paramLocation,
      scopeCount: result.scopeCount,
      clientAuthMethod: result.clientAuthMethod
    }
  });
});

/**
 * @swagger
 * /protected/echo:
 *   post:
 *     summary: Echo request details (for debugging)
 *     tags: [Protected]
 */
router.post('/echo', validationEngine({ allowInvalid: true }), (req, res) => {
  const config = configManager.getConfig();

  res.json({
    status: 'success',
    message: 'Request echo',
    details: {
      method: req.method,
      path: req.path,
      query: req.query,
      body: req.body,
      headers: sanitizeHeaders(req.headers),
      authType: config.authType,
      validationResult: req.validationResult
    }
  });
});

/**
 * @swagger
 * /protected/resource:
 *   get:
 *     summary: Get a mock protected resource
 *     tags: [Protected]
 */
router.get('/resource', validationEngine({ allowInvalid: false }), (req, res) => {
  res.json({
    status: 'success',
    message: 'Protected resource retrieved',
    details: {
      resourceId: 'res_' + Date.now(),
      resourceType: 'mock_resource',
      data: {
        id: 1,
        name: 'Mock Resource',
        description: 'This is a mock protected resource',
        created: new Date().toISOString()
      },
      authInfo: {
        authType: req.validationResult.authType,
        validatedAt: new Date().toISOString()
      }
    }
  });
});

/**
 * @swagger
 * /protected/resource:
 *   post:
 *     summary: Create a mock protected resource
 *     tags: [Protected]
 */
router.post('/resource', validationEngine({ allowInvalid: false }), (req, res) => {
  res.status(201).json({
    status: 'success',
    message: 'Protected resource created',
    details: {
      resourceId: 'res_' + Date.now(),
      resourceType: 'mock_resource',
      data: req.body,
      authInfo: {
        authType: req.validationResult.authType,
        validatedAt: new Date().toISOString()
      }
    }
  });
});

/**
 * @swagger
 * /protected/resource/{id}:
 *   get:
 *     summary: Get specific protected resource
 *     tags: [Protected]
 */
router.get('/resource/:id', validationEngine({ allowInvalid: false }), (req, res) => {
  res.json({
    status: 'success',
    message: 'Protected resource retrieved',
    details: {
      resourceId: req.params.id,
      resourceType: 'mock_resource',
      data: {
        id: req.params.id,
        name: 'Mock Resource ' + req.params.id,
        description: 'This is a mock protected resource',
        created: new Date().toISOString()
      }
    }
  });
});

/**
 * Sanitize headers for echo response
 */
function sanitizeHeaders(headers) {
  const sanitized = { ...headers };
  const sensitiveHeaders = ['authorization', 'cookie'];

  for (const header of sensitiveHeaders) {
    if (sanitized[header]) {
      if (header === 'authorization') {
        const parts = sanitized[header].split(' ');
        sanitized[header] = parts[0] + ' [REDACTED]';
      } else {
        sanitized[header] = '[REDACTED]';
      }
    }
  }

  return sanitized;
}

module.exports = router;

