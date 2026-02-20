/**
 * Validation Engine Middleware
 *
 * Reusable middleware that detects authentication type and validates:
 * - Param location
 * - Param count
 * - Dynamic param count
 * - Scope count
 * - Scope delimiter
 * - Client authentication method
 *
 * Returns structured validation report.
 */

const configManager = require('../config/configManager');
const logger = require('../utils/logger');
const { AuthenticationError, ValidationError } = require('./errorHandler');

/**
 * Main validation engine middleware
 */
const validationEngine = (options = {}) => {
  return (req, res, next) => {
    const config = configManager.getConfig();
    const validationResult = {
      valid: true,
      authType: config.authType,
      grantType: config.grantType,
      errors: [],
      warnings: [],
      validatedParams: 0,
      dynamicParams: 0,
      scopeCount: 0,
      paramLocation: null,
      clientAuthMethod: null,
      scopeDelimiter: config.scopeDelimiter
    };

    try {
      // Detect and validate based on auth type
      switch (config.authType) {
        case 'API Key':
          validateApiKey(req, config, validationResult);
          break;
        case 'Basic Authentication':
          validateBasicAuth(req, config, validationResult);
          break;
        case 'OAuth1':
          validateOAuth1(req, config, validationResult);
          break;
        case 'OAuth2':
          validateOAuth2(req, config, validationResult);
          break;
        default:
          validationResult.errors.push(`Unknown auth type: ${config.authType}`);
          validationResult.valid = false;
      }

      // Validate parameter count
      validateParamCount(req, config, validationResult);

      // Validate dynamic parameters
      validateDynamicParams(req, config, validationResult);

      // Attach validation result to request
      req.validationResult = validationResult;

      // Log validation result
      logger.info('Validation completed', {
        requestId: req.requestId,
        valid: validationResult.valid,
        authType: validationResult.authType,
        errors: validationResult.errors
      });

      if (!validationResult.valid && !options.allowInvalid) {
        return res.status(401).json({
          status: 'failure',
          message: 'Authentication validation failed',
          details: validationResult
        });
      }

      next();
    } catch (error) {
      logger.error('Validation error', { error: error.message });
      next(error);
    }
  };
};

/**
 * Validate API Key authentication
 */
function validateApiKey(req, config, result) {
  const apiKeyConfig = config.credentials.apiKey;
  result.paramLocation = detectParamLocation(req, apiKeyConfig.keys);

  let validKeys = 0;
  for (const keyDef of apiKeyConfig.keys) {
    const value = getParamValue(req, keyDef.name, keyDef.location);

    if (!value) {
      result.errors.push(`Missing API key: ${keyDef.name} in ${keyDef.location}`);
      result.valid = false;
    } else if (value !== keyDef.value) {
      result.errors.push(`Invalid API key: ${keyDef.name}`);
      result.valid = false;
    } else {
      validKeys++;
    }
  }

  result.validatedParams += validKeys;
}

/**
 * Validate Basic Authentication
 */
function validateBasicAuth(req, config, result) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    result.errors.push('Missing or invalid Authorization header');
    result.valid = false;
    return;
  }

  try {
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
    const [username, password] = credentials.split(':');

    const basicConfig = config.credentials.basic;

    if (username !== basicConfig.username) {
      result.errors.push('Invalid username');
      result.valid = false;
    }

    if (password !== basicConfig.password) {
      result.errors.push('Invalid password');
      result.valid = false;
    }

    if (result.valid) {
      result.validatedParams += 2; // username and password
    }

    result.paramLocation = 'header';
  } catch (error) {
    result.errors.push('Failed to decode Basic auth credentials');
    result.valid = false;
  }
}

/**
 * Validate OAuth1 authentication
 */
function validateOAuth1(req, config, result) {
  const authHeader = req.headers.authorization;
  result.paramLocation = 'header';

  if (!authHeader || !authHeader.startsWith('OAuth ')) {
    result.errors.push('Missing OAuth1 Authorization header');
    result.valid = false;
    return;
  }

  // Parse OAuth1 parameters from header
  const oauthParams = parseOAuth1Header(authHeader);
  const oauth1Config = config.credentials.oauth1;

  // Validate required OAuth1 parameters
  const requiredParams = ['oauth_consumer_key', 'oauth_nonce', 'oauth_timestamp',
                          'oauth_signature', 'oauth_signature_method', 'oauth_version'];

  for (const param of requiredParams) {
    if (!oauthParams[param]) {
      result.errors.push(`Missing OAuth1 parameter: ${param}`);
      result.valid = false;
    } else {
      result.validatedParams++;
    }
  }

  // Validate consumer key
  if (oauthParams.oauth_consumer_key !== oauth1Config.consumerKey) {
    result.errors.push('Invalid consumer key');
    result.valid = false;
  }

  // Validate timestamp (within 5 minutes)
  const timestamp = parseInt(oauthParams.oauth_timestamp, 10);
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > 300) {
    result.errors.push('OAuth1 timestamp expired');
    result.valid = false;
  }

  // Validate nonce format
  if (oauthParams.oauth_nonce && oauthParams.oauth_nonce.length < 8) {
    result.errors.push('OAuth1 nonce too short');
    result.valid = false;
  }

  // Mock signature validation (always valid if format is correct)
  if (oauthParams.oauth_signature && oauthParams.oauth_signature.length > 0) {
    result.validatedParams++;
    result.dynamicParams += 3; // nonce, timestamp, signature
  } else {
    result.errors.push('Invalid OAuth1 signature');
    result.valid = false;
  }
}

/**
 * Parse OAuth1 Authorization header
 */
function parseOAuth1Header(header) {
  const params = {};
  const oauthPart = header.replace('OAuth ', '');

  const pairs = oauthPart.split(',').map(p => p.trim());
  for (const pair of pairs) {
    const [key, value] = pair.split('=');
    if (key && value) {
      params[key] = value.replace(/"/g, '');
    }
  }

  return params;
}

/**
 * Validate OAuth2 authentication
 */
function validateOAuth2(req, config, result) {
  result.grantType = config.grantType;
  result.clientAuthMethod = config.clientAuthMethod;

  // Detect token location
  const tokenFromHeader = req.headers.authorization;
  const tokenFromQuery = req.query.access_token;

  if (tokenFromHeader && tokenFromHeader.startsWith('Bearer ')) {
    result.paramLocation = 'header';
    result.validatedParams++;
  } else if (tokenFromQuery) {
    result.paramLocation = 'query';
    result.validatedParams++;
  } else {
    // Check if this is token/authorize endpoint (skip token validation)
    if (!req.path.includes('/token') && !req.path.includes('/authorize')) {
      result.errors.push('Missing access token');
      result.valid = false;
    }
  }

  // Validate client authentication method for token endpoint
  if (req.path.includes('/token')) {
    validateClientAuth(req, config, result);
  }

  // Validate scopes
  validateScopes(req, config, result);
}

/**
 * Validate client authentication method
 */
function validateClientAuth(req, config, result) {
  const authHeader = req.headers.authorization;
  const bodyClientId = req.body.client_id;
  const bodyClientSecret = req.body.client_secret;
  const oauth2Config = config.credentials.oauth2;

  switch (config.clientAuthMethod) {
    case 'Client Secret Basic':
      if (!authHeader || !authHeader.startsWith('Basic ')) {
        result.errors.push('Client Secret Basic auth required but not provided');
        result.valid = false;
      } else {
        try {
          const base64 = authHeader.split(' ')[1];
          const decoded = Buffer.from(base64, 'base64').toString('utf8');
          const [clientId, clientSecret] = decoded.split(':');

          if (clientId !== oauth2Config.clientId || clientSecret !== oauth2Config.clientSecret) {
            result.errors.push('Invalid client credentials');
            result.valid = false;
          } else {
            result.validatedParams += 2;
          }
        } catch (e) {
          result.errors.push('Invalid Basic auth format');
          result.valid = false;
        }
      }
      break;

    case 'Client Secret Post':
      if (!bodyClientId || !bodyClientSecret) {
        result.errors.push('Client Secret Post auth required: client_id and client_secret in body');
        result.valid = false;
      } else if (bodyClientId !== oauth2Config.clientId || bodyClientSecret !== oauth2Config.clientSecret) {
        result.errors.push('Invalid client credentials in body');
        result.valid = false;
      } else {
        result.validatedParams += 2;
      }
      break;

    case 'Client Secret JWT':
      const clientAssertion = req.body.client_assertion;
      const clientAssertionType = req.body.client_assertion_type;

      if (!clientAssertion || clientAssertionType !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
        result.errors.push('Client Secret JWT auth required: client_assertion and client_assertion_type');
        result.valid = false;
      } else {
        // Mock JWT validation (just check format)
        const jwtParts = clientAssertion.split('.');
        if (jwtParts.length !== 3) {
          result.errors.push('Invalid JWT format');
          result.valid = false;
        } else {
          result.validatedParams += 2;
        }
      }
      break;

    case 'None':
      // Only valid for PKCE flow
      if (config.grantType !== 'Authorization Code with PKCE') {
        result.warnings.push('None auth method typically used with PKCE only');
      }
      break;
  }
}

/**
 * Validate scopes
 */
function validateScopes(req, config, result) {
  const scopeParam = req.query.scope || req.body.scope;

  if (scopeParam) {
    const scopes = configManager.parseScopes(scopeParam, config.scopeDelimiter);
    result.scopeCount = scopes.length;
    result.validatedParams += scopes.length;

    // Validate individual scopes if strict validation is enabled
    if (config.validation.strictScopeValidation) {
      const validScopes = config.scopes || [];
      for (const scope of scopes) {
        if (!validScopes.includes(scope) && !scope.startsWith('scope_')) {
          result.warnings.push(`Unknown scope: ${scope}`);
        }
      }
    }
  }
}

/**
 * Validate parameter count
 */
function validateParamCount(req, config, result) {
  // Count all parameters
  const queryParams = Object.keys(req.query).length;
  const bodyParams = typeof req.body === 'object' ? Object.keys(req.body).length : 0;
  const headerParams = countCustomHeaders(req.headers);

  const totalParams = queryParams + bodyParams + headerParams;
  result.validatedParams = Math.max(result.validatedParams, totalParams);

  // Check if minimum params are provided
  if (config.validation.requireAllParams && config.totalParams > 0) {
    if (totalParams < config.totalParams) {
      result.warnings.push(`Expected ${config.totalParams} params, got ${totalParams}`);
    }
  }
}

/**
 * Count custom headers
 */
function countCustomHeaders(headers) {
  let count = 0;
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase().startsWith('x-') ||
        key.toLowerCase() === 'authorization') {
      count++;
    }
  }
  return count;
}

/**
 * Validate dynamic parameters
 */
function validateDynamicParams(req, config, result) {
  const dynamicParamNames = (config.dynamicParamDefinitions || []).map(d => d.name);
  let foundDynamic = 0;

  // Check in all locations
  for (const paramName of dynamicParamNames) {
    if (req.query[paramName] || req.body[paramName] ||
        req.headers[paramName.toLowerCase()] || req.headers[`x-${paramName.toLowerCase()}`]) {
      foundDynamic++;
    }
  }

  // Also check for timestamp, nonce patterns in values
  const allParams = { ...req.query, ...req.body };
  for (const [key, value] of Object.entries(allParams)) {
    if (typeof value === 'string') {
      // Check for timestamp pattern
      if (/^\d{10,13}$/.test(value)) {
        foundDynamic++;
      }
      // Check for nonce/uuid pattern
      if (/^[a-f0-9-]{32,36}$/i.test(value)) {
        foundDynamic++;
      }
    }
  }

  result.dynamicParams = foundDynamic;

  if (config.validation.validateDynamicParams && config.dynamicParams > 0) {
    if (foundDynamic < config.dynamicParams) {
      result.warnings.push(`Expected ${config.dynamicParams} dynamic params, found ${foundDynamic}`);
    }
  }
}

/**
 * Detect param location
 */
function detectParamLocation(req, keyDefs) {
  for (const keyDef of keyDefs) {
    if (req.headers[keyDef.name.toLowerCase()]) return 'header';
    if (req.query[keyDef.name]) return 'query';
    if (req.body && req.body[keyDef.name]) return 'body';
  }
  return 'unknown';
}

/**
 * Get parameter value from specified location
 */
function getParamValue(req, name, location) {
  switch (location) {
    case 'header':
      return req.headers[name.toLowerCase()];
    case 'query':
      return req.query[name];
    case 'body':
    case 'form':
      return req.body ? req.body[name] : undefined;
    default:
      // Check all locations
      return req.headers[name.toLowerCase()] || req.query[name] ||
             (req.body ? req.body[name] : undefined);
  }
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

  // For mock purposes, we'll do a simple validation
  // In real implementation, would compute challenge from verifier
  if (method === 'S256') {
    // Mock: just verify format
    const validChars = /^[A-Za-z0-9\-._~]+$/;
    if (!validChars.test(codeVerifier)) {
      return { valid: false, error: 'Invalid code_verifier format' };
    }
  }

  return { valid: true };
}

module.exports = {
  validationEngine,
  validateApiKey,
  validateBasicAuth,
  validateOAuth1,
  validateOAuth2,
  validatePKCE,
  parseOAuth1Header
};

