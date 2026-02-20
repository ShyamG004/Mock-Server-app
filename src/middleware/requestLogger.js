/**
 * Request Logger Middleware
 *
 * Logs all incoming requests including headers, query params, body params,
 * and validation results for debugging and audit purposes.
 */

const logger = require('../utils/logger');

/**
 * Middleware to log all request details
 */
const requestLogger = (req, res, next) => {
  const startTime = Date.now();

  // Generate request ID if not present
  req.requestId = req.headers['x-request-id'] || generateRequestId();

  // Log request details
  const requestLog = {
    requestId: req.requestId,
    method: req.method,
    path: req.path,
    query: sanitizeForLogging(req.query),
    headers: sanitizeHeaders(req.headers),
    body: sanitizeForLogging(req.body),
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.headers['user-agent']
  };

  logger.info('Incoming request', requestLog);

  // Add response logging
  const originalSend = res.send;
  res.send = function(body) {
    const responseTime = Date.now() - startTime;

    // Log response details
    logger.info('Outgoing response', {
      requestId: req.requestId,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      contentLength: body ? body.length : 0
    });

    // Add response headers
    res.setHeader('X-Request-ID', req.requestId);
    res.setHeader('X-Response-Time', `${responseTime}ms`);

    return originalSend.call(this, body);
  };

  next();
};

/**
 * Generate unique request ID
 */
function generateRequestId() {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Sanitize object for logging (remove sensitive data)
 */
function sanitizeForLogging(obj) {
  if (!obj || typeof obj !== 'object') return obj;

  const sensitiveKeys = ['password', 'secret', 'token', 'api_key', 'apikey',
                        'client_secret', 'access_token', 'refresh_token'];
  const sanitized = { ...obj };

  for (const key of Object.keys(sanitized)) {
    const lowerKey = key.toLowerCase();
    if (sensitiveKeys.some(sk => lowerKey.includes(sk))) {
      sanitized[key] = '[REDACTED]';
    }
  }

  return sanitized;
}

/**
 * Sanitize headers for logging
 */
function sanitizeHeaders(headers) {
  const sanitized = { ...headers };
  const sensitiveHeaders = ['authorization', 'x-api-key', 'x-api-secret', 'cookie'];

  for (const header of sensitiveHeaders) {
    if (sanitized[header]) {
      // Show type but not full value
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

/**
 * Validation result logger
 */
const logValidationResult = (req, result) => {
  logger.info('Validation result', {
    requestId: req.requestId,
    authType: result.authType,
    valid: result.valid,
    validatedParams: result.validatedParams,
    dynamicParams: result.dynamicParams,
    errors: result.errors
  });
};

module.exports = {
  requestLogger,
  logValidationResult,
  generateRequestId,
  sanitizeForLogging
};

