/**
 * Error Handler Middleware
 *
 * Global error handling middleware that catches all errors
 * and returns standardized error responses.
 */

const logger = require('../utils/logger');

/**
 * Global error handler
 */
const errorHandler = (err, req, res, next) => {
  // Log error
  logger.error('Error occurred', {
    requestId: req.requestId,
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });

  // Determine status code
  const statusCode = err.statusCode || err.status || 500;

  // Build error response
  const errorResponse = {
    status: 'failure',
    message: err.message || 'Internal server error',
    details: {
      requestId: req.requestId,
      path: req.path,
      method: req.method
    }
  };

  // Add additional details in development
  if (process.env.NODE_ENV !== 'production') {
    errorResponse.details.stack = err.stack;
  }

  // Add validation errors if present
  if (err.validationErrors) {
    errorResponse.details.validationErrors = err.validationErrors;
  }

  res.status(statusCode).json(errorResponse);
};

/**
 * Custom error class for authentication errors
 */
class AuthenticationError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'AuthenticationError';
    this.statusCode = 401;
    this.details = details;
  }
}

/**
 * Custom error class for validation errors
 */
class ValidationError extends Error {
  constructor(message, validationErrors = []) {
    super(message);
    this.name = 'ValidationError';
    this.statusCode = 400;
    this.validationErrors = validationErrors;
  }
}

/**
 * Custom error class for configuration errors
 */
class ConfigurationError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'ConfigurationError';
    this.statusCode = 400;
    this.details = details;
  }
}

/**
 * Custom error class for OAuth errors
 */
class OAuthError extends Error {
  constructor(errorCode, description, statusCode = 400) {
    super(description);
    this.name = 'OAuthError';
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.errorDescription = description;
  }

  toJSON() {
    return {
      error: this.errorCode,
      error_description: this.errorDescription
    };
  }
}

/**
 * Not found handler
 */
const notFoundHandler = (req, res) => {
  res.status(404).json({
    status: 'failure',
    message: 'Resource not found',
    details: {
      path: req.path,
      method: req.method
    }
  });
};

module.exports = {
  errorHandler,
  notFoundHandler,
  AuthenticationError,
  ValidationError,
  ConfigurationError,
  OAuthError
};

