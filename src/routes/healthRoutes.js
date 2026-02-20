/**
 * Health Check Routes
 *
 * Endpoints for monitoring server health and status.
 */

const express = require('express');
const router = express.Router();
const configManager = require('../config/configManager');

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Health check endpoint
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: Server is healthy
 */
router.get('/', (req, res) => {
  res.json({
    status: 'success',
    message: 'Server is healthy',
    details: {
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
      }
    }
  });
});

/**
 * @swagger
 * /health/ready:
 *   get:
 *     summary: Readiness check
 *     tags: [Health]
 */
router.get('/ready', (req, res) => {
  const config = configManager.getConfig();

  res.json({
    status: 'success',
    message: 'Server is ready',
    details: {
      ready: true,
      authType: config.authType,
      grantType: config.grantType
    }
  });
});

/**
 * @swagger
 * /health/live:
 *   get:
 *     summary: Liveness check
 *     tags: [Health]
 */
router.get('/live', (req, res) => {
  res.json({
    status: 'success',
    message: 'Server is live',
    details: {
      live: true
    }
  });
});

/**
 * @swagger
 * /health/info:
 *   get:
 *     summary: Server information
 *     tags: [Health]
 */
router.get('/info', (req, res) => {
  const config = configManager.getConfig();

  res.json({
    status: 'success',
    message: 'Server information',
    details: {
      name: 'Mock Authentication Server',
      version: '1.0.0',
      nodeVersion: process.version,
      platform: process.platform,
      uptime: process.uptime(),
      currentConfig: {
        authType: config.authType,
        grantType: config.grantType,
        configurationType: config.configurationType,
        clientAuthMethod: config.clientAuthMethod
      },
      endpoints: {
        documentation: '/api-docs',
        ui: '/ui',
        config: '/config',
        protected: '/protected',
        apiKey: '/api-key/test',
        basicAuth: '/basic/test',
        oauth1: '/oauth1/test',
        oauth2: '/oauth2/test',
        authorize: '/authorize',
        token: '/token'
      }
    }
  });
});

module.exports = router;

