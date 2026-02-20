/**
 * Configuration Routes
 *
 * Admin endpoints for managing server configuration including
 * authentication type selection and parameter settings.
 */

const express = require('express');
const router = express.Router();
const configManager = require('../config/configManager');
const logger = require('../utils/logger');

/**
 * @swagger
 * /config:
 *   get:
 *     summary: Get current configuration
 *     tags: [Configuration]
 *     responses:
 *       200:
 *         description: Current server configuration
 */
router.get('/', (req, res) => {
  res.json({
    status: 'success',
    message: 'Current configuration retrieved',
    details: {
      config: configManager.getConfig(),
      validOptions: configManager.getValidOptions()
    }
  });
});

/**
 * @swagger
 * /config:
 *   post:
 *     summary: Update server configuration
 *     tags: [Configuration]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Configuration updated successfully
 *       400:
 *         description: Invalid configuration
 */
router.post('/', (req, res) => {
  const adminKey = req.headers['x-admin-key'];

  // Check admin key if enabled
  if (process.env.ADMIN_ENABLED === 'true' && process.env.ADMIN_API_KEY) {
    if (adminKey !== process.env.ADMIN_API_KEY) {
      return res.status(403).json({
        status: 'failure',
        message: 'Invalid admin key',
        details: {}
      });
    }
  }

  const result = configManager.updateConfig(req.body);

  if (!result.success) {
    return res.status(400).json({
      status: 'failure',
      message: 'Configuration update failed',
      details: {
        errors: result.errors
      }
    });
  }

  logger.info('Configuration updated via API', {
    authType: result.config.authType
  });

  res.json({
    status: 'success',
    message: 'Configuration updated successfully',
    details: {
      config: result.config
    }
  });
});

/**
 * @swagger
 * /config:
 *   put:
 *     summary: Replace entire configuration
 *     tags: [Configuration]
 */
router.put('/', (req, res) => {
  const adminKey = req.headers['x-admin-key'];

  if (process.env.ADMIN_ENABLED === 'true' && process.env.ADMIN_API_KEY) {
    if (adminKey !== process.env.ADMIN_API_KEY) {
      return res.status(403).json({
        status: 'failure',
        message: 'Invalid admin key',
        details: {}
      });
    }
  }

  // Reset and apply new config
  configManager.resetConfig();
  const result = configManager.updateConfig(req.body);

  if (!result.success) {
    return res.status(400).json({
      status: 'failure',
      message: 'Configuration replacement failed',
      details: {
        errors: result.errors
      }
    });
  }

  res.json({
    status: 'success',
    message: 'Configuration replaced successfully',
    details: {
      config: result.config
    }
  });
});

/**
 * @swagger
 * /config/reset:
 *   post:
 *     summary: Reset configuration to defaults
 *     tags: [Configuration]
 */
router.post('/reset', (req, res) => {
  const adminKey = req.headers['x-admin-key'];

  if (process.env.ADMIN_ENABLED === 'true' && process.env.ADMIN_API_KEY) {
    if (adminKey !== process.env.ADMIN_API_KEY) {
      return res.status(403).json({
        status: 'failure',
        message: 'Invalid admin key',
        details: {}
      });
    }
  }

  const config = configManager.resetConfig();

  logger.info('Configuration reset to defaults');

  res.json({
    status: 'success',
    message: 'Configuration reset to defaults',
    details: {
      config
    }
  });
});

/**
 * @swagger
 * /config/history:
 *   get:
 *     summary: Get configuration change history
 *     tags: [Configuration]
 */
router.get('/history', (req, res) => {
  res.json({
    status: 'success',
    message: 'Configuration history retrieved',
    details: {
      history: configManager.getHistory()
    }
  });
});

/**
 * @swagger
 * /config/options:
 *   get:
 *     summary: Get valid configuration options
 *     tags: [Configuration]
 */
router.get('/options', (req, res) => {
  res.json({
    status: 'success',
    message: 'Valid configuration options',
    details: configManager.getValidOptions()
  });
});

/**
 * @swagger
 * /config/auth-type:
 *   post:
 *     summary: Quick switch authentication type
 *     tags: [Configuration]
 */
router.post('/auth-type', (req, res) => {
  const { authType, grantType } = req.body;

  const updateObj = {};
  if (authType) updateObj.authType = authType;
  if (grantType) updateObj.grantType = grantType;

  const result = configManager.updateConfig(updateObj);

  if (!result.success) {
    return res.status(400).json({
      status: 'failure',
      message: 'Auth type update failed',
      details: {
        errors: result.errors
      }
    });
  }

  res.json({
    status: 'success',
    message: 'Authentication type updated',
    details: {
      authType: result.config.authType,
      grantType: result.config.grantType
    }
  });
});

/**
 * @swagger
 * /config/credentials:
 *   get:
 *     summary: Get test credentials (for testing purposes)
 *     tags: [Configuration]
 */
router.get('/credentials', (req, res) => {
  const config = configManager.getConfig();

  res.json({
    status: 'success',
    message: 'Test credentials retrieved',
    details: {
      apiKey: {
        keys: config.credentials.apiKey.keys.map(k => ({
          name: k.name,
          location: k.location,
          value: k.value
        }))
      },
      basic: {
        username: config.credentials.basic.username,
        password: config.credentials.basic.password
      },
      oauth1: {
        consumerKey: config.credentials.oauth1.consumerKey,
        consumerSecret: config.credentials.oauth1.consumerSecret
      },
      oauth2: {
        clientId: config.credentials.oauth2.clientId,
        clientSecret: config.credentials.oauth2.clientSecret,
        redirectUri: config.credentials.oauth2.redirectUri
      }
    }
  });
});

/**
 * @swagger
 * /config/credentials:
 *   post:
 *     summary: Update credentials
 *     tags: [Configuration]
 */
router.post('/credentials', (req, res) => {
  const adminKey = req.headers['x-admin-key'];

  if (process.env.ADMIN_ENABLED === 'true' && process.env.ADMIN_API_KEY) {
    if (adminKey !== process.env.ADMIN_API_KEY) {
      return res.status(403).json({
        status: 'failure',
        message: 'Invalid admin key',
        details: {}
      });
    }
  }

  const result = configManager.updateConfig({
    credentials: req.body
  });

  if (!result.success) {
    return res.status(400).json({
      status: 'failure',
      message: 'Credentials update failed',
      details: {
        errors: result.errors
      }
    });
  }

  res.json({
    status: 'success',
    message: 'Credentials updated successfully',
    details: {}
  });
});

module.exports = router;

