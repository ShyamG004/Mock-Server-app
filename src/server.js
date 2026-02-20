/**
 * Mock Authentication Server
 *
 * A production-ready mock authentication server for testing all authentication
 * type configurations. Supports API Key, Basic Auth, OAuth 1.0, and OAuth 2.0.
 *
 * @author Mock Auth Server Team
 * @version 1.0.0
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const multer = require('multer');
const swaggerUi = require('swagger-ui-express');
const path = require('path');

// Import custom modules
const logger = require('./utils/logger');
const configManager = require('./config/configManager');
const swaggerSpec = require('./docs/swagger');

// Import routes
const configRoutes = require('./routes/configRoutes');
const apiKeyRoutes = require('./routes/apiKeyRoutes');
const basicAuthRoutes = require('./routes/basicAuthRoutes');
const oauth1Routes = require('./routes/oauth1Routes');
const oauth2Routes = require('./routes/oauth2Routes');
const oauth2StrictRoutes = require('./routes/oauth2StrictRoutes');
const protectedRoutes = require('./routes/protectedRoutes');
const healthRoutes = require('./routes/healthRoutes');

// Import middleware
const { requestLogger } = require('./middleware/requestLogger');
const { errorHandler } = require('./middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure multer for form-data (memory storage, no file uploads)
const upload = multer({ storage: multer.memoryStorage() });

// =============================================================================
// MIDDLEWARE CONFIGURATION
// =============================================================================

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-API-Secret',
                   'X-Request-ID', 'X-Timestamp', 'X-Nonce', 'X-Custom-*'],
  exposedHeaders: ['X-Request-ID', 'X-Response-Time'],
  credentials: true
}));

// Body parsing middleware
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Multer middleware for multipart/form-data (parses form fields into req.body)
app.use(upload.none());

// Request logging
app.use(morgan('combined', { stream: { write: (message) => logger.http(message.trim()) } }));
app.use(requestLogger);

// Static files for UI
app.use(express.static(path.join(__dirname, 'public')));

// =============================================================================
// API DOCUMENTATION
// =============================================================================

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'Mock Auth Server API Docs'
}));

// =============================================================================
// ROUTES
// =============================================================================

// Health check routes
app.use('/health', healthRoutes);

// Configuration management routes
app.use('/config', configRoutes);

// Authentication routes
app.use('/api-key', apiKeyRoutes);
app.use('/basic', basicAuthRoutes);
app.use('/oauth1', oauth1Routes);
app.use('/oauth2', oauth2Routes);

// OAuth2 STRICT endpoints (dedicated per configuration)
app.use('/oauth2', oauth2StrictRoutes);

// OAuth2 root-level endpoints (for standard OAuth2 flow)
app.use('/', oauth2Routes);

// Protected resource endpoint
app.use('/protected', protectedRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    status: 'success',
    message: 'Mock Authentication Server is running',
    version: '1.0.0',
    documentation: '/api-docs',
    ui: '/ui',
    endpoints: {
      health: '/health',
      config: '/config',
      protected: '/protected',
      apiKey: '/api-key/test',
      basicAuth: '/basic/test',
      oauth1: '/oauth1/request-token, /oauth1/access-token',
      oauth2: '/authorize, /token, /oauth2/introspect'
    },
    currentConfig: configManager.getConfig()
  });
});

// Serve UI page
app.get('/ui', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =============================================================================
// ERROR HANDLING
// =============================================================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    status: 'failure',
    message: 'Endpoint not found',
    details: {
      path: req.path,
      method: req.method
    }
  });
});

// Global error handler
app.use(errorHandler);

// =============================================================================
// SERVER STARTUP
// =============================================================================

// Initialize configuration
configManager.initialize();

// Start server
app.listen(PORT, () => {
  logger.info(`🚀 Mock Authentication Server started on port ${PORT}`);
  logger.info(`📚 API Documentation available at http://localhost:${PORT}/api-docs`);
  logger.info(`🖥️  Test UI available at http://localhost:${PORT}/ui`);
  logger.info(`⚙️  Current auth type: ${configManager.getConfig().authType}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

module.exports = app;

