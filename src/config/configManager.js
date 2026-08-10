/**
 * Configuration Manager
 *
 * Manages server configuration including authentication type selection,
 * parameter settings, and credential management. Supports both JSON and YAML
 * configuration files and runtime configuration updates.
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const logger = require('../utils/logger');

// Default configuration
const defaultConfig = {
  authType: 'OAuth2',
  grantType: 'Authorization Code',
  configurationType: 'Auto',
  clientAuthMethod: 'Client Secret Basic',
  scopeDelimiter: 'space',
  paramLocation: 'header',
  totalParams: 50,
  dynamicParams: 10,
  totalScopes: 50,
  credentials: {
    apiKey: {
      keys: [
        { name: 'X-API-Key', value: 'test_api_key_12345', location: 'header' }
      ]
    },
    basic: {
      username: 'testuser',
      password: 'testpass123'
    },
    oauth1: {
      consumerKey: 'mock_consumer_key',
      consumerSecret: 'mock_consumer_secret',
      tokenKey: 'mock_token_key',
      tokenSecret: 'mock_token_secret'
    },
    oauth2: {
      clientId: 'test_client_id',
      clientSecret: 'test_client_secret',
      redirectUri: 'http://localhost:3000/callback',
      authorizationUrl: '/authorize',
      tokenUrl: '/token'
    }
  },
  validation: {
    requireAllParams: true,
    validateDynamicParams: true,
    strictScopeValidation: true
  },
  // OAuth1 behaviour flags
  // strictSignature: true  -> oauth_signature is really verified with HMAC
  // strictSignature: false -> legacy mock behaviour (any non-empty signature)
  oauth1: {
    strictSignature: true
  },
  // Failure simulation ("chaos") - see src/middleware/simulationMiddleware.js
  simulation: {
    mode: 'none',
    delayMs: 0,
    errorStatus: 500,
    errorMessage: 'Simulated internal server error',
    applyTo: []
  },
  dynamicParamDefinitions: [
    { name: 'timestamp', type: 'timestamp', format: 'unix' },
    { name: 'nonce', type: 'nonce', length: 32 },
    { name: 'request_id', type: 'uuid', format: 'v4' }
  ],
  scopes: ['read', 'write', 'delete', 'admin', 'profile', 'email', 'openid', 'offline_access']
};

// Valid configuration options
const validAuthTypes = ['API Key', 'Basic Authentication', 'OAuth1', 'OAuth2'];
const validGrantTypes = ['Authorization Code', 'Authorization Code with PKCE', 'Client Credentials'];
const validConfigTypes = ['Auto', 'Manual'];
const validClientAuthMethods = ['Client Secret Basic', 'Client Secret Post', 'Client Secret JWT', 'None'];
const validScopeDelimiters = ['comma', 'space', 'plus'];
const validParamLocations = ['header', 'query', 'body', 'form'];
const validSimulationModes = ['none', 'timeout', 'error', 'delay'];

// Simulation bounds - kept in sync with src/middleware/simulationMiddleware.js
const MAX_SIMULATION_DELAY_MS = 300000;
const MIN_SIMULATION_ERROR_STATUS = 400;
const MAX_SIMULATION_ERROR_STATUS = 599;

/**
 * Deep clone plain JSON configuration so nested defaults can never be mutated
 * by a later update (matters for `simulation` which is reset via /config/reset).
 */
function cloneConfig(config) {
  return JSON.parse(JSON.stringify(config));
}

class ConfigManager {
  constructor() {
    this.config = cloneConfig(defaultConfig);
    this.configHistory = [];
  }

  /**
   * Initialize configuration from file or environment variables
   */
  initialize() {
    logger.info('Initializing configuration manager...');

    // Try to load from config file
    const configPath = this.findConfigFile();
    if (configPath) {
      this.loadFromFile(configPath);
    }

    // Override with environment variables
    this.loadFromEnv();

    logger.info('Configuration initialized', { authType: this.config.authType });
    return this.config;
  }

  /**
   * Find configuration file (JSON or YAML)
   */
  findConfigFile() {
    const possiblePaths = [
      path.join(process.cwd(), 'config', 'default.json'),
      path.join(process.cwd(), 'config', 'default.yaml'),
      path.join(process.cwd(), 'config', 'default.yml'),
      path.join(process.cwd(), 'config.json'),
      path.join(process.cwd(), 'config.yaml')
    ];

    for (const configPath of possiblePaths) {
      if (fs.existsSync(configPath)) {
        logger.info(`Found config file: ${configPath}`);
        return configPath;
      }
    }

    logger.info('No config file found, using defaults');
    return null;
  }

  /**
   * Load configuration from file
   */
  loadFromFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      let fileConfig;

      if (filePath.endsWith('.json')) {
        fileConfig = JSON.parse(content);
      } else if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
        fileConfig = yaml.load(content);
      }

      if (fileConfig) {
        this.config = this.mergeConfig(this.config, fileConfig);
        logger.info('Configuration loaded from file', { path: filePath });
      }
    } catch (error) {
      logger.error('Error loading config file', { error: error.message });
    }
  }

  /**
   * Load configuration from environment variables
   */
  loadFromEnv() {
    const envMappings = {
      DEFAULT_AUTH_TYPE: 'authType',
      DEFAULT_GRANT_TYPE: 'grantType',
      DEFAULT_CONFIG_TYPE: 'configurationType',
      DEFAULT_CLIENT_AUTH_METHOD: 'clientAuthMethod',
      DEFAULT_SCOPE_DELIMITER: 'scopeDelimiter',
      DEFAULT_PARAM_LOCATION: 'paramLocation',
      DEFAULT_TOTAL_PARAMS: 'totalParams',
      DEFAULT_DYNAMIC_PARAMS: 'dynamicParams',
      DEFAULT_TOTAL_SCOPES: 'totalScopes'
    };

    for (const [envKey, configKey] of Object.entries(envMappings)) {
      if (process.env[envKey]) {
        const value = process.env[envKey];
        // Convert numeric values
        if (['totalParams', 'dynamicParams', 'totalScopes'].includes(configKey)) {
          this.config[configKey] = parseInt(value, 10);
        } else {
          this.config[configKey] = value;
        }
      }
    }

    // Load credentials from env
    if (process.env.MOCK_CLIENT_ID) {
      this.config.credentials.oauth2.clientId = process.env.MOCK_CLIENT_ID;
    }
    if (process.env.MOCK_CLIENT_SECRET) {
      this.config.credentials.oauth2.clientSecret = process.env.MOCK_CLIENT_SECRET;
    }
    if (process.env.MOCK_API_KEY) {
      this.config.credentials.apiKey.keys[0].value = process.env.MOCK_API_KEY;
    }
    if (process.env.MOCK_USERNAME) {
      this.config.credentials.basic.username = process.env.MOCK_USERNAME;
    }
    if (process.env.MOCK_PASSWORD) {
      this.config.credentials.basic.password = process.env.MOCK_PASSWORD;
    }
  }

  /**
   * Merge configurations with deep merge
   */
  mergeConfig(target, source) {
    const result = { ...target };

    for (const key of Object.keys(source)) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = this.mergeConfig(target[key] || {}, source[key]);
      } else {
        result[key] = source[key];
      }
    }

    return result;
  }

  /**
   * Get current configuration
   */
  getConfig() {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig) {
    const validation = this.validateConfig(newConfig);

    if (!validation.valid) {
      return {
        success: false,
        errors: validation.errors
      };
    }

    // Store history
    this.configHistory.push({
      timestamp: new Date().toISOString(),
      previousConfig: { ...this.config }
    });

    // Keep only last 10 history entries
    if (this.configHistory.length > 10) {
      this.configHistory.shift();
    }

    // Merge new config
    this.config = this.mergeConfig(this.config, newConfig);

    logger.info('Configuration updated', {
      authType: this.config.authType,
      grantType: this.config.grantType
    });

    return {
      success: true,
      config: this.getConfig()
    };
  }

  /**
   * Validate configuration
   */
  validateConfig(config) {
    const errors = [];

    if (config.authType && !validAuthTypes.includes(config.authType)) {
      errors.push(`Invalid authType. Valid values: ${validAuthTypes.join(', ')}`);
    }

    if (config.grantType && !validGrantTypes.includes(config.grantType)) {
      errors.push(`Invalid grantType. Valid values: ${validGrantTypes.join(', ')}`);
    }

    if (config.configurationType && !validConfigTypes.includes(config.configurationType)) {
      errors.push(`Invalid configurationType. Valid values: ${validConfigTypes.join(', ')}`);
    }

    if (config.clientAuthMethod && !validClientAuthMethods.includes(config.clientAuthMethod)) {
      errors.push(`Invalid clientAuthMethod. Valid values: ${validClientAuthMethods.join(', ')}`);
    }

    if (config.scopeDelimiter && !validScopeDelimiters.includes(config.scopeDelimiter)) {
      errors.push(`Invalid scopeDelimiter. Valid values: ${validScopeDelimiters.join(', ')}`);
    }

    if (config.paramLocation && !validParamLocations.includes(config.paramLocation)) {
      errors.push(`Invalid paramLocation. Valid values: ${validParamLocations.join(', ')}`);
    }

    if (config.totalParams !== undefined && (config.totalParams < 0 || config.totalParams > 1000)) {
      errors.push('totalParams must be between 0 and 1000');
    }

    if (config.dynamicParams !== undefined && (config.dynamicParams < 0 || config.dynamicParams > 100)) {
      errors.push('dynamicParams must be between 0 and 100');
    }

    if (config.totalScopes !== undefined && (config.totalScopes < 0 || config.totalScopes > 100)) {
      errors.push('totalScopes must be between 0 and 100');
    }

    this.validateOAuth1Block(config, errors);
    this.validateSimulationBlock(config, errors);

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate the OAuth1 behaviour flags (accepted at `oauth1` or
   * `credentials.oauth1` for convenience).
   */
  validateOAuth1Block(config, errors) {
    const blocks = [
      { label: 'oauth1.strictSignature', value: config.oauth1 },
      {
        label: 'credentials.oauth1.strictSignature',
        value: config.credentials ? config.credentials.oauth1 : undefined
      }
    ];

    for (const { label, value } of blocks) {
      if (!value || typeof value !== 'object') continue;
      if (value.strictSignature === undefined) continue;
      if (typeof value.strictSignature !== 'boolean') {
        errors.push(`${label} must be a boolean`);
      }
    }
  }

  /**
   * Validate the failure simulation block
   */
  validateSimulationBlock(config, errors) {
    const simulation = config.simulation;

    if (simulation === undefined) return;

    if (simulation === null || typeof simulation !== 'object' || Array.isArray(simulation)) {
      errors.push('simulation must be an object');
      return;
    }

    if (simulation.mode !== undefined && !validSimulationModes.includes(simulation.mode)) {
      errors.push(`Invalid simulation.mode. Valid values: ${validSimulationModes.join(', ')}`);
    }

    if (simulation.delayMs !== undefined) {
      if (!Number.isInteger(simulation.delayMs) ||
          simulation.delayMs < 0 ||
          simulation.delayMs > MAX_SIMULATION_DELAY_MS) {
        errors.push(`simulation.delayMs must be an integer between 0 and ${MAX_SIMULATION_DELAY_MS}`);
      }
    }

    if (simulation.errorStatus !== undefined) {
      if (!Number.isInteger(simulation.errorStatus) ||
          simulation.errorStatus < MIN_SIMULATION_ERROR_STATUS ||
          simulation.errorStatus > MAX_SIMULATION_ERROR_STATUS) {
        errors.push(
          `simulation.errorStatus must be an integer between ${MIN_SIMULATION_ERROR_STATUS} and ${MAX_SIMULATION_ERROR_STATUS}`
        );
      }
    }

    if (simulation.errorMessage !== undefined && typeof simulation.errorMessage !== 'string') {
      errors.push('simulation.errorMessage must be a string');
    }

    if (simulation.applyTo !== undefined) {
      if (!Array.isArray(simulation.applyTo)) {
        errors.push('simulation.applyTo must be an array of route prefixes');
      } else if (simulation.applyTo.some((prefix) => typeof prefix !== 'string' || !prefix.trim())) {
        errors.push('simulation.applyTo entries must be non-empty strings (e.g. "/oauth2")');
      }
    }
  }

  /**
   * Reset configuration to defaults
   */
  resetConfig() {
    this.configHistory.push({
      timestamp: new Date().toISOString(),
      previousConfig: { ...this.config }
    });

    this.config = cloneConfig(defaultConfig);
    logger.info('Configuration reset to defaults (including failure simulation)');

    return this.getConfig();
  }

  /**
   * Get configuration history
   */
  getHistory() {
    return [...this.configHistory];
  }

  /**
   * Get valid options for configuration
   */
  getValidOptions() {
    return {
      authTypes: validAuthTypes,
      grantTypes: validGrantTypes,
      configurationTypes: validConfigTypes,
      clientAuthMethods: validClientAuthMethods,
      scopeDelimiters: validScopeDelimiters,
      paramLocations: validParamLocations,
      simulationModes: validSimulationModes,
      simulationLimits: {
        maxDelayMs: MAX_SIMULATION_DELAY_MS,
        minErrorStatus: MIN_SIMULATION_ERROR_STATUS,
        maxErrorStatus: MAX_SIMULATION_ERROR_STATUS
      },
      perRequestOverrides: {
        delayQueryParam: '_delay',
        statusQueryParam: '_status',
        timeoutHeader: 'x-mock-timeout'
      }
    };
  }

  /**
   * Generate dynamic parameters based on configuration
   */
  generateDynamicParams(count = this.config.dynamicParams) {
    const params = {};
    const definitions = this.config.dynamicParamDefinitions || [];

    for (let i = 0; i < count; i++) {
      const def = definitions[i % definitions.length] || { name: `dynamic_param_${i}`, type: 'string' };
      const paramName = i < definitions.length ? def.name : `dynamic_param_${i}`;

      switch (def.type) {
        case 'timestamp':
          params[paramName] = Math.floor(Date.now() / 1000);
          break;
        case 'nonce':
          params[paramName] = this.generateNonce(def.length || 32);
          break;
        case 'uuid':
          params[paramName] = this.generateUUID();
          break;
        default:
          params[paramName] = `value_${i}_${Date.now()}`;
      }
    }

    return params;
  }

  /**
   * Generate random nonce
   */
  generateNonce(length = 32) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  /**
   * Generate UUID v4
   */
  generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  /**
   * Generate test parameters based on totalParams config
   */
  generateTestParams(count = this.config.totalParams) {
    const params = {};
    for (let i = 0; i < count; i++) {
      params[`param_${i}`] = `value_${i}`;
    }
    return params;
  }

  /**
   * Generate scopes based on configuration
   */
  generateScopes(count = this.config.totalScopes) {
    const baseScopes = this.config.scopes || [];
    const scopes = [];

    for (let i = 0; i < count; i++) {
      if (i < baseScopes.length) {
        scopes.push(baseScopes[i]);
      } else {
        scopes.push(`scope_${i}`);
      }
    }

    return scopes;
  }

  /**
   * Parse scopes based on delimiter
   */
  parseScopes(scopeString, delimiter = this.config.scopeDelimiter) {
    if (!scopeString) return [];

    let delimiterChar;
    switch (delimiter) {
      case 'comma':
        delimiterChar = ',';
        break;
      case 'plus':
        delimiterChar = '+';
        break;
      case 'space':
      default:
        delimiterChar = ' ';
    }

    return scopeString.split(delimiterChar).map(s => s.trim()).filter(s => s);
  }

  /**
   * Format scopes with configured delimiter
   */
  formatScopes(scopes, delimiter = this.config.scopeDelimiter) {
    if (!scopes || !Array.isArray(scopes)) return '';

    let delimiterChar;
    switch (delimiter) {
      case 'comma':
        delimiterChar = ',';
        break;
      case 'plus':
        delimiterChar = '+';
        break;
      case 'space':
      default:
        delimiterChar = ' ';
    }

    return scopes.join(delimiterChar);
  }
}

// Export singleton instance
module.exports = new ConfigManager();

