/**
 * Swagger/OpenAPI Configuration
 *
 * Provides comprehensive API documentation for all authentication endpoints.
 */

const swaggerJsdoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Mock Authentication Server API',
      version: '1.0.0',
      description: `
# Mock Authentication Server

A production-ready mock authentication server for testing all authentication type configurations.

## Supported Authentication Types

- **API Key Authentication** - Header, Query, Form Data support
- **Basic Authentication** - Username/password validation
- **OAuth 1.0** - Request token, access token, signature validation
- **OAuth 2.0** - Authorization Code, PKCE, Client Credentials

## Configuration

The server supports dynamic configuration via:
- Config files (JSON/YAML)
- Admin endpoint (\`/config\`)
- Environment variables

## Getting Started

1. Check current config: \`GET /config\`
2. Update auth type: \`POST /config/auth-type\`
3. Test authentication: \`GET /protected\`
      `,
      contact: {
        name: 'API Support',
        email: 'support@example.com'
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT'
      }
    },
    servers: [
      {
        url: '/',
        description: 'Current server'
      }
    ],
    tags: [
      { name: 'Health', description: 'Health check endpoints' },
      { name: 'Configuration', description: 'Server configuration management' },
      { name: 'API Key', description: 'API Key authentication endpoints' },
      { name: 'Basic Auth', description: 'Basic authentication endpoints' },
      { name: 'OAuth1', description: 'OAuth 1.0 authentication endpoints' },
      { name: 'OAuth2', description: 'OAuth 2.0 authentication endpoints' },
      { name: 'Protected', description: 'Protected resource endpoints' }
    ],
    components: {
      securitySchemes: {
        apiKey: {
          type: 'apiKey',
          in: 'header',
          name: 'X-API-Key',
          description: 'API Key authentication'
        },
        basicAuth: {
          type: 'http',
          scheme: 'basic',
          description: 'Basic authentication'
        },
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'OAuth2 Bearer token'
        },
        oauth2: {
          type: 'oauth2',
          description: 'OAuth 2.0 authentication',
          flows: {
            authorizationCode: {
              authorizationUrl: '/authorize',
              tokenUrl: '/token',
              scopes: {
                read: 'Read access',
                write: 'Write access',
                admin: 'Admin access'
              }
            },
            clientCredentials: {
              tokenUrl: '/token',
              scopes: {
                read: 'Read access',
                write: 'Write access'
              }
            }
          }
        }
      },
      schemas: {
        SuccessResponse: {
          type: 'object',
          properties: {
            status: {
              type: 'string',
              enum: ['success'],
              example: 'success'
            },
            message: {
              type: 'string',
              example: 'Operation completed successfully'
            },
            details: {
              type: 'object',
              additionalProperties: true
            }
          }
        },
        ErrorResponse: {
          type: 'object',
          properties: {
            status: {
              type: 'string',
              enum: ['failure'],
              example: 'failure'
            },
            message: {
              type: 'string',
              example: 'Operation failed'
            },
            details: {
              type: 'object',
              properties: {
                errors: {
                  type: 'array',
                  items: { type: 'string' }
                }
              }
            }
          }
        },
        TokenResponse: {
          type: 'object',
          properties: {
            access_token: {
              type: 'string',
              example: 'at_abc123...'
            },
            token_type: {
              type: 'string',
              example: 'Bearer'
            },
            expires_in: {
              type: 'integer',
              example: 3600
            },
            refresh_token: {
              type: 'string',
              example: 'rt_xyz789...'
            },
            scope: {
              type: 'string',
              example: 'read write'
            }
          }
        },
        ConfigurationObject: {
          type: 'object',
          properties: {
            authType: {
              type: 'string',
              enum: ['API Key', 'Basic Authentication', 'OAuth1', 'OAuth2']
            },
            grantType: {
              type: 'string',
              enum: ['Authorization Code', 'Authorization Code with PKCE', 'Client Credentials']
            },
            configurationType: {
              type: 'string',
              enum: ['Auto', 'Manual']
            },
            clientAuthMethod: {
              type: 'string',
              enum: ['Client Secret Basic', 'Client Secret Post', 'Client Secret JWT', 'None']
            },
            scopeDelimiter: {
              type: 'string',
              enum: ['comma', 'space', 'plus']
            },
            paramLocation: {
              type: 'string',
              enum: ['header', 'query', 'body', 'form']
            },
            totalParams: {
              type: 'integer',
              minimum: 0,
              maximum: 1000
            },
            dynamicParams: {
              type: 'integer',
              minimum: 0,
              maximum: 100
            },
            totalScopes: {
              type: 'integer',
              minimum: 0,
              maximum: 100
            }
          }
        }
      }
    }
  },
  apis: ['./src/routes/*.js']
};

const swaggerSpec = swaggerJsdoc(options);

module.exports = swaggerSpec;

