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

## Distinct Credential Errors

The OAuth2 token endpoints check the **client_id first, then the client_secret**,
so a client can tell the two failures apart:

| Situation | Status | \`error_description\` / \`message\` |
| --- | --- | --- |
| Unknown \`client_id\` | 401 | \`Invalid Client ID\` |
| Known \`client_id\`, wrong \`client_secret\` | 401 | \`Invalid Client Secret\` |

OAuth1 verifies \`oauth_signature\` for real (RFC 5849 HMAC-SHA1 / HMAC-SHA256 /
PLAINTEXT). The consumer key is checked **first**:

| Situation | Status | \`message\` |
| --- | --- | --- |
| Unknown \`oauth_consumer_key\` | 401 | \`OAuth1 signature validation failed\` (\`details.errors\` contains \`Invalid consumer key\`) |
| Known key, signature does not match the consumer secret | 401 | \`Invalid Consumer Secret\` |

Set \`{ "oauth1": { "strictSignature": false } }\` via \`POST /config\` to fall back
to the legacy mock behaviour where any non-empty signature is accepted.

## Failure Simulation

Force backend failures so client-side error alerts can be verified.

Global, via \`POST /config\`:

\`\`\`json
{
  "simulation": {
    "mode": "none | timeout | error | delay",
    "delayMs": 0,
    "errorStatus": 500,
    "errorMessage": "Simulated internal server error",
    "applyTo": ["/oauth2", "/oauth1", "/apikey", "/basic", "/protected"]
  }
}
\`\`\`

Per-request, working even while \`mode\` is \`none\`:

- \`?_delay=<ms>\` - delay that single request (max 300000)
- \`?_status=<400-599>\` - force that status on that single request
- \`x-mock-timeout: true\` - hang that single request

\`/config\`, \`/health\`, \`/ui\` and \`/api-docs\` are **never** simulated, so the
server always stays controllable. \`POST /config/reset\` clears the simulation.
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
      { name: 'Protected', description: 'Protected resource endpoints' },
      { name: 'Simulation', description: 'Failure simulation - timeouts, delays and forced errors' }
    ],
    components: {
      parameters: {
        SimulateDelay: {
          name: '_delay',
          in: 'query',
          required: false,
          description: 'Failure simulation override - delay this single request by N milliseconds (0-300000) before it is handled normally.',
          schema: { type: 'integer', minimum: 0, maximum: 300000, example: 5000 }
        },
        SimulateStatus: {
          name: '_status',
          in: 'query',
          required: false,
          description: 'Failure simulation override - respond immediately with this HTTP status (400-599) and body `{ "status": "failure", "message": "Simulated error via _status" }`.',
          schema: { type: 'integer', minimum: 400, maximum: 599, example: 503 }
        },
        SimulateTimeoutHeader: {
          name: 'x-mock-timeout',
          in: 'header',
          required: false,
          description: 'Failure simulation override - set to `true` to hang this single request (no response is ever sent). Combine with `?_delay=<ms>` to destroy the socket after that delay.',
          schema: { type: 'string', enum: ['true', 'false'], example: 'true' }
        }
      },
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
        OAuth2ClientErrorResponse: {
          type: 'object',
          description:
            'Returned by the OAuth2 token endpoints with HTTP 401 when the client credentials do not match. ' +
            'The client_id is checked before the client_secret so the two failures are distinguishable.',
          properties: {
            error: {
              type: 'string',
              enum: ['invalid_client'],
              example: 'invalid_client'
            },
            error_description: {
              type: 'string',
              enum: ['Invalid Client ID', 'Invalid Client Secret'],
              example: 'Invalid Client ID'
            },
            status: {
              type: 'string',
              enum: ['failure'],
              example: 'failure'
            },
            message: {
              type: 'string',
              enum: ['Invalid Client ID', 'Invalid Client Secret'],
              example: 'Invalid Client ID'
            }
          },
          example: {
            error: 'invalid_client',
            error_description: 'Invalid Client ID',
            status: 'failure',
            message: 'Invalid Client ID'
          }
        },
        OAuth1SignatureErrorResponse: {
          type: 'object',
          description:
            'Returned with HTTP 401 when oauth_signature does not match the configured consumer secret. ' +
            'A wrong oauth_consumer_key is reported first and separately as "Invalid consumer key".',
          properties: {
            status: {
              type: 'string',
              enum: ['failure'],
              example: 'failure'
            },
            message: {
              type: 'string',
              enum: ['Invalid Consumer Secret'],
              example: 'Invalid Consumer Secret'
            },
            details: {
              type: 'object',
              properties: {
                error: { type: 'string', example: 'Invalid Consumer Secret' },
                signatureMethod: { type: 'string', example: 'HMAC-SHA1' },
                providedSignature: { type: 'string', example: 'wrong+signature=' },
                expectedSignature: { type: 'string', example: 'kx3s0Uu0mVQ9x2Bw6c0eA6Zt1Zg=' },
                signatureBaseString: {
                  type: 'string',
                  example: 'POST&https%3A%2F%2Fexample.com%2Foauth1%2Ftest&oauth_consumer_key%3D...'
                },
                signatureBaseUrl: { type: 'string', example: 'https://example.com/oauth1/test' },
                hint: { type: 'string' }
              }
            }
          }
        },
        SimulatedFailureResponse: {
          type: 'object',
          description: 'Body returned when the failure simulation forces an error status.',
          properties: {
            status: {
              type: 'string',
              enum: ['failure'],
              example: 'failure'
            },
            message: {
              type: 'string',
              example: 'Simulated internal server error'
            }
          },
          example: {
            status: 'failure',
            message: 'Simulated internal server error'
          }
        },
        SimulationConfig: {
          type: 'object',
          description:
            'Failure simulation block. Never applied to /config, /health, /ui or /api-docs. ' +
            'Cleared by POST /config/reset.',
          properties: {
            mode: {
              type: 'string',
              enum: ['none', 'timeout', 'error', 'delay'],
              default: 'none',
              description:
                'none: disabled. timeout: hold the request open and never respond ' +
                '(destroy the socket after delayMs when delayMs > 0). ' +
                'delay: wait delayMs then handle normally. error: respond immediately with errorStatus.'
            },
            delayMs: {
              type: 'integer',
              minimum: 0,
              maximum: 300000,
              default: 0,
              description: 'Delay in milliseconds, capped at 300000.'
            },
            errorStatus: {
              type: 'integer',
              minimum: 400,
              maximum: 599,
              default: 500,
              description: 'Status returned when mode is "error".'
            },
            errorMessage: {
              type: 'string',
              default: 'Simulated internal server error',
              description: 'Message returned when mode is "error".'
            },
            applyTo: {
              type: 'array',
              items: { type: 'string' },
              default: [],
              description: 'Route prefixes to affect. Empty or omitted means all non-control routes.',
              example: ['/oauth2', '/oauth1', '/apikey', '/basic', '/protected']
            }
          },
          example: {
            mode: 'error',
            delayMs: 0,
            errorStatus: 503,
            errorMessage: 'Simulated internal server error',
            applyTo: ['/oauth2']
          }
        },
        OAuth1BehaviourConfig: {
          type: 'object',
          description: 'OAuth1 behaviour flags.',
          properties: {
            strictSignature: {
              type: 'boolean',
              default: true,
              description:
                'true: oauth_signature is verified against the configured consumer secret; a mismatch answers ' +
                '401 "Invalid Consumer Secret". false: legacy mock behaviour, any non-empty signature is accepted.'
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
            },
            oauth1: {
              $ref: '#/components/schemas/OAuth1BehaviourConfig'
            },
            simulation: {
              $ref: '#/components/schemas/SimulationConfig'
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

