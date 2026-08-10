/**
 * OAuth 1.0a Signature Utilities (RFC 5849)
 *
 * Real signature verification used by the OAuth1 routes and the shared
 * validation engine. Supports HMAC-SHA1, HMAC-SHA256 and PLAINTEXT.
 *
 * Reverse proxy note (Render / any TLS terminator):
 * The signature base string embeds the *client facing* URL. Behind a proxy the
 * socket-level protocol/host are the internal ones, so `x-forwarded-proto` and
 * `x-forwarded-host` are honoured when rebuilding the base URL. Several
 * candidate base URLs are tried so a signature stays verifiable whether the
 * client signed the public URL or the internal one.
 *
 * Only Node's built-in `crypto` is used - no extra dependencies.
 */

const crypto = require('crypto');

// oauth_signature_method -> Node HMAC algorithm
const HMAC_ALGORITHMS = {
  'HMAC-SHA1': 'sha1',
  'HMAC-SHA256': 'sha256'
};

const SUPPORTED_SIGNATURE_METHODS = ['HMAC-SHA1', 'HMAC-SHA256', 'PLAINTEXT'];

/**
 * RFC 3986 percent encoding (RFC 5849 section 3.6).
 * encodeURIComponent leaves !'()* unescaped, so they are escaped explicitly.
 * The unreserved set -._~ stays literal.
 */
function percentEncode(value) {
  if (value === undefined || value === null) return '';
  return encodeURIComponent(String(value)).replace(
    /[!'()*]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()
  );
}

/**
 * Decode a percent-encoded value without throwing on malformed input.
 * `plusIsSpace` must be true for query-string values only.
 */
function safeDecode(value, plusIsSpace = false) {
  const input = plusIsSpace ? String(value).replace(/\+/g, ' ') : String(value);
  try {
    return decodeURIComponent(input);
  } catch (e) {
    return input;
  }
}

/**
 * Parse an `Authorization: OAuth ...` header into a plain object.
 *
 * Splits on the FIRST '=' of each pair so base64 signatures keep their '='
 * padding, and only strips the surrounding quotes.
 */
function parseOAuth1Header(header) {
  const params = {};

  if (!header || !/^OAuth\s/i.test(header)) {
    return params;
  }

  const oauthPart = header.replace(/^OAuth\s+/i, '');

  for (const pair of oauthPart.split(',')) {
    const trimmed = pair.trim();
    if (!trimmed) continue;

    const eqIndex = trimmed.indexOf('=');
    if (eqIndex <= 0) continue;

    const key = trimmed.substring(0, eqIndex).trim();
    let value = trimmed.substring(eqIndex + 1).trim();

    // Remove surrounding quotes (leading and trailing only)
    if (value.length >= 2) {
      const first = value.charAt(0);
      const last = value.charAt(value.length - 1);
      if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
        value = value.substring(1, value.length - 1);
      }
    }

    params[key] = safeDecode(value);
  }

  return params;
}

/**
 * Lowercase the host and drop the default port for the scheme (RFC 5849 3.4.1.2)
 */
function normalizeHost(host, protocol) {
  if (!host) return '';

  const normalized = String(host).trim().toLowerCase();

  if (protocol === 'http' && normalized.endsWith(':80')) {
    return normalized.slice(0, -3);
  }
  if (protocol === 'https' && normalized.endsWith(':443')) {
    return normalized.slice(0, -4);
  }

  return normalized;
}

/**
 * `x-forwarded-*` headers may be a comma separated chain - the client facing
 * value is the first entry.
 */
function firstForwardedValue(headerValue) {
  if (!headerValue) return '';
  return String(headerValue).split(',')[0].trim();
}

/**
 * Build the candidate signature base URLs, most likely first.
 * The forwarded (public) URL wins, the direct one is kept as a fallback.
 */
function buildCandidateBaseUrls(req) {
  const requestPath = String(req.originalUrl || req.url || '/').split('?')[0];

  const directHost = (typeof req.get === 'function' ? req.get('host') : req.headers.host) || '';
  const directProtocol = String(req.protocol || 'http').toLowerCase();

  const forwardedHost = firstForwardedValue(req.headers['x-forwarded-host']);
  const forwardedProtocol = firstForwardedValue(req.headers['x-forwarded-proto']).toLowerCase();

  const protocol = forwardedProtocol || directProtocol;
  const host = forwardedHost || directHost;

  const combinations = [
    [protocol, host],
    [protocol, directHost],
    [directProtocol, directHost],
    ['https', host],
    ['http', host]
  ];

  const urls = [];
  for (const [proto, hostCandidate] of combinations) {
    if (!proto || !hostCandidate) continue;

    const scheme = String(proto).toLowerCase();
    const url = `${scheme}://${normalizeHost(hostCandidate, scheme)}${requestPath}`;

    if (!urls.includes(url)) {
      urls.push(url);
    }
  }

  return urls;
}

function isPrimitive(value) {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

/**
 * Collect every parameter that takes part in the signature (RFC 5849 3.4.1.3.1):
 * - query string parameters
 * - x-www-form-urlencoded body parameters
 * - the OAuth protocol parameters, minus `oauth_signature` and `realm`
 *
 * The query string is read from the raw URL rather than `req.query` so the
 * express `extended` parser cannot reshape it.
 */
function collectSignatureParams(req, oauthParams) {
  const params = [];

  const originalUrl = String(req.originalUrl || req.url || '');
  const queryIndex = originalUrl.indexOf('?');

  if (queryIndex !== -1) {
    for (const pair of originalUrl.slice(queryIndex + 1).split('&')) {
      if (!pair) continue;
      const eqIndex = pair.indexOf('=');
      const rawKey = eqIndex === -1 ? pair : pair.slice(0, eqIndex);
      const rawValue = eqIndex === -1 ? '' : pair.slice(eqIndex + 1);
      params.push([safeDecode(rawKey, true), safeDecode(rawValue, true)]);
    }
  }

  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  if (contentType.includes('application/x-www-form-urlencoded') && req.body && typeof req.body === 'object') {
    for (const [key, value] of Object.entries(req.body)) {
      if (Array.isArray(value)) {
        for (const item of value) {
          if (isPrimitive(item)) params.push([key, String(item)]);
        }
      } else if (isPrimitive(value)) {
        params.push([key, String(value)]);
      }
    }
  }

  for (const [key, value] of Object.entries(oauthParams || {})) {
    if (key === 'oauth_signature' || key === 'realm') continue;
    params.push([key, value === undefined || value === null ? '' : String(value)]);
  }

  return params;
}

/**
 * Percent-encode, sort by encoded name then encoded value, join with '&'
 */
function normalizeParams(params) {
  return params
    .map(([key, value]) => [percentEncode(key), percentEncode(value)])
    .sort((a, b) => {
      if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
      if (a[1] !== b[1]) return a[1] < b[1] ? -1 : 1;
      return 0;
    })
    .map(([key, value]) => `${key}=${value}`)
    .join('&');
}

/**
 * METHOD & percentEncode(baseUrl) & percentEncode(normalizedParams)
 */
function buildSignatureBaseString(method, baseUrl, params) {
  return [
    String(method || 'GET').toUpperCase(),
    percentEncode(baseUrl),
    percentEncode(normalizeParams(params))
  ].join('&');
}

/**
 * percentEncode(consumerSecret) & percentEncode(tokenSecret)
 */
function buildSigningKey(consumerSecret, tokenSecret) {
  return `${percentEncode(consumerSecret || '')}&${percentEncode(tokenSecret || '')}`;
}

/**
 * Compute the expected oauth_signature. Returns null for unknown methods.
 */
function computeSignature(signatureMethod, baseString, consumerSecret, tokenSecret) {
  const signingKey = buildSigningKey(consumerSecret, tokenSecret);

  if (signatureMethod === 'PLAINTEXT') {
    return signingKey;
  }

  const algorithm = HMAC_ALGORITHMS[signatureMethod];
  if (!algorithm) return null;

  return crypto.createHmac(algorithm, signingKey).update(baseString, 'utf8').digest('base64');
}

/**
 * Constant-time string comparison that tolerates length mismatches.
 */
function safeCompare(a, b) {
  const bufferA = Buffer.from(String(a === undefined || a === null ? '' : a), 'utf8');
  const bufferB = Buffer.from(String(b === undefined || b === null ? '' : b), 'utf8');

  if (bufferA.length !== bufferB.length) return false;
  if (bufferA.length === 0) return true;

  return crypto.timingSafeEqual(bufferA, bufferB);
}

function dedupe(values) {
  const seen = [];
  for (const value of values) {
    const normalized = value === undefined || value === null ? '' : String(value);
    if (!seen.includes(normalized)) seen.push(normalized);
  }
  return seen;
}

/**
 * Verify `oauth_signature` against the consumer secret (and token secret).
 *
 * @param {object} req                    express request
 * @param {object} oauthParams            parsed OAuth1 protocol parameters
 * @param {object} options
 * @param {string} options.consumerSecret the configured consumer secret
 * @param {string[]} [options.tokenSecrets] candidate token secrets; the empty
 *        secret (two-legged / request-token step) is always appended
 *
 * @returns {{valid: boolean, signatureMethod: string, expectedSignature: ?string,
 *            baseString: ?string, baseUrl: ?string, error: ?string}}
 */
function verifyOAuth1Signature(req, oauthParams, options = {}) {
  const signatureMethod = String(oauthParams.oauth_signature_method || 'HMAC-SHA1').toUpperCase();
  const providedSignature = oauthParams.oauth_signature || '';
  const consumerSecret = options.consumerSecret || '';
  const tokenSecrets = dedupe([...(options.tokenSecrets || []), '']);

  if (!SUPPORTED_SIGNATURE_METHODS.includes(signatureMethod)) {
    return {
      valid: false,
      signatureMethod,
      expectedSignature: null,
      baseString: null,
      baseUrl: null,
      error: `Unsupported signature method: ${signatureMethod}`
    };
  }

  // PLAINTEXT - the signature is the signing key itself
  if (signatureMethod === 'PLAINTEXT') {
    for (const tokenSecret of tokenSecrets) {
      const encodedKey = buildSigningKey(consumerSecret, tokenSecret);
      const rawKey = `${consumerSecret}&${tokenSecret}`;

      if (safeCompare(providedSignature, encodedKey) || safeCompare(providedSignature, rawKey)) {
        return {
          valid: true,
          signatureMethod,
          expectedSignature: encodedKey,
          baseString: null,
          baseUrl: null,
          tokenSecretUsed: tokenSecret,
          error: null
        };
      }
    }

    return {
      valid: false,
      signatureMethod,
      expectedSignature: buildSigningKey(consumerSecret, tokenSecrets[0]),
      baseString: null,
      baseUrl: null,
      error: null
    };
  }

  // HMAC-SHA1 / HMAC-SHA256
  const params = collectSignatureParams(req, oauthParams);
  const candidateBaseUrls = buildCandidateBaseUrls(req);

  let firstExpected = null;
  let firstBaseString = null;

  for (const baseUrl of candidateBaseUrls) {
    const baseString = buildSignatureBaseString(req.method, baseUrl, params);

    for (const tokenSecret of tokenSecrets) {
      const expectedSignature = computeSignature(signatureMethod, baseString, consumerSecret, tokenSecret);

      if (firstExpected === null) {
        firstExpected = expectedSignature;
        firstBaseString = baseString;
      }

      if (safeCompare(providedSignature, expectedSignature)) {
        return {
          valid: true,
          signatureMethod,
          expectedSignature,
          baseString,
          baseUrl,
          tokenSecretUsed: tokenSecret,
          error: null
        };
      }
    }
  }

  return {
    valid: false,
    signatureMethod,
    expectedSignature: firstExpected,
    baseString: firstBaseString,
    baseUrl: candidateBaseUrls[0] || null,
    candidateBaseUrls,
    error: null
  };
}

/**
 * Resolve whether strict (real) signature verification is enabled.
 * Accepts the flag at `oauth1.strictSignature` or, for convenience,
 * at `credentials.oauth1.strictSignature`. Defaults to true.
 */
function isStrictSignatureEnabled(config) {
  const credentialFlag = config && config.credentials && config.credentials.oauth1
    ? config.credentials.oauth1.strictSignature
    : undefined;

  if (typeof credentialFlag === 'boolean') return credentialFlag;

  const topLevelFlag = config && config.oauth1 ? config.oauth1.strictSignature : undefined;
  if (typeof topLevelFlag === 'boolean') return topLevelFlag;

  return true;
}

module.exports = {
  HMAC_ALGORITHMS,
  SUPPORTED_SIGNATURE_METHODS,
  percentEncode,
  safeDecode,
  parseOAuth1Header,
  normalizeHost,
  buildCandidateBaseUrls,
  collectSignatureParams,
  normalizeParams,
  buildSignatureBaseString,
  buildSigningKey,
  computeSignature,
  safeCompare,
  verifyOAuth1Signature,
  isStrictSignatureEnabled
};
