/**
 * OAuth2 client credential checks
 *
 * The client_id is verified BEFORE the client_secret so the caller can tell
 * "unknown client" apart from "wrong secret" - the SIEM Connections module
 * raises a different alert for each.
 *
 *   wrong client_id      -> 401 invalid_client / "Invalid Client ID"
 *   wrong client_secret  -> 401 invalid_client / "Invalid Client Secret"
 */

const INVALID_CLIENT_ID = 'Invalid Client ID';
const INVALID_CLIENT_SECRET = 'Invalid Client Secret';
const INVALID_CLIENT_ERROR_CODE = 'invalid_client';

/**
 * Check client_id then client_secret against the configured OAuth2 credentials.
 *
 * @param {string} clientId       client id presented by the caller
 * @param {string} clientSecret   client secret presented by the caller
 * @param {object} oauth2Config   config.credentials.oauth2
 * @returns {null|{valid: false, error: string, oauthError: string}}
 *          null when both match, otherwise the distinct failure
 */
function checkClientCredentials(clientId, clientSecret, oauth2Config) {
  if (clientId !== oauth2Config.clientId) {
    return {
      valid: false,
      error: INVALID_CLIENT_ID,
      oauthError: INVALID_CLIENT_ERROR_CODE
    };
  }

  if (clientSecret !== oauth2Config.clientSecret) {
    return {
      valid: false,
      error: INVALID_CLIENT_SECRET,
      oauthError: INVALID_CLIENT_ERROR_CODE
    };
  }

  return null;
}

module.exports = {
  checkClientCredentials,
  INVALID_CLIENT_ID,
  INVALID_CLIENT_SECRET,
  INVALID_CLIENT_ERROR_CODE
};
