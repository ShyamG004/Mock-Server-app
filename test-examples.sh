#!/bin/bash
# ============================================================================
# Mock Authentication Server - Test Examples
# ============================================================================
# This file contains comprehensive curl command examples for testing
# all authentication types supported by the Mock Auth Server.
#
# Usage: Run individual commands or source this file and call functions
# ============================================================================

BASE_URL="${BASE_URL:-http://localhost:3000}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_success() { echo -e "${GREEN}✓ $1${NC}"; }
echo_error() { echo -e "${RED}✗ $1${NC}"; }
echo_info() { echo -e "${YELLOW}→ $1${NC}"; }

# ============================================================================
# HEALTH & CONFIG
# ============================================================================

test_health() {
    echo_info "Testing health endpoint..."
    curl -s "$BASE_URL/health" | jq .
}

test_config_get() {
    echo_info "Getting current configuration..."
    curl -s "$BASE_URL/config" | jq .
}

test_config_update_oauth2() {
    echo_info "Updating config to OAuth2..."
    curl -s -X POST "$BASE_URL/config" \
        -H "Content-Type: application/json" \
        -d '{
            "authType": "OAuth2",
            "grantType": "Client Credentials",
            "clientAuthMethod": "Client Secret Basic"
        }' | jq .
}

test_config_update_apikey() {
    echo_info "Updating config to API Key..."
    curl -s -X POST "$BASE_URL/config" \
        -H "Content-Type: application/json" \
        -d '{
            "authType": "API Key",
            "paramLocation": "header"
        }' | jq .
}

test_config_reset() {
    echo_info "Resetting configuration..."
    curl -s -X POST "$BASE_URL/config/reset" | jq .
}

# ============================================================================
# API KEY AUTHENTICATION - 5 Test Examples
# ============================================================================

test_apikey_1_header_valid() {
    echo_info "API Key Test 1: Valid key in header"
    curl -s "$BASE_URL/api-key/test" \
        -H "X-API-Key: test_api_key_12345" | jq .
}

test_apikey_2_query_valid() {
    echo_info "API Key Test 2: Valid key in query string"
    curl -s "$BASE_URL/api-key/test?X-API-Key=test_api_key_12345" | jq .
}

test_apikey_3_invalid() {
    echo_info "API Key Test 3: Invalid key (expect 401)"
    curl -s "$BASE_URL/api-key/test" \
        -H "X-API-Key: wrong_key" | jq .
}

test_apikey_4_with_params() {
    echo_info "API Key Test 4: With dynamic parameters"
    TIMESTAMP=$(date +%s)
    NONCE=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 32 | head -n 1)
    curl -s -X POST "$BASE_URL/api-key/test-params" \
        -H "X-API-Key: test_api_key_12345" \
        -H "Content-Type: application/json" \
        -d "{
            \"timestamp\": $TIMESTAMP,
            \"nonce\": \"$NONCE\",
            \"param_1\": \"value_1\",
            \"param_2\": \"value_2\"
        }" | jq .
}

test_apikey_5_multi() {
    echo_info "API Key Test 5: Multiple API keys"
    curl -s -X POST "$BASE_URL/api-key/multi" \
        -H "X-API-Key-1: key_value_1" \
        -H "X-Key-2: key_value_2" \
        -H "Content-Type: application/json" \
        -d '{
            "api_key_3": "key_value_3",
            "key_4": "key_value_4"
        }' | jq .
}

# ============================================================================
# BASIC AUTHENTICATION - 5 Test Examples
# ============================================================================

test_basic_1_valid() {
    echo_info "Basic Auth Test 1: Valid credentials"
    curl -s -u "testuser:testpass123" "$BASE_URL/basic/test" | jq .
}

test_basic_2_invalid() {
    echo_info "Basic Auth Test 2: Invalid credentials (expect 401)"
    curl -s -u "wrong:credentials" "$BASE_URL/basic/test" | jq .
}

test_basic_3_with_params() {
    echo_info "Basic Auth Test 3: With additional parameters"
    TIMESTAMP=$(date +%s)
    curl -s -u "testuser:testpass123" \
        -X POST "$BASE_URL/basic/test-params" \
        -H "Content-Type: application/json" \
        -d "{
            \"timestamp\": $TIMESTAMP,
            \"custom_param\": \"custom_value\"
        }" | jq .
}

test_basic_4_validate_body() {
    echo_info "Basic Auth Test 4: Validate via body"
    curl -s -X POST "$BASE_URL/basic/validate" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "testuser",
            "password": "testpass123"
        }' | jq .
}

test_basic_5_multi_params() {
    echo_info "Basic Auth Test 5: With 50 parameters"
    curl -s -u "testuser:testpass123" \
        -X POST "$BASE_URL/basic/multi-params" \
        -H "Content-Type: application/json" \
        -d '{
            "param_0": "v0", "param_1": "v1", "param_2": "v2",
            "param_3": "v3", "param_4": "v4", "param_5": "v5"
        }' | jq .
}

# ============================================================================
# OAUTH 1.0 AUTHENTICATION
#
# oauth_signature is verified for real whenever oauth1.strictSignature is true
# (the default), so the requests below are signed with HMAC-SHA1 via openssl.
# ============================================================================

# RFC 3986 percent encoding - only A-Z a-z 0-9 - . _ ~ stay literal
urlencode() {
    local string="$1" i c out=""
    for (( i = 0; i < ${#string}; i++ )); do
        c="${string:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *) out+=$(printf '%%%02X' "'$c") ;;
        esac
    done
    printf '%s' "$out"
}

# oauth1_auth_header <method> <endpoint> [consumer_key] [consumer_secret]
oauth1_auth_header() {
    local method="${1:-POST}" endpoint="${2:-/oauth1/test}"
    local consumer_key="${3:-mock_consumer_key}" consumer_secret="${4:-mock_consumer_secret}"
    local timestamp nonce params base_string signing_key signature

    timestamp=$(date +%s)
    nonce=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')

    # Already in sorted-by-name order, as RFC 5849 requires
    params="oauth_consumer_key=${consumer_key}&oauth_nonce=${nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp=${timestamp}&oauth_version=1.0"

    base_string="$(echo "$method" | tr '[:lower:]' '[:upper:]')&$(urlencode "${BASE_URL}${endpoint}")&$(urlencode "$params")"
    signing_key="$(urlencode "$consumer_secret")&"

    signature=$(printf '%s' "$base_string" | openssl dgst -sha1 -hmac "$signing_key" -binary | openssl base64 -A)

    printf 'OAuth oauth_consumer_key="%s", oauth_nonce="%s", oauth_signature_method="HMAC-SHA1", oauth_timestamp="%s", oauth_version="1.0", oauth_signature="%s"' \
        "$consumer_key" "$nonce" "$timestamp" "$(urlencode "$signature")"
}

test_oauth1_1_request_token() {
    echo_info "OAuth1 Test 1: Get request token (signed)"
    curl -s -X POST "$BASE_URL/oauth1/request-token" \
        -H "Authorization: $(oauth1_auth_header POST /oauth1/request-token)"
    echo
}

test_oauth1_2_valid_signature() {
    echo_info "OAuth1 Test 2: Valid signature (expect 200)"
    curl -s -X POST "$BASE_URL/oauth1/test" \
        -H "Authorization: $(oauth1_auth_header POST /oauth1/test)" | jq .
}

test_oauth1_3_invalid_consumer() {
    echo_info "OAuth1 Test 3: Invalid consumer KEY (expect 401 'Invalid consumer key')"
    curl -s -X POST "$BASE_URL/oauth1/test" \
        -H "Authorization: $(oauth1_auth_header POST /oauth1/test wrong_key)" | jq .
}

test_oauth1_3b_invalid_consumer_secret() {
    echo_info "OAuth1 Test 3b: Invalid consumer SECRET (expect 401 'Invalid Consumer Secret')"
    curl -s -X POST "$BASE_URL/oauth1/test" \
        -H "Authorization: $(oauth1_auth_header POST /oauth1/test mock_consumer_key definitely_wrong_secret)" | jq .
}

test_oauth1_3c_strict_signature_off() {
    echo_info "OAuth1 Test 3c: strictSignature=false accepts a dummy signature"
    curl -s -X POST "$BASE_URL/config" \
        -H "Content-Type: application/json" \
        -d '{"oauth1": {"strictSignature": false}}' > /dev/null

    TIMESTAMP=$(date +%s)
    NONCE=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    curl -s -X POST "$BASE_URL/oauth1/test" \
        -H "Authorization: OAuth oauth_consumer_key=\"mock_consumer_key\", oauth_nonce=\"$NONCE\", oauth_timestamp=\"$TIMESTAMP\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"dummy_signature\", oauth_version=\"1.0\"" | jq .

    echo_info "Restoring strictSignature=true"
    curl -s -X POST "$BASE_URL/config" \
        -H "Content-Type: application/json" \
        -d '{"oauth1": {"strictSignature": true}}' > /dev/null
}

test_oauth1_4_expired_timestamp() {
    echo_info "OAuth1 Test 4: Expired timestamp (expect 401)"
    curl -s -X POST "$BASE_URL/oauth1/test" \
        -H "Authorization: OAuth oauth_consumer_key=\"mock_consumer_key\", oauth_nonce=\"abc123\", oauth_timestamp=\"1000000000\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"sig\", oauth_version=\"1.0\"" | jq .
}

test_oauth1_5_echo() {
    echo_info "OAuth1 Test 5: Echo request"
    TIMESTAMP=$(date +%s)
    curl -s -X POST "$BASE_URL/oauth1/echo" \
        -H "Authorization: OAuth oauth_consumer_key=\"mock_consumer_key\", oauth_nonce=\"test_nonce\", oauth_timestamp=\"$TIMESTAMP\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"test_sig\", oauth_version=\"1.0\"" | jq .
}

# ============================================================================
# OAUTH 2.0 AUTHENTICATION - 5 Test Examples
# ============================================================================

test_oauth2_1_client_credentials_basic() {
    echo_info "OAuth2 Test 1: Client Credentials with Basic Auth"
    curl -s -X POST "$BASE_URL/token" \
        -u "test_client_id:test_client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&scope=read write" | jq .
}

test_oauth2_2_client_credentials_post() {
    echo_info "OAuth2 Test 2: Client Credentials with POST body"
    curl -s -X POST "$BASE_URL/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=test_client_id&client_secret=test_client_secret&scope=read,write" | jq .
}

test_oauth2_3_auth_code() {
    echo_info "OAuth2 Test 3: Get Authorization Code"
    curl -s "$BASE_URL/authorize?response_type=code&client_id=test_client_id&redirect_uri=http://localhost:3000/callback&scope=read%20write&state=test_state" | jq .
}

test_oauth2_4_invalid_client() {
    echo_info "OAuth2 Test 4: Invalid client (expect 401)"
    curl -s -X POST "$BASE_URL/token" \
        -u "wrong_client:wrong_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" | jq .
}

test_oauth2_5_introspect() {
    echo_info "OAuth2 Test 5: Token introspection"
    # First get a token
    TOKEN=$(curl -s -X POST "$BASE_URL/token" \
        -u "test_client_id:test_client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&scope=read" | jq -r '.access_token')

    echo_info "Introspecting token: ${TOKEN:0:20}..."
    curl -s -X POST "$BASE_URL/oauth2/introspect" \
        -u "test_client_id:test_client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "token=$TOKEN" | jq .
}

test_oauth2_6_invalid_client_id() {
    echo_info "OAuth2 Test 6: Wrong client_id (expect 401 'Invalid Client ID')"
    curl -s -X POST "$BASE_URL/token" \
        -u "wrong_client_id:test_client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" | jq .
}

test_oauth2_7_invalid_client_secret() {
    echo_info "OAuth2 Test 7: Wrong client_secret (expect 401 'Invalid Client Secret')"
    curl -s -X POST "$BASE_URL/token" \
        -u "test_client_id:wrong_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" | jq .
}

test_oauth2_8_strict_invalid_client_secret() {
    echo_info "OAuth2 Test 8: Strict endpoint, wrong client_secret (expect 401 'Invalid Client Secret')"
    curl -s -X POST "$BASE_URL/oauth2/client-creds/basic/space/token" \
        -u "test_client_id:wrong_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&scope=read write" | jq .
}

# ============================================================================
# FAILURE SIMULATION
#
# /config, /health, /ui and /api-docs are never simulated.
# ============================================================================

reset_simulation() {
    echo_info "Resetting configuration (clears the simulation)"
    curl -s -X POST "$BASE_URL/config/reset" > /dev/null
}

test_simulation_forced_error() {
    echo_info "Simulation: force 503 on every auth endpoint"
    curl -s -X POST "$BASE_URL/config" \
        -H "Content-Type: application/json" \
        -d '{"simulation": {"mode": "error", "errorStatus": 503}}' > /dev/null

    echo_info "Auth endpoint (expect 503):"
    curl -s -o /dev/null -w "  HTTP %{http_code}\n" -X POST "$BASE_URL/token" \
        -u "test_client_id:test_client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials"

    echo_info "/health (expect 200):"
    curl -s -o /dev/null -w "  HTTP %{http_code}\n" "$BASE_URL/health"

    echo_info "/config (expect 200):"
    curl -s -o /dev/null -w "  HTTP %{http_code}\n" "$BASE_URL/config"

    reset_simulation

    echo_info "After reset, auth endpoint (expect 200):"
    curl -s -o /dev/null -w "  HTTP %{http_code}\n" -X POST "$BASE_URL/token" \
        -u "test_client_id:test_client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials"
}

test_simulation_timeout() {
    echo_info "Simulation: hang every /oauth2 request (curl gives up after 10s)"
    curl -s -X POST "$BASE_URL/config" \
        -H "Content-Type: application/json" \
        -d '{"simulation": {"mode": "timeout", "applyTo": ["/oauth2"]}}' > /dev/null

    curl -s --max-time 10 -o /dev/null -w "  HTTP %{http_code} after %{time_total}s\n" \
        -X POST "$BASE_URL/oauth2/introspect" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "token=whatever" || echo_success "no response - client timed out as expected"

    echo_info "/health still reachable:"
    curl -s -o /dev/null -w "  HTTP %{http_code}\n" "$BASE_URL/health"

    reset_simulation
}

test_simulation_delay_override() {
    echo_info "Simulation: ?_delay=5000 delays exactly one request"
    curl -s -o /dev/null -w "  delayed: HTTP %{http_code} in %{time_total}s\n" \
        "$BASE_URL/api-key/test?_delay=5000" -H "X-API-Key: test_api_key_12345"
    curl -s -o /dev/null -w "  next:    HTTP %{http_code} in %{time_total}s\n" \
        "$BASE_URL/api-key/test" -H "X-API-Key: test_api_key_12345"
}

test_simulation_status_override() {
    echo_info "Simulation: ?_status=502 forces one request to fail"
    curl -s "$BASE_URL/api-key/test?_status=502" -H "X-API-Key: test_api_key_12345" | jq .
    echo_info "Next request without the override (expect 200):"
    curl -s -o /dev/null -w "  HTTP %{http_code}\n" \
        "$BASE_URL/api-key/test" -H "X-API-Key: test_api_key_12345"
}

test_simulation_timeout_header() {
    echo_info "Simulation: x-mock-timeout hangs exactly one request"
    curl -s --max-time 10 -o /dev/null -w "  HTTP %{http_code}\n" \
        "$BASE_URL/protected" \
        -H "X-API-Key: test_api_key_12345" \
        -H "x-mock-timeout: true" || echo_success "no response - request hung as expected"

    echo_info "Next request without the header:"
    curl -s -o /dev/null -w "  HTTP %{http_code}\n" "$BASE_URL/health"
}

# ============================================================================
# PROTECTED ENDPOINT TESTS
# ============================================================================

test_protected_bearer() {
    echo_info "Protected Test: With Bearer token"
    # Get token first
    TOKEN=$(curl -s -X POST "$BASE_URL/token" \
        -u "test_client_id:test_client_secret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&scope=read" | jq -r '.access_token')

    curl -s "$BASE_URL/protected" \
        -H "Authorization: Bearer $TOKEN" | jq .
}

test_protected_apikey() {
    echo_info "Protected Test: With API Key"
    curl -s "$BASE_URL/protected" \
        -H "X-API-Key: test_api_key_12345" | jq .
}

# ============================================================================
# RUN ALL TESTS
# ============================================================================

run_all_apikey_tests() {
    echo "============================================"
    echo "Running all API Key tests..."
    echo "============================================"
    test_apikey_1_header_valid
    test_apikey_2_query_valid
    test_apikey_3_invalid
    test_apikey_4_with_params
    test_apikey_5_multi
}

run_all_basic_tests() {
    echo "============================================"
    echo "Running all Basic Auth tests..."
    echo "============================================"
    test_basic_1_valid
    test_basic_2_invalid
    test_basic_3_with_params
    test_basic_4_validate_body
    test_basic_5_multi_params
}

run_all_oauth1_tests() {
    echo "============================================"
    echo "Running all OAuth1 tests..."
    echo "============================================"
    test_oauth1_1_request_token
    test_oauth1_2_valid_signature
    test_oauth1_3_invalid_consumer
    test_oauth1_3b_invalid_consumer_secret
    test_oauth1_3c_strict_signature_off
    test_oauth1_4_expired_timestamp
    test_oauth1_5_echo
}

run_all_oauth2_tests() {
    echo "============================================"
    echo "Running all OAuth2 tests..."
    echo "============================================"
    test_oauth2_1_client_credentials_basic
    test_oauth2_2_client_credentials_post
    test_oauth2_3_auth_code
    test_oauth2_4_invalid_client
    test_oauth2_5_introspect
    test_oauth2_6_invalid_client_id
    test_oauth2_7_invalid_client_secret
    test_oauth2_8_strict_invalid_client_secret
}

run_all_simulation_tests() {
    echo "============================================"
    echo "Running all failure simulation tests..."
    echo "============================================"
    test_simulation_forced_error
    test_simulation_timeout
    test_simulation_delay_override
    test_simulation_status_override
    test_simulation_timeout_header
    reset_simulation
}

run_all_tests() {
    test_health
    test_config_get
    run_all_apikey_tests
    run_all_basic_tests
    run_all_oauth1_tests
    run_all_oauth2_tests
    run_all_simulation_tests
    echo_success "All tests completed!"
}

# If script is run directly, show usage
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "============================================"
    echo "Mock Auth Server Test Script"
    echo "============================================"
    echo ""
    echo "Usage: source test-examples.sh"
    echo "Then call individual test functions, e.g.:"
    echo "  test_health"
    echo "  test_apikey_1_header_valid"
    echo "  test_oauth1_3b_invalid_consumer_secret   # 401 'Invalid Consumer Secret'"
    echo "  test_oauth2_6_invalid_client_id          # 401 'Invalid Client ID'"
    echo "  test_oauth2_7_invalid_client_secret      # 401 'Invalid Client Secret'"
    echo "  run_all_simulation_tests                 # timeouts / delays / forced errors"
    echo "  run_all_tests"
    echo ""
    echo "Requires: curl, jq, openssl (OAuth1 requests are signed for real)"
    echo ""
    echo "Or run directly: ./test-examples.sh"
    echo ""

    # Run all tests
    run_all_tests
fi

