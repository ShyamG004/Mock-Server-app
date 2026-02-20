# Windows PowerShell Test Examples for Mock Auth Server
# ============================================================================
# This file contains test examples using PowerShell for Windows users
# ============================================================================

$BASE_URL = if ($env:BASE_URL) { $env:BASE_URL } else { "http://localhost:3000" }

# Helper function to make requests
function Invoke-MockAuthRequest {
    param(
        [string]$Method = "GET",
        [string]$Endpoint,
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [string]$ContentType = "application/json"
    )

    $uri = "$BASE_URL$Endpoint"
    $params = @{
        Method = $Method
        Uri = $uri
        Headers = $Headers
        ContentType = $ContentType
    }

    if ($Body) {
        $params.Body = $Body
    }

    try {
        $response = Invoke-RestMethod @params
        $response | ConvertTo-Json -Depth 10
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.ErrorDetails.Message) {
            $_.ErrorDetails.Message | ConvertFrom-Json | ConvertTo-Json -Depth 10
        }
    }
}

# ============================================================================
# HEALTH & CONFIG
# ============================================================================

function Test-Health {
    Write-Host "Testing health endpoint..." -ForegroundColor Yellow
    Invoke-MockAuthRequest -Endpoint "/health"
}

function Get-CurrentConfig {
    Write-Host "Getting current configuration..." -ForegroundColor Yellow
    Invoke-MockAuthRequest -Endpoint "/config"
}

function Set-ConfigOAuth2 {
    Write-Host "Updating config to OAuth2..." -ForegroundColor Yellow
    $body = @{
        authType = "OAuth2"
        grantType = "Client Credentials"
        clientAuthMethod = "Client Secret Basic"
    } | ConvertTo-Json

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/config" -Body $body
}

function Set-ConfigApiKey {
    Write-Host "Updating config to API Key..." -ForegroundColor Yellow
    $body = @{
        authType = "API Key"
        paramLocation = "header"
    } | ConvertTo-Json

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/config" -Body $body
}

# ============================================================================
# API KEY TESTS
# ============================================================================

function Test-ApiKey-Header {
    Write-Host "API Key Test: Valid key in header" -ForegroundColor Yellow
    $headers = @{ "X-API-Key" = "test_api_key_12345" }
    Invoke-MockAuthRequest -Endpoint "/api-key/test" -Headers $headers
}

function Test-ApiKey-Query {
    Write-Host "API Key Test: Valid key in query" -ForegroundColor Yellow
    Invoke-MockAuthRequest -Endpoint "/api-key/test?X-API-Key=test_api_key_12345"
}

function Test-ApiKey-Invalid {
    Write-Host "API Key Test: Invalid key (expect 401)" -ForegroundColor Yellow
    $headers = @{ "X-API-Key" = "wrong_key" }
    Invoke-MockAuthRequest -Endpoint "/api-key/test" -Headers $headers
}

function Test-ApiKey-WithParams {
    Write-Host "API Key Test: With dynamic parameters" -ForegroundColor Yellow
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $nonce = [guid]::NewGuid().ToString("N")

    $headers = @{ "X-API-Key" = "test_api_key_12345" }
    $body = @{
        timestamp = $timestamp
        nonce = $nonce
        param_1 = "value_1"
        param_2 = "value_2"
    } | ConvertTo-Json

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/api-key/test-params" -Headers $headers -Body $body
}

function Test-ApiKey-Multi {
    Write-Host "API Key Test: Multiple keys" -ForegroundColor Yellow
    $headers = @{
        "X-API-Key-1" = "key_value_1"
        "X-Key-2" = "key_value_2"
    }
    $body = @{
        api_key_3 = "key_value_3"
        key_4 = "key_value_4"
    } | ConvertTo-Json

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/api-key/multi" -Headers $headers -Body $body
}

# ============================================================================
# BASIC AUTH TESTS
# ============================================================================

function Test-BasicAuth-Valid {
    Write-Host "Basic Auth Test: Valid credentials" -ForegroundColor Yellow
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("testuser:testpass123"))
    $headers = @{ "Authorization" = "Basic $creds" }
    Invoke-MockAuthRequest -Endpoint "/basic/test" -Headers $headers
}

function Test-BasicAuth-Invalid {
    Write-Host "Basic Auth Test: Invalid credentials" -ForegroundColor Yellow
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("wrong:credentials"))
    $headers = @{ "Authorization" = "Basic $creds" }
    Invoke-MockAuthRequest -Endpoint "/basic/test" -Headers $headers
}

function Test-BasicAuth-WithParams {
    Write-Host "Basic Auth Test: With parameters" -ForegroundColor Yellow
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("testuser:testpass123"))
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    $headers = @{ "Authorization" = "Basic $creds" }
    $body = @{
        timestamp = $timestamp
        custom_param = "custom_value"
    } | ConvertTo-Json

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/basic/test-params" -Headers $headers -Body $body
}

function Test-BasicAuth-Validate {
    Write-Host "Basic Auth Test: Validate via body" -ForegroundColor Yellow
    $body = @{
        username = "testuser"
        password = "testpass123"
    } | ConvertTo-Json

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/basic/validate" -Body $body
}

function Test-BasicAuth-MultiParams {
    Write-Host "Basic Auth Test: With 50 parameters" -ForegroundColor Yellow
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("testuser:testpass123"))
    $headers = @{ "Authorization" = "Basic $creds" }

    $params = @{}
    for ($i = 0; $i -lt 50; $i++) {
        $params["param_$i"] = "value_$i"
    }
    $body = $params | ConvertTo-Json

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/basic/multi-params" -Headers $headers -Body $body
}

# ============================================================================
# OAUTH 1.0 TESTS
# ============================================================================

function Test-OAuth1-RequestToken {
    Write-Host "OAuth1 Test: Get request token" -ForegroundColor Yellow
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $nonce = [guid]::NewGuid().ToString("N")

    $authHeader = "OAuth oauth_consumer_key=`"mock_consumer_key`", oauth_nonce=`"$nonce`", oauth_timestamp=`"$timestamp`", oauth_signature_method=`"HMAC-SHA1`", oauth_signature=`"mock_signature`", oauth_version=`"1.0`""
    $headers = @{ "Authorization" = $authHeader }

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/oauth1/request-token" -Headers $headers
}

function Test-OAuth1-ValidSignature {
    Write-Host "OAuth1 Test: Valid signature" -ForegroundColor Yellow
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $nonce = [guid]::NewGuid().ToString("N")

    $authHeader = "OAuth oauth_consumer_key=`"mock_consumer_key`", oauth_nonce=`"$nonce`", oauth_timestamp=`"$timestamp`", oauth_signature_method=`"HMAC-SHA1`", oauth_signature=`"valid_signature`", oauth_version=`"1.0`""
    $headers = @{ "Authorization" = $authHeader }

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/oauth1/test" -Headers $headers
}

function Test-OAuth1-InvalidConsumer {
    Write-Host "OAuth1 Test: Invalid consumer key" -ForegroundColor Yellow
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    $authHeader = "OAuth oauth_consumer_key=`"wrong_key`", oauth_nonce=`"abc123`", oauth_timestamp=`"$timestamp`", oauth_signature_method=`"HMAC-SHA1`", oauth_signature=`"sig`", oauth_version=`"1.0`""
    $headers = @{ "Authorization" = $authHeader }

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/oauth1/test" -Headers $headers
}

function Test-OAuth1-ExpiredTimestamp {
    Write-Host "OAuth1 Test: Expired timestamp" -ForegroundColor Yellow
    $authHeader = "OAuth oauth_consumer_key=`"mock_consumer_key`", oauth_nonce=`"abc123`", oauth_timestamp=`"1000000000`", oauth_signature_method=`"HMAC-SHA1`", oauth_signature=`"sig`", oauth_version=`"1.0`""
    $headers = @{ "Authorization" = $authHeader }

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/oauth1/test" -Headers $headers
}

function Test-OAuth1-Echo {
    Write-Host "OAuth1 Test: Echo request" -ForegroundColor Yellow
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    $authHeader = "OAuth oauth_consumer_key=`"mock_consumer_key`", oauth_nonce=`"test_nonce`", oauth_timestamp=`"$timestamp`", oauth_signature_method=`"HMAC-SHA1`", oauth_signature=`"test_sig`", oauth_version=`"1.0`""
    $headers = @{ "Authorization" = $authHeader }

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/oauth1/echo" -Headers $headers
}

# ============================================================================
# OAUTH 2.0 TESTS
# ============================================================================

function Test-OAuth2-ClientCredentials-Basic {
    Write-Host "OAuth2 Test: Client Credentials with Basic Auth" -ForegroundColor Yellow
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("test_client_id:test_client_secret"))
    $headers = @{ "Authorization" = "Basic $creds" }
    $body = "grant_type=client_credentials&scope=read write"

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/token" -Headers $headers -Body $body -ContentType "application/x-www-form-urlencoded"
}

function Test-OAuth2-ClientCredentials-Post {
    Write-Host "OAuth2 Test: Client Credentials with POST body" -ForegroundColor Yellow
    $body = "grant_type=client_credentials&client_id=test_client_id&client_secret=test_client_secret&scope=read,write"

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/token" -Body $body -ContentType "application/x-www-form-urlencoded"
}

function Test-OAuth2-AuthCode {
    Write-Host "OAuth2 Test: Get Authorization Code" -ForegroundColor Yellow
    $redirectUri = [uri]::EscapeDataString("http://localhost:3000/callback")
    Invoke-MockAuthRequest -Endpoint "/authorize?response_type=code&client_id=test_client_id&redirect_uri=$redirectUri&scope=read%20write&state=test_state"
}

function Test-OAuth2-InvalidClient {
    Write-Host "OAuth2 Test: Invalid client" -ForegroundColor Yellow
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("wrong_client:wrong_secret"))
    $headers = @{ "Authorization" = "Basic $creds" }
    $body = "grant_type=client_credentials"

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/token" -Headers $headers -Body $body -ContentType "application/x-www-form-urlencoded"
}

function Test-OAuth2-Introspect {
    Write-Host "OAuth2 Test: Token introspection" -ForegroundColor Yellow

    # First get a token
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("test_client_id:test_client_secret"))
    $headers = @{ "Authorization" = "Basic $creds" }
    $body = "grant_type=client_credentials&scope=read"

    $tokenResponse = Invoke-RestMethod -Method POST -Uri "$BASE_URL/token" -Headers $headers -Body $body -ContentType "application/x-www-form-urlencoded"
    $token = $tokenResponse.access_token

    Write-Host "Introspecting token: $($token.Substring(0, 20))..." -ForegroundColor Cyan

    $introspectBody = "token=$token"
    Invoke-MockAuthRequest -Method "POST" -Endpoint "/oauth2/introspect" -Headers $headers -Body $introspectBody -ContentType "application/x-www-form-urlencoded"
}

# ============================================================================
# PROTECTED ENDPOINT TESTS
# ============================================================================

function Test-Protected-Bearer {
    Write-Host "Protected Test: With Bearer token" -ForegroundColor Yellow

    # Get token first
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("test_client_id:test_client_secret"))
    $authHeaders = @{ "Authorization" = "Basic $creds" }
    $tokenResponse = Invoke-RestMethod -Method POST -Uri "$BASE_URL/token" -Headers $authHeaders -Body "grant_type=client_credentials&scope=read" -ContentType "application/x-www-form-urlencoded"

    $headers = @{ "Authorization" = "Bearer $($tokenResponse.access_token)" }
    Invoke-MockAuthRequest -Endpoint "/protected" -Headers $headers
}

function Test-Protected-ApiKey {
    Write-Host "Protected Test: With API Key" -ForegroundColor Yellow
    $headers = @{ "X-API-Key" = "test_api_key_12345" }
    Invoke-MockAuthRequest -Endpoint "/protected" -Headers $headers
}

# ============================================================================
# RUN ALL TESTS
# ============================================================================

function Run-AllApiKeyTests {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "Running all API Key tests..." -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Test-ApiKey-Header
    Test-ApiKey-Query
    Test-ApiKey-Invalid
    Test-ApiKey-WithParams
    Test-ApiKey-Multi
}

function Run-AllBasicAuthTests {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "Running all Basic Auth tests..." -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Test-BasicAuth-Valid
    Test-BasicAuth-Invalid
    Test-BasicAuth-WithParams
    Test-BasicAuth-Validate
    Test-BasicAuth-MultiParams
}

function Run-AllOAuth1Tests {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "Running all OAuth1 tests..." -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Test-OAuth1-RequestToken
    Test-OAuth1-ValidSignature
    Test-OAuth1-InvalidConsumer
    Test-OAuth1-ExpiredTimestamp
    Test-OAuth1-Echo
}

function Run-AllOAuth2Tests {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "Running all OAuth2 tests..." -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Test-OAuth2-ClientCredentials-Basic
    Test-OAuth2-ClientCredentials-Post
    Test-OAuth2-AuthCode
    Test-OAuth2-InvalidClient
    Test-OAuth2-Introspect
}

function Run-AllTests {
    Test-Health
    Get-CurrentConfig
    Run-AllApiKeyTests
    Run-AllBasicAuthTests
    Run-AllOAuth1Tests
    Run-AllOAuth2Tests
    Write-Host "All tests completed!" -ForegroundColor Green
}

# Show usage
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Mock Auth Server PowerShell Test Script" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Available functions:" -ForegroundColor Yellow
Write-Host "  Test-Health, Get-CurrentConfig" -ForegroundColor White
Write-Host "  Test-ApiKey-Header, Test-ApiKey-Query, Test-ApiKey-Invalid" -ForegroundColor White
Write-Host "  Test-BasicAuth-Valid, Test-BasicAuth-Invalid" -ForegroundColor White
Write-Host "  Test-OAuth1-RequestToken, Test-OAuth1-ValidSignature" -ForegroundColor White
Write-Host "  Test-OAuth2-ClientCredentials-Basic, Test-OAuth2-AuthCode" -ForegroundColor White
Write-Host "  Run-AllTests" -ForegroundColor White
Write-Host ""
Write-Host "Example: Run-AllTests" -ForegroundColor Green

