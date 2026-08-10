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

# Like Invoke-MockAuthRequest but always returns the status code, so failure
# cases (401 / 503 / client timeout) can be asserted instead of just printed.
function Invoke-MockAuthRaw {
    param(
        [string]$Method = "GET",
        [string]$Endpoint,
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [string]$ContentType = "application/json",
        [int]$TimeoutSec = 100
    )

    $params = @{
        Method          = $Method
        Uri             = "$BASE_URL$Endpoint"
        Headers         = $Headers
        ContentType     = $ContentType
        TimeoutSec      = $TimeoutSec
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }

    if ($Body) { $params.Body = $Body }

    try {
        $response = Invoke-WebRequest @params
        return [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Body       = $response.Content
            TimedOut   = $false
            Error      = $null
        }
    } catch {
        $status = 0
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $status = [int]$_.Exception.Response.StatusCode
        }

        $body = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $body = $_.ErrorDetails.Message }

        return [pscustomobject]@{
            StatusCode = $status
            Body       = $body
            TimedOut   = ($status -eq 0)
            Error      = $_.Exception.Message
        }
    }
}

# Print a raw result and flag whether it matched the expected status
function Show-MockAuthResult {
    param(
        [Parameter(Mandatory = $true)]$Result,
        [int]$ExpectedStatus = 0,
        [string]$ExpectedMessage = $null
    )

    if ($Result.TimedOut) {
        Write-Host "  no response (client timed out / connection dropped)" -ForegroundColor Magenta
    } else {
        Write-Host "  HTTP $($Result.StatusCode)" -ForegroundColor Cyan
    }

    if ($Result.Body) {
        try {
            $Result.Body | ConvertFrom-Json | ConvertTo-Json -Depth 10
        } catch {
            Write-Host $Result.Body
        }
    }

    $ok = $true
    if ($ExpectedStatus -gt 0 -and $Result.StatusCode -ne $ExpectedStatus) { $ok = $false }
    if ($ExpectedMessage -and $Result.Body -notlike "*$ExpectedMessage*") { $ok = $false }

    if ($ExpectedStatus -gt 0 -or $ExpectedMessage) {
        if ($ok) {
            Write-Host "  PASS" -ForegroundColor Green
        } else {
            $expected = if ($ExpectedStatus -gt 0) { "status $ExpectedStatus" } else { "" }
            if ($ExpectedMessage) { $expected = "$expected message like '$ExpectedMessage'" }
            Write-Host "  FAIL (expected $expected)" -ForegroundColor Red
        }
    }
}

# ============================================================================
# OAUTH 1.0 SIGNING HELPERS (RFC 5849)
#
# The server verifies oauth_signature against the configured consumer secret
# whenever oauth1.strictSignature is true (the default), so signatures have to
# be computed for real.
# ============================================================================

# RFC 3986 percent encoding - only A-Z a-z 0-9 - . _ ~ stay literal
function ConvertTo-OAuth1Encoded {
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return "" }

    $unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    $builder = New-Object System.Text.StringBuilder

    foreach ($byte in [Text.Encoding]::UTF8.GetBytes($Value)) {
        $char = [char]$byte
        if ($unreserved.IndexOf($char) -ge 0) {
            [void]$builder.Append($char)
        } else {
            [void]$builder.AppendFormat("%{0:X2}", $byte)
        }
    }

    return $builder.ToString()
}

# HMAC-SHA1 signature over METHOD & percentEncode(url) & percentEncode(params)
function Get-OAuth1Signature {
    param(
        [string]$Method,
        [string]$Url,
        [hashtable]$Params,
        [string]$ConsumerSecret,
        [string]$TokenSecret = ""
    )

    $normalized = ($Params.GetEnumerator() | ForEach-Object {
        [pscustomobject]@{
            K = (ConvertTo-OAuth1Encoded $_.Key)
            V = (ConvertTo-OAuth1Encoded ([string]$_.Value))
        }
    } | Sort-Object K, V | ForEach-Object { "$($_.K)=$($_.V)" }) -join '&'

    $baseString = "{0}&{1}&{2}" -f $Method.ToUpper(),
        (ConvertTo-OAuth1Encoded $Url),
        (ConvertTo-OAuth1Encoded $normalized)

    $signingKey = "{0}&{1}" -f (ConvertTo-OAuth1Encoded $ConsumerSecret),
        (ConvertTo-OAuth1Encoded $TokenSecret)

    $hmac = New-Object System.Security.Cryptography.HMACSHA1
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($signingKey)
    $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($baseString))
    $hmac.Dispose()

    return [Convert]::ToBase64String($hash)
}

# Build a fully signed "Authorization: OAuth ..." header value
function New-OAuth1Header {
    param(
        [string]$Method = "POST",
        [string]$Path = "/oauth1/test",
        [string]$ConsumerKey = "mock_consumer_key",
        [string]$ConsumerSecret = "mock_consumer_secret",
        [string]$TokenSecret = "",
        [hashtable]$Extra = @{}
    )

    $params = @{
        oauth_consumer_key     = $ConsumerKey
        oauth_nonce            = [guid]::NewGuid().ToString("N")
        oauth_signature_method = "HMAC-SHA1"
        oauth_timestamp        = [string][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        oauth_version          = "1.0"
    }

    foreach ($key in $Extra.Keys) { $params[$key] = $Extra[$key] }

    $params["oauth_signature"] = Get-OAuth1Signature -Method $Method -Url "$BASE_URL$Path" `
        -Params $params -ConsumerSecret $ConsumerSecret -TokenSecret $TokenSecret

    $parts = $params.GetEnumerator() | Sort-Object Key | ForEach-Object {
        '{0}="{1}"' -f $_.Key, (ConvertTo-OAuth1Encoded ([string]$_.Value))
    }

    return "OAuth " + ($parts -join ", ")
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
    Write-Host "OAuth1 Test: Get request token (signed, expect 200)" -ForegroundColor Yellow

    # At this step there is no token yet, so the signing key is "consumerSecret&"
    $headers = @{ "Authorization" = (New-OAuth1Header -Method "POST" -Path "/oauth1/request-token") }

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth1/request-token" -Headers $headers
    Show-MockAuthResult -Result $result -ExpectedStatus 200
}

function Test-OAuth1-ValidSignature {
    Write-Host "OAuth1 Test: Valid signature (expect 200)" -ForegroundColor Yellow

    $headers = @{ "Authorization" = (New-OAuth1Header -Method "POST" -Path "/oauth1/test") }

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth1/test" -Headers $headers
    Show-MockAuthResult -Result $result -ExpectedStatus 200
}

function Test-OAuth1-InvalidConsumer {
    Write-Host "OAuth1 Test: Invalid consumer KEY (expect 401 'Invalid consumer key')" -ForegroundColor Yellow

    # Signed correctly, but with an unknown consumer key: the key is checked
    # first, so the answer must be the consumer-key error, not a secret error.
    $headers = @{ "Authorization" = (New-OAuth1Header -Method "POST" -Path "/oauth1/test" -ConsumerKey "wrong_key") }

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth1/test" -Headers $headers
    Show-MockAuthResult -Result $result -ExpectedStatus 401 -ExpectedMessage "Invalid consumer key"
}

function Test-OAuth1-InvalidConsumerSecret {
    Write-Host "OAuth1 Test: Invalid consumer SECRET (expect 401 'Invalid Consumer Secret')" -ForegroundColor Yellow

    # Correct consumer key, signature computed with the wrong secret
    $headers = @{ "Authorization" = (New-OAuth1Header -Method "POST" -Path "/oauth1/test" -ConsumerSecret "definitely_wrong_secret") }

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth1/test" -Headers $headers
    Show-MockAuthResult -Result $result -ExpectedStatus 401 -ExpectedMessage "Invalid Consumer Secret"
}

function Test-OAuth1-StrictSignatureOff {
    Write-Host "OAuth1 Test: strictSignature=false accepts a dummy signature" -ForegroundColor Yellow

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/config" -Body '{"oauth1": {"strictSignature": false}}' | Out-Null

    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $nonce = [guid]::NewGuid().ToString("N")
    $authHeader = "OAuth oauth_consumer_key=`"mock_consumer_key`", oauth_nonce=`"$nonce`", oauth_timestamp=`"$timestamp`", oauth_signature_method=`"HMAC-SHA1`", oauth_signature=`"dummy_signature`", oauth_version=`"1.0`""

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth1/test" -Headers @{ "Authorization" = $authHeader }
    Show-MockAuthResult -Result $result -ExpectedStatus 200

    Write-Host "Restoring strictSignature=true..." -ForegroundColor DarkGray
    Invoke-MockAuthRequest -Method "POST" -Endpoint "/config" -Body '{"oauth1": {"strictSignature": true}}' | Out-Null
}

function Test-OAuth1-ExpiredTimestamp {
    Write-Host "OAuth1 Test: Expired timestamp (expect 401)" -ForegroundColor Yellow

    $headers = @{ "Authorization" = (New-OAuth1Header -Method "POST" -Path "/oauth1/test" -Extra @{ oauth_timestamp = "1000000000" }) }

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth1/test" -Headers $headers
    Show-MockAuthResult -Result $result -ExpectedStatus 401 -ExpectedMessage "timestamp expired"
}

function Test-OAuth1-Echo {
    Write-Host "OAuth1 Test: Echo request" -ForegroundColor Yellow

    $headers = @{ "Authorization" = (New-OAuth1Header -Method "POST" -Path "/oauth1/echo") }

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/oauth1/echo" -Headers $headers
}

function Test-OAuth1-FullFlow {
    Write-Host "OAuth1 Test: Full three-legged flow (signed at every step)" -ForegroundColor Yellow

    # 1. Request token
    $headers = @{ "Authorization" = (New-OAuth1Header -Method "POST" -Path "/oauth1/request-token") }
    $tokenResult = Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth1/request-token" -Headers $headers

    if ($tokenResult.StatusCode -ne 200) {
        Show-MockAuthResult -Result $tokenResult -ExpectedStatus 200
        return
    }

    $pairs = @{}
    foreach ($pair in $tokenResult.Body -split '&') {
        $kv = $pair -split '=', 2
        if ($kv.Length -eq 2) { $pairs[$kv[0]] = [uri]::UnescapeDataString($kv[1]) }
    }

    $requestToken = $pairs["oauth_token"]
    $requestTokenSecret = $pairs["oauth_token_secret"]
    Write-Host "  request token: $requestToken" -ForegroundColor Cyan

    # 2. Authorize (skip_login shortcut for API testing)
    $authorize = Invoke-MockAuthRaw -Method "GET" -Endpoint "/oauth1/authorize?oauth_token=$requestToken&skip_login=true"
    $verifier = ($authorize.Body | ConvertFrom-Json).details.oauth_verifier
    Write-Host "  verifier: $verifier" -ForegroundColor Cyan

    # 3. Access token - now signed with "consumerSecret&requestTokenSecret"
    $accessHeaders = @{
        "Authorization" = (New-OAuth1Header -Method "POST" -Path "/oauth1/access-token" `
            -TokenSecret $requestTokenSecret `
            -Extra @{ oauth_token = $requestToken; oauth_verifier = $verifier })
    }

    $accessResult = Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth1/access-token" -Headers $accessHeaders
    Show-MockAuthResult -Result $accessResult -ExpectedStatus 200
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

# ----------------------------------------------------------------------------
# Distinct "Invalid Client ID" vs "Invalid Client Secret"
# The client_id is validated before the client_secret on every token endpoint.
# ----------------------------------------------------------------------------

function Test-OAuth2-InvalidClientId-Basic {
    Write-Host "OAuth2 Test: Wrong client_id via Basic (expect 401 'Invalid Client ID')" -ForegroundColor Yellow
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("wrong_client_id:test_client_secret"))
    $headers = @{ "Authorization" = "Basic $creds" }

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/token" -Headers $headers `
        -Body "grant_type=client_credentials" -ContentType "application/x-www-form-urlencoded"
    Show-MockAuthResult -Result $result -ExpectedStatus 401 -ExpectedMessage "Invalid Client ID"
}

function Test-OAuth2-InvalidClientSecret-Basic {
    Write-Host "OAuth2 Test: Wrong client_secret via Basic (expect 401 'Invalid Client Secret')" -ForegroundColor Yellow
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("test_client_id:wrong_secret"))
    $headers = @{ "Authorization" = "Basic $creds" }

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/token" -Headers $headers `
        -Body "grant_type=client_credentials" -ContentType "application/x-www-form-urlencoded"
    Show-MockAuthResult -Result $result -ExpectedStatus 401 -ExpectedMessage "Invalid Client Secret"
}

function Test-OAuth2-InvalidClientId-Post {
    Write-Host "OAuth2 Test: Wrong client_id in body (expect 401 'Invalid Client ID')" -ForegroundColor Yellow

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/token/post" `
        -Body "grant_type=client_credentials&client_id=wrong_client_id&client_secret=test_client_secret" `
        -ContentType "application/x-www-form-urlencoded"
    Show-MockAuthResult -Result $result -ExpectedStatus 401 -ExpectedMessage "Invalid Client ID"
}

function Test-OAuth2-InvalidClientSecret-Post {
    Write-Host "OAuth2 Test: Wrong client_secret in body (expect 401 'Invalid Client Secret')" -ForegroundColor Yellow

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/token/post" `
        -Body "grant_type=client_credentials&client_id=test_client_id&client_secret=wrong_secret" `
        -ContentType "application/x-www-form-urlencoded"
    Show-MockAuthResult -Result $result -ExpectedStatus 401 -ExpectedMessage "Invalid Client Secret"
}

function Test-OAuth2-Strict-InvalidClientId {
    Write-Host "OAuth2 Strict Test: Wrong client_id (expect 401 'Invalid Client ID')" -ForegroundColor Yellow
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("wrong_client_id:test_client_secret"))
    $headers = @{ "Authorization" = "Basic $creds" }

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth2/client-creds/basic/space/token" -Headers $headers `
        -Body "grant_type=client_credentials&scope=read write" -ContentType "application/x-www-form-urlencoded"
    Show-MockAuthResult -Result $result -ExpectedStatus 401 -ExpectedMessage "Invalid Client ID"
}

function Test-OAuth2-Strict-InvalidClientSecret {
    Write-Host "OAuth2 Strict Test: Wrong client_secret (expect 401 'Invalid Client Secret')" -ForegroundColor Yellow
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("test_client_id:wrong_secret"))
    $headers = @{ "Authorization" = "Basic $creds" }

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth2/client-creds/basic/space/token" -Headers $headers `
        -Body "grant_type=client_credentials&scope=read write" -ContentType "application/x-www-form-urlencoded"
    Show-MockAuthResult -Result $result -ExpectedStatus 401 -ExpectedMessage "Invalid Client Secret"
}

function Test-OAuth2-Strict-InvalidClientSecret-Post {
    Write-Host "OAuth2 Strict Test: Wrong client_secret in body (expect 401 'Invalid Client Secret')" -ForegroundColor Yellow

    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth2/client-creds/post/space/token" `
        -Body "grant_type=client_credentials&client_id=test_client_id&client_secret=wrong_secret&scope=read write" `
        -ContentType "application/x-www-form-urlencoded"
    Show-MockAuthResult -Result $result -ExpectedStatus 401 -ExpectedMessage "Invalid Client Secret"
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
# FAILURE SIMULATION TESTS
#
# Global "chaos" config + per-request overrides. /config, /health, /ui and
# /api-docs are never simulated, so the server stays controllable throughout.
# ============================================================================

function Set-Simulation {
    param([string]$Json)

    Write-Host "Applying simulation: $Json" -ForegroundColor Yellow
    Invoke-MockAuthRequest -Method "POST" -Endpoint "/config" -Body $Json
}

function Reset-Simulation {
    Write-Host "Resetting configuration (clears the simulation)..." -ForegroundColor Yellow
    Invoke-MockAuthRequest -Method "POST" -Endpoint "/config/reset" | Out-Null
    Write-Host "  simulation cleared" -ForegroundColor Green
}

function Get-SimulationConfig {
    Write-Host "Current simulation block:" -ForegroundColor Yellow
    $result = Invoke-MockAuthRaw -Endpoint "/config"
    ($result.Body | ConvertFrom-Json).details.config.simulation | ConvertTo-Json -Depth 10
}

function Test-Simulation-ForcedError {
    Write-Host "Simulation Test: force 503 on every auth endpoint" -ForegroundColor Yellow

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/config" `
        -Body '{"simulation": {"mode": "error", "errorStatus": 503}}' | Out-Null

    Write-Host "Auth endpoint (expect 503):" -ForegroundColor Cyan
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("test_client_id:test_client_secret"))
    $auth = Invoke-MockAuthRaw -Method "POST" -Endpoint "/token" -Headers @{ "Authorization" = "Basic $creds" } `
        -Body "grant_type=client_credentials" -ContentType "application/x-www-form-urlencoded"
    Show-MockAuthResult -Result $auth -ExpectedStatus 503

    Write-Host "Control endpoint /health (expect 200):" -ForegroundColor Cyan
    Show-MockAuthResult -Result (Invoke-MockAuthRaw -Endpoint "/health") -ExpectedStatus 200

    Write-Host "Control endpoint /config (expect 200):" -ForegroundColor Cyan
    Show-MockAuthResult -Result (Invoke-MockAuthRaw -Endpoint "/config") -ExpectedStatus 200

    Reset-Simulation

    Write-Host "After reset, auth endpoint (expect 200):" -ForegroundColor Cyan
    $after = Invoke-MockAuthRaw -Method "POST" -Endpoint "/token" -Headers @{ "Authorization" = "Basic $creds" } `
        -Body "grant_type=client_credentials" -ContentType "application/x-www-form-urlencoded"
    Show-MockAuthResult -Result $after -ExpectedStatus 200
}

function Test-Simulation-ScopedError {
    Write-Host "Simulation Test: force 500 on /oauth1 only" -ForegroundColor Yellow

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/config" `
        -Body '{"simulation": {"mode": "error", "errorStatus": 500, "applyTo": ["/oauth1"]}}' | Out-Null

    Write-Host "/oauth1/test (expect 500):" -ForegroundColor Cyan
    $headers = @{ "Authorization" = (New-OAuth1Header -Method "POST" -Path "/oauth1/test") }
    Show-MockAuthResult -Result (Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth1/test" -Headers $headers) -ExpectedStatus 500

    Write-Host "/api-key/test (expect 200 - outside applyTo):" -ForegroundColor Cyan
    Show-MockAuthResult -Result (Invoke-MockAuthRaw -Endpoint "/api-key/test" -Headers @{ "X-API-Key" = "test_api_key_12345" }) -ExpectedStatus 200

    Reset-Simulation
}

function Test-Simulation-Delay {
    Write-Host "Simulation Test: global 5s delay on every auth endpoint" -ForegroundColor Yellow

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/config" `
        -Body '{"simulation": {"mode": "delay", "delayMs": 5000}}' | Out-Null

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-MockAuthRaw -Endpoint "/api-key/test" -Headers @{ "X-API-Key" = "test_api_key_12345" }
    $stopwatch.Stop()

    Write-Host "  elapsed: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2))s (expect >= 5s)" -ForegroundColor Cyan
    Show-MockAuthResult -Result $result -ExpectedStatus 200

    Reset-Simulation
}

function Test-Simulation-Timeout {
    Write-Host "Simulation Test: hang every /oauth2 request (expect client timeout)" -ForegroundColor Yellow

    Invoke-MockAuthRequest -Method "POST" -Endpoint "/config" `
        -Body '{"simulation": {"mode": "timeout", "applyTo": ["/oauth2"]}}' | Out-Null

    Write-Host "/oauth2/introspect with a 10s client timeout:" -ForegroundColor Cyan
    $result = Invoke-MockAuthRaw -Method "POST" -Endpoint "/oauth2/introspect" -TimeoutSec 10 `
        -Body "token=whatever" -ContentType "application/x-www-form-urlencoded"

    if ($result.TimedOut) {
        Write-Host "  PASS - server never responded" -ForegroundColor Green
    } else {
        Write-Host "  FAIL - got HTTP $($result.StatusCode)" -ForegroundColor Red
    }

    Write-Host "/health (expect 200 - still controllable):" -ForegroundColor Cyan
    Show-MockAuthResult -Result (Invoke-MockAuthRaw -Endpoint "/health") -ExpectedStatus 200

    Reset-Simulation
}

# ----------------------------------------------------------------------------
# Per-request overrides - these work even while simulation.mode is "none"
# ----------------------------------------------------------------------------

function Test-Simulation-DelayOverride {
    Write-Host "Simulation Test: ?_delay=5000 delays exactly one request" -ForegroundColor Yellow

    $headers = @{ "X-API-Key" = "test_api_key_12345" }

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $delayed = Invoke-MockAuthRaw -Endpoint "/api-key/test?_delay=5000" -Headers $headers
    $stopwatch.Stop()
    Write-Host "  delayed request: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2))s (expect >= 5s)" -ForegroundColor Cyan
    Show-MockAuthResult -Result $delayed -ExpectedStatus 200

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $normal = Invoke-MockAuthRaw -Endpoint "/api-key/test" -Headers $headers
    $stopwatch.Stop()
    Write-Host "  next request: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2))s (expect < 1s - the delay was one-off)" -ForegroundColor Cyan
    Show-MockAuthResult -Result $normal -ExpectedStatus 200
}

function Test-Simulation-StatusOverride {
    Write-Host "Simulation Test: ?_status=502 forces one request to fail" -ForegroundColor Yellow

    $headers = @{ "X-API-Key" = "test_api_key_12345" }

    $forced = Invoke-MockAuthRaw -Endpoint "/api-key/test?_status=502" -Headers $headers
    Show-MockAuthResult -Result $forced -ExpectedStatus 502 -ExpectedMessage "Simulated error via _status"

    Write-Host "Next request without the override (expect 200):" -ForegroundColor Cyan
    Show-MockAuthResult -Result (Invoke-MockAuthRaw -Endpoint "/api-key/test" -Headers $headers) -ExpectedStatus 200
}

function Test-Simulation-TimeoutHeader {
    Write-Host "Simulation Test: x-mock-timeout hangs exactly one request" -ForegroundColor Yellow

    $result = Invoke-MockAuthRaw -Endpoint "/protected" -TimeoutSec 10 -Headers @{
        "X-API-Key"      = "test_api_key_12345"
        "x-mock-timeout" = "true"
    }

    if ($result.TimedOut) {
        Write-Host "  PASS - server never responded" -ForegroundColor Green
    } else {
        Write-Host "  FAIL - got HTTP $($result.StatusCode)" -ForegroundColor Red
    }

    Write-Host "Next request without the header (expect a normal response):" -ForegroundColor Cyan
    Show-MockAuthResult -Result (Invoke-MockAuthRaw -Endpoint "/health") -ExpectedStatus 200
}

function Test-Simulation-InvalidConfig {
    Write-Host "Simulation Test: invalid simulation blocks are rejected (expect 400)" -ForegroundColor Yellow

    foreach ($body in @(
        '{"simulation": {"mode": "explode"}}',
        '{"simulation": {"delayMs": 999999}}',
        '{"simulation": {"errorStatus": 200}}',
        '{"simulation": {"applyTo": "not-an-array"}}'
    )) {
        Write-Host "  POST /config $body" -ForegroundColor DarkGray
        Show-MockAuthResult -Result (Invoke-MockAuthRaw -Method "POST" -Endpoint "/config" -Body $body) -ExpectedStatus 400
    }
}

function Run-AllSimulationTests {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "Running all failure simulation tests..." -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Test-Simulation-InvalidConfig
    Test-Simulation-ForcedError
    Test-Simulation-ScopedError
    Test-Simulation-Delay
    Test-Simulation-Timeout
    Test-Simulation-DelayOverride
    Test-Simulation-StatusOverride
    Test-Simulation-TimeoutHeader
    Reset-Simulation
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
    Test-OAuth1-InvalidConsumerSecret
    Test-OAuth1-StrictSignatureOff
    Test-OAuth1-ExpiredTimestamp
    Test-OAuth1-FullFlow
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
    Test-OAuth2-InvalidClientId-Basic
    Test-OAuth2-InvalidClientSecret-Basic
    Test-OAuth2-InvalidClientId-Post
    Test-OAuth2-InvalidClientSecret-Post
    Test-OAuth2-Strict-InvalidClientId
    Test-OAuth2-Strict-InvalidClientSecret
    Test-OAuth2-Strict-InvalidClientSecret-Post
    Test-OAuth2-Introspect
}

function Run-AllTests {
    Test-Health
    Get-CurrentConfig
    Run-AllApiKeyTests
    Run-AllBasicAuthTests
    Run-AllOAuth1Tests
    Run-AllOAuth2Tests
    Run-AllSimulationTests
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
Write-Host ""
Write-Host "  OAuth1 (signatures are computed for real, HMAC-SHA1):" -ForegroundColor Yellow
Write-Host "    Test-OAuth1-RequestToken, Test-OAuth1-ValidSignature, Test-OAuth1-FullFlow" -ForegroundColor White
Write-Host "    Test-OAuth1-InvalidConsumer        -> 401 'Invalid consumer key'" -ForegroundColor White
Write-Host "    Test-OAuth1-InvalidConsumerSecret  -> 401 'Invalid Consumer Secret'" -ForegroundColor White
Write-Host "    Test-OAuth1-StrictSignatureOff     -> legacy behaviour via strictSignature:false" -ForegroundColor White
Write-Host ""
Write-Host "  OAuth2:" -ForegroundColor Yellow
Write-Host "    Test-OAuth2-ClientCredentials-Basic, Test-OAuth2-AuthCode" -ForegroundColor White
Write-Host "    Test-OAuth2-InvalidClientId-Basic     -> 401 'Invalid Client ID'" -ForegroundColor White
Write-Host "    Test-OAuth2-InvalidClientSecret-Basic -> 401 'Invalid Client Secret'" -ForegroundColor White
Write-Host "    Test-OAuth2-InvalidClientId-Post, Test-OAuth2-InvalidClientSecret-Post" -ForegroundColor White
Write-Host "    Test-OAuth2-Strict-InvalidClientId, Test-OAuth2-Strict-InvalidClientSecret" -ForegroundColor White
Write-Host ""
Write-Host "  Failure simulation:" -ForegroundColor Yellow
Write-Host "    Get-SimulationConfig, Set-Simulation '<json>', Reset-Simulation" -ForegroundColor White
Write-Host "    Test-Simulation-ForcedError, Test-Simulation-ScopedError" -ForegroundColor White
Write-Host "    Test-Simulation-Delay, Test-Simulation-Timeout" -ForegroundColor White
Write-Host "    Test-Simulation-DelayOverride    -> ?_delay=5000" -ForegroundColor White
Write-Host "    Test-Simulation-StatusOverride   -> ?_status=502" -ForegroundColor White
Write-Host "    Test-Simulation-TimeoutHeader    -> x-mock-timeout: true" -ForegroundColor White
Write-Host "    Test-Simulation-InvalidConfig, Run-AllSimulationTests" -ForegroundColor White
Write-Host ""
Write-Host "  Run-AllTests" -ForegroundColor White
Write-Host ""
Write-Host "Example: Run-AllTests" -ForegroundColor Green

