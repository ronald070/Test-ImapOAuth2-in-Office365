<#
.SYNOPSIS
  Tests Exchange Online IMAP OAuth2 authentication (XOAUTH2) using your App Registration.

.DESCRIPTION
  - Supports two auth modes:
      1) Client Credentials (app-only) -> requires IMAP app permission + EXO service principal + mailbox permission.
      2) Device Code (delegated user)  -> requires delegated scope IMAP.AccessAsUser.All consented.
  - Connects to outlook.office365.com:993 via TLS and sends AUTHENTICATE XOAUTH2.
  - Prints "SUCCESS" if the server returns "OK AUTHENTICATE completed".

.REFERENCES
  Microsoft Learn - Authenticate IMAP/POP/SMTP with OAuth (scopes, XOAUTH2, endpoints):
  https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
  (Use of v2.0 token endpoints and IMAP scopes)  # [1](https://dev.to/itcs11/start-using-oauth-for-office-365-popimap-authentication-3e2h)

  Microsoft 365 Connectivity Analyzer (IMAP OAuth test):
  https://testconnectivity.microsoft.com/tests/O365Imap/input  # [2](https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0816072)
#>

param(
  # === Common parameters ===
  [Parameter(Mandatory=$true)]
  [ValidateSet('ClientCredentials','DeviceCode')]
  [string]$AuthMode,

  [Parameter(Mandatory=$true)]
  [string]$TenantId,             # e.g. 11111111-2222-3333-4444-555555555555 or contoso.onmicrosoft.com

  [Parameter(Mandatory=$true)]
  [string]$ClientId,             # Application (client) ID of your App Registration

  # Mailbox UPN to test against (the mailbox you expect to access via IMAP)
  [Parameter(Mandatory=$true)]
  [string]$MailboxUpn,           # e.g. imap@dev.dijkstra.nl

  # === Client Credentials only ===
  [Parameter(Mandatory=$false)]
  [string]$ClientSecret,         # Required if AuthMode=ClientCredentials

  # === Optional ===
  [string]$ImapHost = 'outlook.office365.com',
  [int]$ImapPort = 993,
  [switch]$VerboseOutput
)

# -------------------- Helper: Write-Log --------------------
function Write-Log {
  param([string]$Message, [ConsoleColor]$Color = 'Gray')
  $orig = $Host.UI.RawUI.ForegroundColor
  $Host.UI.RawUI.ForegroundColor = $Color
  Write-Host $Message
  $Host.UI.RawUI.ForegroundColor = $orig
}

# -------------------- Acquire Token (Client Credentials) --------------------
function Get-AccessTokenClientCredentials {
  param(
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret
  )
  # Token endpoint per Microsoft identity platform v2.0  # [1](https://dev.to/itcs11/start-using-oauth-for-office-365-popimap-authentication-3e2h)
  $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

  # For app-only you typically use the ".default" resource for app permissions.
  # IMAP app permission must be granted in Exchange Online enterprise app.
  # We'll request a token for Outlook resource using .default.  # [1](https://dev.to/itcs11/start-using-oauth-for-office-365-popimap-authentication-3e2h)
  $body = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://outlook.office.com/.default"
    grant_type    = "client_credentials"
  }

  try {
    $resp = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType "application/x-www-form-urlencoded"
    return $resp.access_token
  }
  catch {
    throw "Failed to get token (client credentials): $($_.Exception.Message)"
  }
}

# -------------------- Acquire Token (Device Code) --------------------
function Get-AccessTokenDeviceCode {
  param(
    [string]$TenantId,
    [string]$ClientId
  )
  # Device code flow endpoints and required delegated IMAP scope  # [1](https://dev.to/itcs11/start-using-oauth-for-office-365-popimap-authentication-3e2h)
  $deviceCodeEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
  $tokenEndpoint      = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

  # Delegated scope for IMAP:
  $scope = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"

  try {
    $dcResp = Invoke-RestMethod -Method Post -Uri $deviceCodeEndpoint `
              -Body @{ client_id=$ClientId; scope=$scope } -ContentType "application/x-www-form-urlencoded"

    Write-Log "To sign in, open $($dcResp.verification_uri) and enter code: $($dcResp.user_code)" Cyan
    Write-Log "Waiting for you to complete sign-in..." Yellow

    $pollBody = @{
      grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
      client_id  = $ClientId
      device_code= $dcResp.device_code
    }

    while ($true) {
      Start-Sleep -Seconds $dcResp.interval
      try {
        $tokenResp = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $pollBody `
                      -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        return $tokenResp.access_token
      } catch {
        $errText = $_.ErrorDetails.Message
        if ($errText -match 'authorization_pending' -or $errText -match 'slow_down') {
          continue
        } else {
          throw "Device code token error: $($errText)"
        }
      }
    }
  }
  catch {
    throw "Failed to start/complete device code flow: $($_.Exception.Message)"
  }
}

# -------------------- Build XOAUTH2 line --------------------
<# function Build-XOAuth2 {
  param(
    [string]$MailboxUpn,
    [string]$AccessToken
  )
  # SASL XOAUTH2 format per Microsoft documentation  # [1](https://dev.to/itcs11/start-using-oauth-for-office-365-popimap-authentication-3e2h)
  $raw = "user=$MailboxUpn`nauth=Bearer $AccessToken`n`n"
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($raw)
  return [Convert]::ToBase64String($bytes)
} #>

function Build-XOAuth2 {
  param(
    [string]$MailboxUpn,
    [string]$AccessToken
  )
  # Use ASCII 0x01 (control-A) as SASL field separators for XOAUTH2
  $sep = [char]1  # 0x01
  $raw = "user=$MailboxUpn$sep" + "auth=Bearer $AccessToken$sep$sep"
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($raw)
  return [Convert]::ToBase64String($bytes)
}

# -------------------- Test IMAP AUTHENTICATE XOAUTH2 --------------------
function Test-ImapOAuth2 {
  param(
    [string]$ImapHost,
    [int]$ImapPort,
    [string]$Base64Xoauth2,
    [switch]$VerboseOutput
  )

  $tcp = New-Object System.Net.Sockets.TcpClient
  $tcp.Connect($ImapHost, $ImapPort)
  $sslStream = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, ({ $true }))
  $sslStream.AuthenticateAsClient($ImapHost)

  $reader = New-Object System.IO.StreamReader($sslStream)
  $writer = New-Object System.IO.StreamWriter($sslStream)
  $writer.NewLine = "`r`n"
  $writer.AutoFlush = $true

  # Read server greeting
  $greeting = $reader.ReadLine()
  if ($VerboseOutput) { Write-Log "IMAP Greeting: $greeting" DarkGray }

  # Send AUTHENTICATE XOAUTH2
  $writer.WriteLine("a AUTHENTICATE XOAUTH2 $Base64Xoauth2")

  # Read lines until we get tagged response for "a"
  $result = ""
  for ($i=0; $i -lt 20; $i++) {
    $line = $reader.ReadLine()
    if ($null -eq $line) { break }
    if ($VerboseOutput) { Write-Log $line DarkGray }
    $result += $line + "`n"
    if ($line -match '^a\s') { break }
  }

  $sslStream.Dispose()
  $tcp.Close()

  if ($result -match '^a OK') {
    Write-Log "SUCCESS: IMAP XOAUTH2 authentication completed." Green
    return $true
  } else {
    Write-Log "FAILED: IMAP XOAUTH2 authentication was not accepted." Red
    Write-Log "Server response:" Yellow
    Write-Host $result
    return $false
  }
}

# -------------------- Main --------------------
try {
  if ($AuthMode -eq 'ClientCredentials' -and [string]::IsNullOrWhiteSpace($ClientSecret)) {
    throw "ClientSecret is required for ClientCredentials mode."
  }

  Write-Log "Requesting OAuth2 access token ($AuthMode)..." Cyan
  $token = if ($AuthMode -eq 'ClientCredentials') {
    Get-AccessTokenClientCredentials -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
  } else {
    Get-AccessTokenDeviceCode -TenantId $TenantId -ClientId $ClientId
  }

  Write-Log "Building XOAUTH2 string for $MailboxUpn..." Cyan
  $xoauth2 = Build-XOAuth2 -MailboxUpn $MailboxUpn -AccessToken $token

  #Write-Log "Connecting to $ImapHost:$ImapPort and sending AUTHENTICATE XOAUTH2..." Cyan
  Write-Log "Connecting to ${ImapHost}:${ImapPort} and sending AUTHENTICATE XOAUTH2..." Cyan
  $ok = Test-ImapOAuth2 -ImapHost $ImapHost -ImapPort $ImapPort -Base64Xoauth2 $xoauth2 -VerboseOutput:$VerboseOutput

  if (-not $ok) {
    Write-Log "`nTroubleshooting tips:" Yellow
    Write-Host @"
 - If using ClientCredentials:
     • Ensure the app has IMAP app permission (Office 365 Exchange Online: IMAP.AccessAsApp) and admin consent is granted.
     • Ensure you've created the Exchange Online service principal and granted the mailbox FullAccess to the appId.
 - If using DeviceCode:
     • Ensure delegated scope 'IMAP.AccessAsUser.All' is consented and the signed-in user has mailbox access.
 - Token audience/scope must be for Outlook (https://outlook.office.com).
 - Try external validation: https://testconnectivity.microsoft.com/tests/O365Imap/input
"@
  }

} catch {
  Write-Log "ERROR: $($_.Exception.Message)" Red
  exit 1
}
