# Test-ImapOAuth2-in-Office365
Script to test Imap OAuth2 setup in Office 365

## Client Credentials (app‑only)
Requires your app to have IMAP.AccessAsApp (application permission) and an Exchange Online service principal with mailbox access (FullAccess) granted to the AppId.

```powershell
.\Test-ImapOAuth2.ps1 `
  -AuthMode ClientCredentials `
  -TenantId "YOUR_TENANT_ID_OR_NAME" `
  -ClientId "YOUR_APP_CLIENT_ID" `
  -ClientSecret "YOUR_APP_CLIENT_SECRET" `
  -MailboxUpn "imap-user@domain.com" `
  -VerboseOutput
```

## Device Code (delegated user)
Requires delegated permission IMAP.AccessAsUser.All and consent. You’ll be prompted to sign in with a code. 

```powershell
.\Test-ImapOAuth2.ps1 `
  -AuthMode DeviceCode `
  -TenantId "YOUR_TENANT_ID_OR_NAME" `
  -ClientId "YOUR_APP_CLIENT_ID" `
  -MailboxUpn "imap-user@domain.com" `
  -VerboseOutput
```
## Expected Results
* Success: You’ll see SUCCESS: IMAP XOAUTH2 authentication completed. returned by the server as a OK. (This proves token + XOAUTH2 + IMAP are good.)
* Failure: Script prints IMAP server’s error (e.g., invalid scope, no mailbox permission, invalid audience), which helps you pinpoint configuration issues. If in doubt, cross‑check with Microsoft’s Connectivity Analyzer to isolate tenant vs. local issues.

## Reference: 
https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
