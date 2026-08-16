# Entra-PowerShell-Audit-Scripts

## Summary

These Microsoft Graph PowerShell scripts were made with AI-assistance and personally tested, customized, and reviewed by me. The base script, **Get-EntraAuthenticationBaseline**,  was taken from Microsoft's official [Entra SMS Voice Usage Analyzer](https://github.com/microsoft/entra-sms-voice-usage-analyzer). I expanded this script to, while still focusing on making sure SMS/Voice is disabled, also include whether "Security Defaults" or "Conditional Access" is enabled and also enumerate the names of any active Conditional Access policies.. This script was used to greatly reduce the time it took to audit 20+ Microsoft tenants in an MSP environment. The second script, **Get-CAPScope**, was created after I manually reviewed one client after the initial audit and realized that their Conditional Access Policy named "MFA for All Users" did not actually target all users, but instead a singular user. The script enumerates included groups and excluded users for each Conditional Access policy.

### Disclaimer

No tenant data is collected or transmitted outside Microsoft Graph. CSV Output is written locally.
