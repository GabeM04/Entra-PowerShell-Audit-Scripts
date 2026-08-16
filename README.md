# Entra-PowerShell-Audit-Scripts

## Summary

These Microsoft Graph PowerShell scripts were made with AI-assistance and personally tested, customized, and reviewed by me.

The base script, **Get-EntraAuthenticationBaseline**,  was taken from Microsoft's official [Entra SMS Voice Usage Analyzer](https://github.com/microsoft/entra-sms-voice-usage-analyzer). I expanded this script to, while still focusing on making sure SMS/Voice is disabled, also include additional tenant checks such as whether "Security Defaults" or "Conditional Access" is enabled and also enumerate the names of any active Conditional Access policies.

The second script, **Get-CAPScope**, was created after I manually reviewed one tenant after the initial audit and realized that their Conditional Access Policy named "MFA for All Users" did not actually target all users, but instead a singular user. The script enumerates included/excluded users/groups for each Conditional Access policy and also reports whether the policy uses "Require Multifactor Authentication" or "Require Authentication Strength". If the latter is enabled, it will display the name of the "Authentication Strength" being used.

These scripts helped greatly reduce the time required to audit the Entra security baseline for 20+ Microsoft tenants.

### Disclaimer

No tenant data is collected or transmitted outside Microsoft Graph. CSV Output is written locally.
