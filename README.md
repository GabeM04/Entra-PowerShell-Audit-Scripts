# Entra-PowerShell-Audit-Scripts

## Summary

These Microsoft Graph PowerShell scripts were made with AI-assistance and personally tested, customized, and reviewed by me.

The base script, **Get-EntraAuthenticationBaseline**,  was taken from Microsoft's official [Entra SMS Voice Usage Analyzer](https://github.com/microsoft/entra-sms-voice-usage-analyzer). I expanded this script to, while still focusing on making sure SMS/Voice is disabled, also include additional tenant checks such as whether "Security Defaults" or "Conditional Access" is enabled and also enumerate the names of any active Conditional Access policies.

The second script, **Get-CAPScope**, was created after I manually reviewed one tenant after the initial audit and realized that their Conditional Access Policy named "MFA for All Users" did not actually target all users, but instead a singular user. The script enumerates included users/groups for each Conditional Access policy and also ensures either "Require Multifactor Authentication" or "Require Authentication Strength". If the latter is enabled, it will display the name of the "Authentication Strength" being used. Finally, it also does a quick check of whether exclusions are present in a Conditional Access policy, but does not enumerate the users. This is because the script was primarily focused on quickly gathering data for multiple tenants, which would then be analyzed deeper in the future.

These scripts helped greatly reduce the time required to audit the Entra security baseline for 20+ Microsoft tenants.

### Disclaimer

No tenant data is collected or transmitted outside Microsoft Graph. CSV Output is written locally.
