# Discourse Account Security Plugin

Provider-neutral account-security intelligence for Discourse.

## Why the general name?

The initial implementation uses IP reputation as one signal, but the namespace, setting prefix and admin area deliberately use **Account Security** rather than a provider or IP-specific product name. This leaves room for future modules such as duplicate-account correlation, shared-network analysis, registration-pattern detection and other account-integrity signals without renaming the plugin.

## Version 0.1.0 - substantial first iteration

This is a substantial first implementation, not the final implementation of every feature in the design specification. It includes:

- a conservative master switch plus an independent IP-reputation module switch;
- a provider-neutral account-security namespace and extensible data model;
- strict public IPv4/IPv6 parsing, reserved/private-range exclusion and IPv6 /64 familiarity by default;
- registration and successful-login lifecycle integration using Discourse lifecycle data rather than raw proxy headers;
- a global IP intelligence cache with risk-dependent refresh TTLs;
- an AbuseIPDB API v2 CHECK adapter with fixed HTTPS endpoint, server-side secret, no verbose reports, bounded responses, short timeouts and no redirects;
- provider quota tracking, protected local daily reserves and a concurrency-safe circuit breaker;
- per-IP lookup deduplication that consumes a local quota slot only when a provider CHECK is actually made;
- local AbuseIPDB high-confidence blacklist synchronization (four times per day when enabled);
- local official Tor exit-list synchronization (hourly when enabled); Tor is context only and never increases risk by itself;
- Risk Events review, IP Intelligence, Trusted Networks, Health and aggregate Statistics administration pages;
- Installed Plugins settings-button compatibility using the stable `account_security` settings filter, based on the proven pattern in the supplied example plugins;
- an AbuseIPDB REPORT adapter and local audit model as a **guarded future capability**, with `account_security_abuse_reporting_enabled` defaulting to **false**;
- outbound reporting restricted in server code to a persisted `auth_failure_cluster` event that is High/Critical, Corroborated and explicitly marked `local_abuse_confirmed=true` plus `threshold_exceeded=true`;
- privacy-safe admin responses (`Cache-Control: no-store`) and provider credentials kept server-side.

Version 0.1.0 deliberately does **not** generate `auth_failure_cluster` events yet. Therefore normal v0.1 operation cannot submit an AbuseIPDB abuse report even if the reporting setting is enabled. This is intentional: the provider reporting path exists for a later locally corroborated failed-authentication module, but arbitrary IPs, high reputation scores, VPN/Tor use and community-rule violations cannot be reported through the current admin UI.

## Deliberately not in 0.1.0

The first iteration does **not** add automatic account/IP blocking, active failed-authentication cluster detection, User Notes, moderator notifications, IPinfo/IPQS enrichment, provider CIDR lookups or duplicate-account scoring. Those functions are safer to add after the observation-mode foundation has been exercised on the target Discourse build.

## Installation

Add the repository to the normal Discourse plugin installation flow and rebuild the app. The plugin installs with the master switch disabled. After the rebuild:

1. Open **Admin > Plugins > Account Security**.
2. Open **Settings**.
3. Add the AbuseIPDB API key if the external provider will be used.
4. Confirm that the site is entitled to use that API key/plan by enabling the terms acknowledgement.
5. Review **Health** and run the guarded provider test.
6. Enable `account_security_enabled` only after configuration is correct.
7. Keep provider reporting disabled unless a future locally corroborated abuse-event workflow is intentionally deployed.

## Privacy and security notes

- Only the literal public IP address is sent to AbuseIPDB for CHECK requests.
- Username, email, posts, private messages and chat content are never sent by the IP reputation module.
- Verbose AbuseIPDB report payloads are not requested.
- Admin-entered IP/network parameters are filtered from Rails parameter logging.
- Normal browsing, posting, PM and chat activity do not trigger provider lookups.
- Provider failures fail open: the plugin can lose enrichment without blocking normal authentication.
- The plugin never treats VPN, Tor, hosting or shared-network use as proof of abuse.
- External feed/provider calls stop when either the Account Security master switch or the IP-reputation module is disabled.
- Discourse user deletion removes compact user-network familiarity data and detaches deleted users from retained risk events; IP-anonymization removes the user-network familiarity records as well.

## Suggested repository name

`Discourse-Account-Security-Plugin`
