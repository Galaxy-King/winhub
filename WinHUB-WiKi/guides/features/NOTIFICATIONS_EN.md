# WinHUB notifications

The bell is available in signed-in desktop and mobile screens. Its red counter shows unread notifications. Open it to filter the history, mark notifications read, clear your own history or follow an event to its current details. Clearing notifications does not delete tasks, audit entries or approval requests. Read state is shared across your devices. The inbox shows the latest 500 accessible notifications from the last 90 days; older entries are removed automatically.

Green means success, red means failure, amber means review/warning and blue means information. Multi-host tasks produce one completion summary. Delivery failure, script failure and unknown execution results remain distinct. A completed Fleet rollout means wave scheduling has finished; it does not certify that every agent installed the update. This is an informational notification. An approval handled by another administrator is marked `Resolved`.

## Events and access

Active superadmins receive pending host, identity conflict, template and software recipe reviews. Initiators receive their task and software results, scheduler outcomes, installer preparation results, report/AI/report-delivery results, agent rollout results and Newsletter completion. System audit entries in the `System` module with `Error` or `Critical` status notify superadmins. Each event remains subject to the current module and target-group permissions. Notification preferences never grant access.

Push messages contain only a generic WinHUB notice. Hostnames, addresses, parameters, results and secrets are not placed on a lock screen. Opening details, sending a push and approving a change each recheck permissions.

## Install on your phone

1. Update the server through the supported updater, including Python requirements and migration `20261118_01`. No agent update is required.
2. Open a stable HTTPS URL trusted by your phone's browser.
3. On iPhone/iPad (iOS/iPadOS 16.4+), add WinHUB to the Home Screen and launch that icon. On Android, use your browser's Install app / Add to Home screen command.
4. Sign in. On a private device, select `Remember this device for 30 days` if desired. The configured server absolute session timeout still applies; ordinary sessions retain the existing idle timeout.
5. Open the bell → `Notification settings & devices` → `Enable push on this device`, then allow browser/OS notifications.
6. Run a small test task, verify delivery with the app open, then repeat with it closed.

Web Push needs outbound HTTPS to the browser provider (`fcm.googleapis.com`, Apple `*.push.apple.com`, Mozilla `push.services.mozilla.com` and its subdomains, or `*.notify.windows.com`). Add the relevant provider to an enforced `OUTBOUND_ALLOWED_HOSTS` policy. TLS verification, public-address validation and redirect blocking remain enabled.

The server creates its VAPID identity once and stores it encrypted in the database. No manual key distribution is required. This is independent of agent release-signing keys. Preserve the database and encryption key in regular backups; do not rotate VAPID keys on routine updates.

Different URLs/ports are different browser origins and need separate subscriptions. Prefer one stable address. The phone still needs network/VPN access to WinHUB to open event details. Push delivery is best effort; the durable inbox is the source of history. Push retries are bounded to five, expired subscriptions are disabled and events older than one day are not pushed.

## Preferences and devices

Choose popup visibility, push categories, errors/reviews only and quiet hours (UTC). Manage up to ten active push devices and revoke remembered sessions from the same drawer. Explicit logout disables the current push subscription and remembered session. A normal idle expiry retains the generic push subscription but requires sign-in for details. Password/2FA changes and account deactivation invalidate remembered sessions.

Background notification polls do not refresh the user's idle timer. The service worker does not cache authenticated content and never queues offline approvals.

## Review from mobile

Notification details show the current host or executable recipe. Superadmins can approve ordinary pending hosts, templates and software recipes after reviewing them. A revision mismatch requires refreshing and reviewing again. Existing software preparation and AI validation checks still apply.

Identity conflicts open the existing Review tools rather than receiving an ordinary host approval. Workspace links from notifications retain their intended section instead of returning to the mobile landing screen.

Production acceptance should cover successful/failed/group tasks, another user's access, permission revocation, concurrent approval, closed-app push and logout on real devices. Automated browser and cryptographic tests do not certify production Nginx, TLS, Apple/Google/Mozilla delivery or phone permissions.

[Український посібник](NOTIFICATIONS_UA.md)
