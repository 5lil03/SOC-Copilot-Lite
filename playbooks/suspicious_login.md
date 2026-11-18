# Suspicious Login Investigation

## Purpose
Investigate successful logins that look unusual, such as a login outside normal hours or from a source IP address never seen before for that user.

## Typical indicators
- Successful login at an unusual time for the user.
- Login from a new or unfamiliar source IP address or network.
- Login to a privileged or sensitive account such as an administrator or finance account.
- VPN or remote access login that differs from the normal pattern of the user.

## Investigation steps
1. Identify the account, the source IP address and the time of the login, and check the source against the IOC database.
2. Compare with the login history of the user: usual hours, devices and source addresses.
3. Contact the user or the manager of the user to confirm whether the login was legitimate.
4. Review what the account did after the login: systems accessed, files opened, privilege changes.
5. Check whether the same source IP address appears in other alerts.

## Recommended actions (require analyst approval)
- Recommend confirming with the user through a trusted channel, not through the suspicious session.
- Recommend a password reset and multi-factor authentication if the login is not confirmed.
- Recommend reviewing the active sessions of the account and ending them if needed.
- Mark the incident as investigated once the user has confirmed or denied the login.

## Escalation
Escalate to the account compromise response if the user denies the login or if suspicious actions follow.