# SSH Brute Force and Repeated Authentication Failures Response

## Purpose
Investigate and respond to alerts showing many failed SSH logins, or repeated failed logons for the same account, coming from one source.

## Typical indicators
- Many "Failed password" messages in the sshd logs within a short time.
- Many failed logons from the same source IP address against one or several user accounts.
- Attempts against common account names such as root, admin or invalid users.
- A high firedtimes counter on the authentication failure rule.

## Investigation steps
1. Identify the source IP address and check it against the threat intelligence (IOC) database.
2. Count the failed attempts and list the targeted user accounts and the time window.
3. Check whether a login from the same source succeeded after the failures. If yes, follow the account compromise playbook.
4. Check whether the source is an internal host, a known scanner, or a legitimate user who forgot a password.
5. Review whether SSH is exposed to the internet and whether password authentication is enabled.

## Recommended actions (require analyst approval)
- Recommend blocking the source IP address at the firewall after analyst validation.
- Recommend rate limiting or a temporary lockout for the targeted accounts.
- Recommend key-based authentication and disabling password logins for SSH.
- Mark the incident as investigated once the source and the targeted accounts are reviewed.

## Escalation
Escalate if a successful login follows the failures, if privileged accounts are targeted, or if several hosts are attacked from the same source.