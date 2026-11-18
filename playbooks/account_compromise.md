# Account Compromise Response

## Purpose
Respond to alerts suggesting that an attacker gained access to a valid account, for example a successful login after many failed attempts from the same source.

## Typical indicators
- Successful login shortly after a series of failed attempts from the same source IP address.
- A login that the real user did not make.
- New activity from the account: unusual commands, new accounts, changed permissions, new scheduled tasks or access to unusual data.
- Connections from the affected host to unfamiliar external addresses.

## Investigation steps
1. Establish the timeline: first failed attempt, first successful login, last known activity.
2. Identify the compromised account, the host and the source IP address, and check the source against the IOC database.
3. Review the commands run and the files accessed during the session.
4. Look for persistence: new user accounts, new keys, scheduled tasks, changed configuration.
5. Check whether the same credentials were used on other systems.

## Recommended actions (require analyst approval)
- Recommend disabling or locking the compromised account and ending its active sessions.
- Recommend resetting the credentials and any related keys or tokens.
- Recommend isolating the affected host from the network while the investigation continues.
- Recommend blocking the source IP address after analyst validation.
- Escalate the incident to the incident response lead.

## Escalation
Treat this as a confirmed incident until proven otherwise: escalate immediately and preserve the logs as evidence.