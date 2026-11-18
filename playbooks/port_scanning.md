# Port Scanning Investigation

## Purpose
Investigate alerts showing one source probing many distinct ports or hosts in a short time. Port scanning is usually reconnaissance that comes before an attack.

## Typical indicators
- Connection attempts to many distinct destination ports within seconds or minutes.
- Many connections rejected or dropped by the firewall from the same source IP address.
- Probing of several hosts or services in sequence.

## Investigation steps
1. Identify the scanning source IP address and check it against the IOC database.
2. Determine whether the source is external or an internal host. An internal scanner may be an authorized security tool or a compromised machine.
3. List the targeted hosts and ports, and check which ports are open and which services answered.
4. Look for follow-up activity from the same source, such as login attempts against the services that were found.
5. Check whether a vulnerability scan was scheduled by the security team.

## Recommended actions (require analyst approval)
- Recommend blocking or rate limiting the source IP address after analyst validation.
- Recommend closing or restricting unnecessary open ports and exposed services.
- Recommend monitoring the targeted hosts for follow-up login attempts.
- Mark the incident as investigated once the scan scope and the exposed services are reviewed.

## Escalation
Escalate if the scan comes from an internal host, if it is followed by login attempts, or if critical servers are targeted.