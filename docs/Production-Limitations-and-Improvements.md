# Production Limitations and Improvements

## Purpose

This document separates the validated Project 2 laboratory from a production
identity threat detection and response capability. The laboratory proves the
engineering method; it does not reproduce enterprise identity scale,
availability, governance or response authority.

The gaps are explicit so that laboratory evidence is not presented as a
production operational deployment.

## Current laboratory scope

| Area | Current implementation |
|---|---|
| Identity platform | One VMware-hosted `corporate.test` domain controller |
| Controlled identities | Five disposable users in `IDTR-Lab` |
| High-value marker | One synthetic group with no real administrative privilege |
| Collection | Azure Monitor Agent with two validated Data Collection Rules |
| Analytics | One Log Analytics workspace and Microsoft Sentinel instance |
| Completed detections | IDTR001 password spraying; IDTR002 successful authentication after failures; IDTR003 high-value group change; IDTR004 integrated identity attack chain |
| Response | Assigned incident, task-based investigation, idempotent containment, recovery validation and closure |
| Recovery | Scripted cleanup plus final powered-off VMware checkpoint `P2-M08-Final-Validated-State` |

## Architecture limitations

### Single domain controller

The laboratory does not represent multiple domain controllers, sites, network
segments, read-only domain controllers or cloud-only authentication paths.

Production improvement:

- Collect from all relevant domain controllers and authentication authorities.
- Test replication, failover and event consistency across sites.
- Include Entra sign-in, endpoint and identity-risk telemetry where approved.
- Design workspace and collection topology for regional and organisational
  boundaries.

### One workspace and region

The current design does not test multi-workspace access, regional residency,
cross-tenant operations or disaster recovery.

Production improvement:

- Choose workspace architecture according to tenancy, geography, ownership,
  retention and investigation needs.
- Define recovery procedures for connector, workspace and rule failures.
- Monitor ingestion and query availability against service objectives.

## Telemetry limitations

### Authentication-path coverage

Controlled Windows methods do not reproduce every protocol, endpoint, remote
source, application or adversary tool. The first IDTR002 LDAP method produced a
successful Event `4624` but not the required Event `4625` failures. The
validated Windows `LogonUser` network-logon method produced the correct five
failures and one success, but did not provide a reliable remote source address.

Production improvement:

- Validate Kerberos, NTLM, Remote Desktop, SMB, VPN, application and cloud
  authentication paths relevant to the organisation.
- Record which source and workstation fields are reliable for each path.
- Add normalisation only after field-level validation.

### Small and predictable volume

Five accounts and one host cannot reproduce enterprise seasonality, service
accounts, scanners, lockouts, help-desk activity or background noise.

Production improvement:

- Derive thresholds from historical baselines and known business processes.
- Segment human, service, privileged, emergency and non-interactive identities.
- Tune by source concentration, identity criticality, time, geography and later
  successful activity.

### Limited enrichment

The current project does not include endpoint detection and response, Entra
Identity Protection, threat intelligence, asset criticality or vulnerability
context.

Production improvement:

- Correlate identity activity with endpoint, device, network and risk data.
- Enrich accounts and hosts with ownership and criticality.
- Preserve raw evidence when enrichment is absent or delayed.

## Detection-engineering limitations

### Fixed laboratory thresholds

IDTR001 uses five failures against five identities. IDTR002 uses five failures
for one identity before a success within 30 minutes. IDTR004 requires the
five-identity spray threshold, a later successful account and a matching group
addition. Its current KQL correlates the failure aggregate by host and does not
enforce a separate failure threshold for the successful account. The final test
did record five failures for that account, but this was observed evidence rather
than an additional query condition. These values create controlled, repeatable
results; none is a universal production recommendation.

Production improvement:

- Test thresholds against representative historical data.
- Measure alert volume, precision and missed-behaviour risk.
- Decide whether IDTR004 must require the successful account to appear in the
  failed-identity set and enforce that condition explicitly if required.
- Use watchlists or governed attributes for approved exclusions.
- Apply stricter handling to privileged and high-value identities.

### Ingestion-delay assumptions

The IDTR001 and IDTR002 freshness guards were based on measured laboratory
behaviour. Milestone 5 demonstrated that a five-minute-only freshness guard can
exclude every result because Sentinel evaluates scheduled rules with a built-in
five-minute delay. IDTR003 therefore uses a non-overlapping 5-to-10-minute
ingestion-age window with its five-minute frequency.

IDTR004 uses a different anchor model: failures and success remain available
inside a 75-minute event-time horizon, while only the chain-completing group
addition is limited to `ingestion_time() > ago(5m)`. The query must also return
`TimeGenerated`; historical correlation success alone does not prove that a
scheduled rule can create an alert.

Production improvement:

- Measure latency across sources and periods.
- Monitor late-arriving and dropped records.
- Revalidate guard logic after collection or schedule changes.
- Include rule-health tests in deployment pipelines.
- Enable `SentinelHealth` collection for scheduled-rule execution evidence.
- Validate local deployment payloads and persistent readback before accepting a
  success message.

### Parent ATT&CK technique in the deployed model

The current Microsoft Sentinel rule accepted `T1110`, while the project
documents the more precise `T1110.003` password-spraying behaviour.

Production improvement:

- Track platform-schema changes.
- Validate deployment payloads in a non-production workspace.
- Preserve precise sub-technique documentation when the deployment model is
  less specific.

## Entity and incident limitations

### Variable source-IP availability

No IP entity was mapped in the validated Milestone 3 incident because the raw
source value contained `-`. The Milestone 4 local network authentication also
did not provide a reliable remote source address, so IDTR002 mapped only the
validated Account and Host entities.

Production improvement:

- Map only syntactically and operationally usable source addresses.
- Enrich valid IP addresses with approved network and threat context.
- Treat missing source information as an investigation limitation rather than
  replacing it with a guessed value.

### Limited grouping models

IDTR001 uses `AllEntities` incident grouping with a 5-hour lookback. IDTR002
uses `Selected` entity grouping with the same lookback and produces one alert
per result. IDTR003 uses `AllEntities` to group its separate addition and
removal alerts into one incident. IDTR004 uses `AllEntities` for the successful
target, actor, host and group. Its final alert joined an existing three-alert
incident because separate authorised executions shared those entities. The
small laboratory does not test high-volume entity collisions, concurrent
campaigns or unrelated changes sharing the same identity graph.

Production improvement:

- Evaluate grouping against realistic identity and host volume.
- Confirm whether separate sources or campaigns remain distinguishable.
- Monitor reopened, merged and long-running incidents for analyst usability.

## Response limitations

### Laboratory containment and closure

Milestone 7 validates incident ownership, three tracked response tasks,
idempotent Active Directory containment, local and cloud recovery evidence, an
analyst record and closure. It intentionally avoids automated destructive
action. The target was already disabled, unlocked and absent from the synthetic
group, so the validated containment applied zero changes.

This does not test password reset, Kerberos-ticket or cloud-session revocation,
endpoint isolation, enterprise group review, user coordination or business
service recovery. A fresh Event `4688` proves that the tested collection path
remained healthy; it does not prove recovery of every dependent service.

Production improvement:

- Define approved response authority and separation of duties.
- Automate low-risk enrichment and evidence gathering.
- Require human approval for account disablement, credential reset, session
  revocation or privilege removal unless an approved emergency process applies.
- Integrate ticketing, case ownership and escalation contacts.

### Synthetic high-value group

`IDTR-HighValue-Lab` grants no privilege and cannot reproduce the business
impact of a real administrative group.

Production improvement:

- Maintain a governed inventory of privileged groups and roles.
- Prefer stable identifiers over display names where possible.
- Connect group monitoring to identity governance, privileged access and access
  review processes.

## Governance and access limitations

The laboratory does not implement enterprise role separation, approval chains,
Privileged Identity Management or detection change governance.

Production improvement:

- Apply least-privilege Azure role-based access control.
- Use separate named administrative identities and emergency-access controls.
- Protect detection and response changes through peer review and change records.
- Record ownership, review cadence and retirement criteria for every rule.

## Testing and deployment limitations

Current rule configuration was validated through supported management
interfaces because the preferred graphical experience repeatedly redirected.
The repository stores the reusable KQL but does not yet implement a full
detection-as-code pipeline.

Production improvement:

- Store complete rule definitions in version control.
- Add syntax, schema, threshold and known-event tests.
- Deploy through reviewed pipelines with environment-specific parameters.
- Retain prior rule versions and a tested rollback procedure.
- Validate persisted rule state after deployment.

### Incident interface and API disagreement

During Milestone 4, the Defender incident interface showed zero active
incidents while the supported, paginated incident API returned Incident `6`.
The alert, entities, comment and closure were therefore validated through
official management endpoints. The same visibility symptom recurred during
Milestone 7: the interface showed zero results while the API returned fresh
Incident `14` and its attached alert.

Production improvement:

- Monitor interface and API visibility as separate operational dependencies.
- Preserve read-only API procedures for incident inventory validation.
- Escalate persistent interface discrepancies through the supported service
  channel rather than assuming that an unseen incident does not exist.
- Use retrieved persistent state as evidence for automated workflows.

### Analytics interface and health-state visibility

During Milestone 6, the graphical analytics experience did not provide a
reliable path to rule configuration or execution state. Supported management
endpoints were used for persistent rule readback, and the SentinelHealth
`Analytics` diagnostic category was enabled in the existing workspace.

Production improvement:

- Treat portal availability, resource configuration and rule execution health
  as separate dependencies.
- Monitor `SentinelHealth` for failed, delayed and unexpectedly empty runs.
- Alert the detection-engineering owner when a critical rule stops executing.
- Retain a reviewed management-interface fallback for controlled recovery.

## Cost and retention limitations

Laboratory volume is small and does not model production ingestion, archive,
hunting, restoration or long-term retention costs.

Production improvement:

- Estimate data volume by source and event type.
- Filter unnecessary collection at the Data Collection Rule where appropriate.
- Select log plans and retention according to investigation and regulatory
  requirements.
- Configure budgets, alerts and regular cost review.
- Test archive search and restoration before relying on long-term evidence.

## Prioritised production roadmap

| Priority | Improvement | Reason |
|---:|---|---|
| 1 | Expand identity and authentication-path coverage | Prevent blind spots before adding automation |
| 2 | Establish rule ownership, peer review and versioned deployment | Control detection changes and rollback |
| 3 | Baseline thresholds using representative data | Reduce both missed attacks and analyst noise |
| 4 | Add health monitoring for agents, DCRs, ingestion and rule runs | Detect monitoring failure independently of security incidents |
| 5 | Add identity, endpoint and risk enrichment | Improve prioritisation and scope determination |
| 6 | Introduce approved response automation | Reduce analyst effort without uncontrolled disruption |
| 7 | Validate multi-region, retention and recovery design | Support operational and regulatory requirements |

## Current conclusion

Through Milestone 8, the Project 2 laboratory is credible evidence of
detection-engineering method, cross-event authentication correlation, schema
validation, privileged-group monitoring, integrated attack-chain correlation,
safe testing, incident reasoning, verified response and controlled recovery. It
is not evidence of production scale or authority. The production improvements
in this document are required before the design could be considered an
enterprise identity monitoring capability.

The technical laboratory and final repository review are complete. Future
changes must be treated as a new, separately validated revision rather than an
unrecorded extension of the completed evidence.

## References

- [Microsoft Sentinel best practices](https://learn.microsoft.com/en-us/azure/sentinel/best-practices)
- [Microsoft Sentinel workspace architecture best practices](https://learn.microsoft.com/en-us/azure/sentinel/best-practices-workspace-architecture)
- [Handle ingestion delay in scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay)
- [Azure Monitor Logs cost calculations and options](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/cost-logs)
- [Azure Monitor Agent overview](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-overview)
- [Data Collection Rules overview](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-rule-overview)
- [Microsoft Sentinel scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview)
- [Monitor analytics-rule health and integrity](https://learn.microsoft.com/en-us/azure/sentinel/monitor-analytics-rule-integrity)
- [Turn on Microsoft Sentinel auditing and health monitoring](https://learn.microsoft.com/en-us/azure/sentinel/enable-monitoring)
- [Microsoft Windows Event 4624 — An account was successfully logged on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft Windows Event 4625 — An account failed to log on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [Microsoft Audit Security Group Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)
- [MITRE ATT&CK T1098.007 — Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/)
