# Lessons Learned — Microsoft Identity Threat Detection and Response

## Executive reflection

This project progressed from baseline recovery and identity-telemetry profiling
to four validated Microsoft Sentinel detections, an integrated attack-chain
correlation, a complete investigation and response workflow, and a final
repository-quality review.

The work required more than writing Kusto Query Language (KQL). It included
safe test design, local Windows event validation, hybrid collection
troubleshooting, cloud-schema analysis, scheduled-rule engineering,
ingestion-delay tuning, entity mapping, alert and incident reasoning,
idempotent containment, recovery validation, closure decisions, documentation
and publication controls.

The central lesson is that identity detection depends on the complete chain:

```text
Controlled action → local Windows event → Azure Monitor Agent and DCR
→ Log Analytics record → detection query → alert → incident
→ analyst decision → direct final-state validation → closure
```

A later layer cannot repair an earlier broken link. Each stage must be
validated independently before the next result can be trusted.

## Milestone 1 — baseline and recovery lessons

### Reuse requires revalidation

Project 2 reused the Project 1 `DC01`, Azure Arc connection, Azure Monitor
Agent, Data Collection Rules and Microsoft Sentinel workspace. Reuse reduced
cost and avoided unnecessary reconstruction, but prior success was not treated
as proof of current health.

The baseline was revalidated across:

- Active Directory and domain-controller services.
- Azure Arc connectivity.
- Azure Monitor Agent extension state.
- Data Collection Rule associations.
- Fresh `Heartbeat`, `SecurityEvent` and PowerShell event records.
- Preserved Project 1 analytics rules.

The lesson is that inherited infrastructure still needs a fresh
effective-state checkpoint.

### Recovery checkpoints should not replace logical rollback

A powered-off VMware snapshot was created before Project 2 changes. A final
powered-off checkpoint, `P2-M08-Final-Validated-State`, was created after all
technical and recovery checks passed.

Those checkpoints protect the project from severe failure, but restoring a
complete domain controller is more disruptive than repairing five controlled
users or one synthetic group. The correct recovery order is targeted cleanup,
independent state validation and snapshot restoration only if logical recovery
fails.

### Azure Arc, Azure Monitor Agent and Data Collection Rules are separate

An Azure Arc-connected server can still have stale or missing telemetry:

- Azure Arc provides the resource and management relationship.
- Azure Monitor Agent performs collection.
- Data Collection Rules select sources and destinations.
- Log Analytics proves ingestion through fresh records.

This responsibility boundary prevented an Arc **Connected** status from being
misinterpreted as complete Microsoft Sentinel health.

### Interface failure is not service failure

The Microsoft Sentinel graphical experience repeatedly redirected or showed
an empty result while the workspace, data and resources remained available
through supported management interfaces.

The correct response was to validate the underlying resource, use the
graphical interface where it worked, use an official fallback only where
necessary and retrieve persisted state afterwards. The limitation was
documented rather than hidden.

## Milestone 2 — identity telemetry and safe-testing lessons

### Profile the collected schema before writing a detection

Events `4624`, `4625`, `4728` and `4729` were inspected locally and in
`SecurityEvent` before scheduled-rule engineering began. Similar Windows
events do not populate every field consistently, and a field visible in raw
Extensible Markup Language (XML) may be empty or represented differently after
collection.

The schema profile established which columns could support filtering,
grouping, entity mapping and investigation. This avoided building detections
around assumed fields.

### Source-address population depends on authentication context

The controlled authentication methods did not yield one consistent remote
address:

- Some local failures recorded loopback context.
- The successful network authentication had no populated source address in the
  collected context.
- Password-spray records contained the placeholder `-`.

The lesson is to inspect the raw field for every scenario and map an Internet
Protocol entity only when the value is usable.

### Directory-change events require role-aware interpretation

For Events `4728` and `4729`, the acting account, target group and member are
different objects. The member may appear as a distinguished name rather than a
short account name.

Detection and investigation logic must distinguish the subject performing the
change from the group being changed and the identity being added or removed.

### Test safety must survive operator and execution failure

The Project 2 scripts use disposable identities, preserve original account
state and reverse temporary group membership through guaranteed-cleanup logic.
The final state is checked by a separate validation script.

Safe test design should not depend on the operator remembering a manual cleanup
step after every successful or failed command.

### Events do not prove current state

A removal event proves that a removal was recorded at one point in time. It
does not prove that the group is still empty or that the account remains
disabled.

Project 2 therefore validates the current user and group objects directly.
This is stronger containment evidence than relying on an audit-event sequence
alone.

## Milestone 3 — password-spray detection lessons

### Ingestion delay and overlapping schedules must be designed together

The initial IDTR001 rule used overlapping event-time windows without
restricting records to the latest ingestion interval. Delayed events were
eligible for more than one evaluation and produced repeated alerts.

The corrected design separates two purposes:

- A 15-minute `TimeGenerated` window recovers delayed events.
- A 5-minute `ingestion_time()` guard selects records newly available during
  the latest rule interval.

This preserves delayed-event coverage without repeatedly selecting the same
source activity.

### Alert count and incident count describe different objects

The fresh post-correction alert did not create a new incident. It was grouped
into existing Incident `4`, which already contained earlier troubleshooting
alerts.

A query filtered only by incident creation time therefore returned no new
incident even though the fresh alert existed. Retrieving the incident by its
last-modified state and listing attached alerts exposed the correct result.

Analysts must distinguish source events, query results, alerts and incidents.

### Entity mapping must not invent unavailable evidence

IDTR001 mapped five Account entities and one Host entity. No Internet Protocol
entity was created because the source field contained `-`.

An empty entity is preferable to a false entity. Placeholder filtering protects
analyst pivots and prevents a presentation-friendly but inaccurate result.

### Platform schemas can be less specific than ATT&CK documentation

The Microsoft Sentinel rule model accepted the parent technique `T1110` but
not the sub-technique format `T1110.003` in the deployed field.

The rule stores the accepted parent technique while the detection document
records the more precise password-spraying behaviour. Security meaning and
platform-schema compliance both matter.

### Duplicate control requires an observation cycle

One fresh alert was not enough to prove the correction. The incident-alert
list was checked after a later overlapping cycle. Validation confirmed one and
only one post-correction alert occurrence.

Tuning should be tested over the schedule behaviour that originally caused the
problem, not only against one immediate query result.

## Milestone 4 — successful authentication after failures lessons

### The test method must generate the required event sequence

The first controlled authentication method produced a successful Event `4624`
but not the required Event `4625` failures. The corrected Windows network-logon
method produced five invalid-password failures followed by one success for the
same account and host.

When a query returns no result, the first question is whether the intended
source events exist. Detection logic cannot compensate for a simulation that
does not exercise the expected authentication path.

### Ordered correlation adds meaning

Failures alone can indicate user error or background noise. A later successful
authentication for the same identity and host changes the risk interpretation.

IDTR002 therefore models sequence and time, not only volume. Its 30-minute
behaviour window, ingestion-delay allowance and fresh-success guard make the
later success the analytic anchor.

### Service limits must shape alert design

A custom-detail key exceeded a Microsoft Sentinel service limit. The design was
corrected to retain the most useful investigation context within the supported
model.

Automated deployment must satisfy the platform contract as well as the
security objective.

### Graphical absence requires independent validation

The incident interface showed no active result while the supported incident
interface returned Incident `6`, its alert, entities and comments.

An empty interface is evidence about that interface, not proof that the
underlying incident does not exist.

## Milestone 5 — high-value group-change lessons

### Scheduled analytics rules include evaluation delay

A five-minute-only ingestion freshness guard excluded every IDTR003 result
because the service evaluates scheduled rules with a built-in delay.

The corrected design used a non-overlapping 5-to-10-minute ingestion-age
window with a five-minute query frequency. The correction was based on observed
execution behaviour rather than an arbitrary wider lookback.

### Addition and removal are separate security facts

Each controlled sequence generated one group-addition alert and one
group-removal alert. Those were not duplicates. They represented different
state transitions and belonged together in one incident timeline.

Reducing both transitions to one alert would remove evidence needed to
understand exposure and recovery.

### Entity meaning matters more than entity count

The actor Account, member Account security identifier, Host and Security Group
security identifier were validated separately. Mapping several entities is
useful only when each one represents the correct role in the event.

### Rule state must be read back after deployment

The rule was initially disabled despite the intended configuration. Persistent
readback exposed the defect and the corrected enabled state was validated
before the evidence sequence.

A deployment command returning success is not sufficient proof of effective
analytics-rule state.

## Milestone 6 — integrated attack-chain lessons

### Correlation requires a deliberate anchor

IDTR004 correlates password spraying across five identities, repeated failures
and a later successful network authentication for one identity, followed by a
synthetic high-value group addition.

The query retains a 75-minute supporting-event horizon while applying the final
`ingestion_time() > ago(5m)` guard only to the chain-completing group addition.
That design preserves enough history for correlation while selecting newly
completed chains.

### A successful historical query is not a scheduled-rule proof

The scheduled output must return `TimeGenerated`, and analytics-rule health
must confirm that the service executed the deployed rule successfully.

Interactive query success, deployment success and scheduled execution health
are separate validation layers.

### Grouped alerts are not automatically duplicates

The final corrected alert joined Incident `13`, which already contained alerts
from separate authorised troubleshooting executions sharing the same entities.

The source records and run boundaries were reviewed before deciding that those
earlier alerts were separate evidence rather than duplicate source-row
selection.

### The source contract should be stated explicitly

The final chain was validated as:

- Five spray identities.
- Nine failed authentications.
- Five failures for the later successful identity.
- One network success.
- One group addition.
- One group removal.

An explicit source contract makes the correlation reproducible and prevents a
single alert from becoming the only evidence that the test worked.

## Milestone 7 — investigation, containment and recovery lessons

### Incident work should be organised and auditable

Incident `14` was assigned, moved to Active and given three investigation
tasks. The alert, complete source sequence, target Account, actor Account, Host
and Security Group were validated before response.

Ownership and tasks are not decoration. They establish responsibility,
sequence the investigation and create a reviewable record.

### Containment should be idempotent

The desired safe state was that the controlled identity was disabled,
unlocked and absent from the synthetic group. The containment script checked
current state and changed only unsafe conditions.

The identity was already safe, so zero directory mutations were required. A
no-change result can be the correct containment outcome when it is supported by
direct validation.

### Recovery must test both identity state and telemetry health

Recovery validation confirmed:

- Controlled identities disabled and unlocked.
- The synthetic high-value group empty.
- Seven required services running.
- Azure Monitor Agent running.
- A fresh harmless Event `4688` recorded locally and observed in
  `SecurityEvent`.

Recovery of one identity object does not prove that the monitoring path still
works. Both security state and observability must be checked.

### Benign Positive is not the same as False Positive

The controlled activity genuinely occurred and the detections identified it
correctly. The incidents were closed as **Benign Positive / Suspicious But
Expected** because the tests were authorised and safely restored.

A False Positive would mean that the rule or evidence incorrectly represented
the intended behaviour.

### Analyst comments should be decision records

The final analyst record captured the alert, timeline, mapped entities,
unavailable source-address context, containment result, recovery evidence and
authorised-test conclusion.

Another analyst should be able to understand the decision without rebuilding
the entire investigation.

## Milestone 8 — completion and publication lessons

### Final validation must cover the whole repository

The completed repository was tested for exact inventory, empty files,
duplicate-content groups, filename variants, PowerShell parsing, Portable
Network Graphics signatures, screenshot sequences, Markdown links, evidence
hashes, stale status language and sensitive values.

The final technical state contained 94 files before this lessons-learned record
was published. Adding this document requires the inventory and validator to be
updated together so the quality gate remains truthful.

### Target-platform parsing matters

A validator that appeared correct in a modern environment exposed a Windows
PowerShell 5.1 encoding issue. Non-ASCII status text was replaced with
ASCII-safe character construction, then the script was parsed and executed on
the actual laptop environment.

Compatibility should be proven on the target runtime, not inferred from source
appearance.

### Publication history is part of the privacy boundary

Replacing a screenshot in the latest commit did not remove its earlier Git
object. A targeted history rewrite replaced only the affected image across the
relevant history, preserved the final Git tree and was verified through a
fresh clone.

Privacy review must consider current files, earlier commits and downloadable
artifacts. Visible redaction in the latest version is not sufficient if a
previous blob remains reachable.

### Final recovery evidence should follow final live validation

The preserved Project 1 rules, domain services, Azure components, collection
configuration and recovery state were validated before `DC01` was shut down.
Only then was `P2-M08-Final-Validated-State` created.

A recovery point is strongest when its recorded description corresponds to a
recently proven effective state.

## Documentation and evidence lessons

### Evidence should prove outcomes, not every click

The repository retains evidence of effective state, source events, cloud
ingestion, rule configuration, alert generation, incident grouping, entity
mapping, direct final-state validation, recovery and closure. Routine
navigation and transient errors are excluded unless they explain an important
engineering decision.

### Screenshots support the engineering record

Screenshots are paired with written reasoning, reusable KQL, PowerShell, known
limitations and expected results. This keeps the project understandable when
a portal layout changes.

### Evidence names and framing matter

Images were retained only when the relevant rule names, states, incident
details or validation output were readable. Duplicate browser-style filenames,
cropped context and unnecessary identifiers were rejected.

Evidence quality is not only about whether an image exists. It must allow a
reviewer to understand what was proven.

### Documentation completeness requires a template gate

File-integrity, link, evidence and sensitive-value checks do not prove that the
repository tells the complete engineering story. Validation must include
section-by-section document coverage: architecture, detections, response,
runbook, limitations, completion review and cross-milestone lessons.

### Sensitive information must be excluded before publication

Repository files are checked for passwords, tokens, personal email addresses,
tenant identifiers, subscription identifiers and private-key markers.
Laboratory resource and domain names remain only where they explain the
architecture without exposing authentication material.

## What I would change for production

| Laboratory design | Production improvement |
|---|---|
| One VMware domain controller | Multiple domain controllers, sites and representative authentication paths |
| Five fixed disposable identities | Organisation-wide coverage with governed exclusions and identity criticality |
| Fixed laboratory thresholds | Thresholds derived from baselines, identity type, source behaviour and risk |
| One workspace and region | Architecture aligned with tenancy, geography, access, retention and recovery requirements |
| Limited identity-only context | Microsoft Entra, endpoint, network, threat-intelligence and asset-criticality enrichment |
| Manual investigation | Approved enrichment and low-risk automation with human control for disruptive actions |
| Reusable queries without full deployment pipeline | Versioned detection-as-code, peer review, tests and rollback |
| Manual health checks | Monitoring for agent, Data Collection Rule, ingestion and analytics-rule health |
| Short laboratory observation windows | Retention, archive and hunting windows based on risk and regulatory needs |

Production design would also require Azure role-based access control
separation, Privileged Identity Management where applicable, cost governance,
formal change records, escalation contacts, detection ownership and
representative test data.

See [Production Limitations and Improvements](docs/Production-Limitations-and-Improvements.md)
for the expanded design-gap analysis.

## Skills demonstrated

- Active Directory identity-state validation.
- Safe PowerShell-based security testing, containment and cleanup.
- Azure Arc, Azure Monitor Agent and Data Collection Rule troubleshooting.
- Windows Security event and Log Analytics schema analysis.
- KQL detection engineering, correlation and ingestion-delay tuning.
- Microsoft Sentinel rule, entity, alert and incident validation.
- MITRE ATT&CK mapping within platform constraints.
- Alert-versus-incident reasoning and grouping analysis.
- Incident ownership, task tracking and auditable decision records.
- Direct final-state and recovery validation.
- Privacy-conscious Git history and evidence management.
- Reproducible technical documentation and repository quality control.

## Final assessment

The strongest outcome is not simply that four rules generated alerts. The
project traces controlled identity activity from the source Windows events
through hybrid collection, cloud-schema validation, ingestion-aware detection,
entity mapping, alert and incident behaviour, investigation, idempotent
containment, direct recovery evidence and defensible closure.

The limitations are explicit rather than hidden. That makes the repository a
credible laboratory implementation and a reproducible demonstration of
identity detection and response method, without presenting it as production
scale or production authority.

## References

- [Azure Monitor Agent overview](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-overview)
- [Data Collection Rules overview](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-rule-overview)
- [Handle ingestion delay in scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay)
- [Microsoft Sentinel scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview)
- [Investigate incidents in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/investigate-incidents)
- [Monitor analytics-rule health and integrity](https://learn.microsoft.com/en-us/azure/sentinel/monitor-analytics-rule-integrity)
- [Microsoft Windows Event 4625 — An account failed to log on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [MITRE ATT&CK T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
