# High-Value Group-Membership Change Detection

## Purpose

Milestone 5 implements and validates `IDTR003 - High-Value Group Membership
Change`. The rule detects additions to and removals from the synthetic global
security group `IDTR-HighValue-Lab` on `DC01.corporate.test`.

The group grants no real administrative privilege. It is a safe monitoring
marker used to demonstrate how a SOC analyst validates privileged-group
telemetry, maps affected entities, distinguishes alerts from incidents, proves
cleanup and records a defensible closure decision.

## Detection objective

A group-membership addition can create or expand privileged access. A later
removal does not erase the security significance of the earlier addition: an
analyst must establish who performed the change, which identity was affected,
which group was targeted, whether the membership remains active and whether
related activity occurred during the exposure window.

IDTR003 monitors:

| Event | Meaning |
|---:|---|
| `4728` | A member was added to a security-enabled global group |
| `4729` | A member was removed from a security-enabled global group |

The validated test used `CORPORATE\Administrator` as the actor,
`idtr-user01` as the controlled member, `IDTR-HighValue-Lab` as the target and
`DC01.corporate.test` as the recording host.

## Validated source contract

The controlled sequence produced exactly one addition followed by one removal:

- Addition: `2026-08-27T22:02:59.750Z`
- Removal: `2026-08-27T22:03:02.762Z`
- First cloud ingestion: `2026-08-27T22:03:35.813Z`
- Last cloud ingestion: `2026-08-27T22:03:56.270Z`
- Actor: `CORPORATE\Administrator`
- Group SID: `S-1-5-21-2144938337-3584204851-355588034-1163`
- Member SID: `S-1-5-21-2144938337-3584204851-355588034-1164`
- Final group membership: zero

The local and cloud evidence is retained in:

- [`m05-01-idtr003-local-group-change-events.png`](../screenshots/m05-01-idtr003-local-group-change-events.png)
- [`m05-02-idtr003-cloud-group-change-ingestion.png`](../screenshots/m05-02-idtr003-cloud-group-change-ingestion.png)

## Final KQL design

The reusable query is
[`IDTR003-HighValueGroupMembershipChange.kql`](../queries/IDTR003-HighValueGroupMembershipChange.kql).

The rule runs every five minutes with a 15-minute event-time period. Microsoft
Sentinel evaluates scheduled rules on a built-in five-minute delay. The final
query therefore selects records whose ingestion age is between five and ten
minutes:

```kusto
| where ingestion_time() between (ago(10m) .. ago(5m))
```

That interval is deliberate. Adjacent five-minute evaluations process adjacent
non-overlapping ingestion windows, accommodating the platform delay while
preventing the same event from being selected repeatedly.

### Corrected engineering defect

The first deployed query used `ingestion_time() > ago(5m)`. Two controlled test
sequences reached `SecurityEvent`, but generated no alerts because the records
were older than five minutes when the delayed scheduled evaluation executed.
The first enablement attempt was also incorrectly reported as successful after
a standalone PASS message was run following a validation exception. Persistent
readback exposed both defects: the rule was disabled and the corrected guard
had not been saved.

The final update rebuilt the payload, enabled the rule and retrieved it again.
The authoritative validation proved:

- `Enabled: True`
- Query frequency `PT5M`
- Query period `PT15M`
- Correct delay-aware guard present
- Unsafe five-minute-only guard absent
- Four entity mappings persisted

Evidence:
[`m05-03-idtr003-validated-rule-configuration.png`](../screenshots/m05-03-idtr003-validated-rule-configuration.png).

## Rule configuration

| Setting | Validated value |
|---|---|
| Display name | `IDTR003 - High-Value Group Membership Change` |
| Severity | High |
| Enabled | Yes |
| Frequency | 5 minutes |
| Period | 15 minutes |
| Trigger | Results greater than 0 |
| Event grouping | Alert per result |
| Incident creation | Enabled |
| Incident grouping | All mapped entities, 5-hour lookback |
| Reopen closed incident | No |
| ATT&CK tactics | Persistence; Privilege Escalation |
| Deployed technique | T1098 Account Manipulation |
| Precise documented behaviour | T1098.007 Additional Local or Domain Groups |

## Alert and incident result

Two authorised troubleshooting sequences were inside the corrected rule's
eligible event-time and ingestion-time ranges. Each sequence generated exactly
one addition alert and one removal alert:

| Sequence | Action | Generated UTC | System alert ID |
|---:|---|---|---|
| 1 | Member removed | `2026-08-27T22:06:05Z` | `2153c18f-c2ed-4fea-8b9f-682154a20d3b` |
| 1 | Member added | `2026-08-27T22:06:05Z` | `92cd2b7c-6104-08a5-d686-1e516f603720` |
| 2 | Member added | `2026-08-27T22:15:55Z` | `2dc5ae4e-32f9-b764-58d8-eca674cc38c8` |
| 2 | Member removed | `2026-08-27T22:16:02Z` | `829bbdc1-597d-2771-2e4d-1df511306ac2` |

These are four distinct alerts for four distinct source changes, not repeated
selection of one source row. All four were grouped into Incident `8`, resource
`0dd46f9f-4d4f-4a42-b7c9-43191dc59381`, because the two sequences shared the
same mapped actor, member, host and security group. This is the intended
relationship between Alert-per-result event grouping and entity-based incident
grouping.

Evidence:
[`m05-04-idtr003-alerts-and-incident.png`](../screenshots/m05-04-idtr003-alerts-and-incident.png).

## Entity mapping

Four mappings produced four validated incident entities:

| Entity | Identifier and result |
|---|---|
| Actor Account | `CORPORATE\Administrator` from Name and NTDomain |
| Member Account | SID ending `-1164` |
| Host | `DC01.corporate.test` from HostName and DnsDomain |
| Security Group | SID ending `-1163` |

No IP entity was mapped because this group-management scenario did not supply a
reliable remote source address. No address was invented.

Evidence:
[`m05-05-idtr003-mapped-entities.png`](../screenshots/m05-05-idtr003-mapped-entities.png).

## Response and safe-state validation

Direct Active Directory and service validation confirmed:

- Five disposable users existed.
- Zero disposable users were enabled.
- Zero disposable users were locked.
- `IDTR-HighValue-Lab` contained zero members.
- All seven required services were running.
- Azure Monitor Agent was running.

Four disabled accounts retained nonzero historical `badPwdCount` values from
earlier authorised tests. Those counters were documented but were not treated
as active exposure: the authoritative safety controls were disabled state,
lockout state and current group membership.

Evidence:
[`m05-06-idtr003-verified-safe-state.png`](../screenshots/m05-06-idtr003-verified-safe-state.png).

An analyst investigation note was saved. When the later pair arrived, a second
comment corrected the final alert inventory and distinguished two controlled
sequences from duplicate selection. Incident `8` was persistently validated as
closed with four alerts and two comments. Its classification remained **Benign
Positive / Suspicious But Expected** because the suspicious changes occurred
and the detection represented them correctly, but the activity was authorised,
controlled and fully reversed.

Evidence:
[`m05-07-idtr003-closed-benign-positive.png`](../screenshots/m05-07-idtr003-closed-benign-positive.png).

## Investigation guidance

For an unplanned production alert, analysts should establish:

1. Whether the actor was authorised to change the group.
2. Whether the member or target group is privileged or business-critical.
3. How long the membership existed and what the member did during that window.
4. Whether the same actor changed other groups or identities.
5. Whether the membership remains active in current directory state.
6. Whether endpoint, authentication or cloud-risk evidence supports compromise.

A removal event is evidence of a change, not proof of containment. Current
membership must be queried directly before closure.

## Production considerations

- Monitor a governed inventory of privileged groups by stable SID rather than
  relying only on display names.
- Correlate changes with approval systems, privileged-access workflows and
  identity ownership.
- Baseline expected administrative tools, actors and maintenance windows.
- Preserve separate actor and affected-member Account mappings.
- Measure ingestion delay and validate non-overlapping query windows after any
  schedule or collection change.
- Enable Sentinel rule-health monitoring so execution failures are visible in
  `SentinelHealth`.
- Automate destructive response only under approved authority and change
  controls.

## References

- [Microsoft Audit Security Group Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)
- [Microsoft Sentinel scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview)
- [Handle ingestion delay in scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay)
- [Map data fields to Microsoft Sentinel entities](https://learn.microsoft.com/en-us/azure/sentinel/map-data-fields-to-entities)
- [Microsoft Sentinel entity types reference](https://learn.microsoft.com/en-us/azure/sentinel/entities-reference)
- [MITRE ATT&CK T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK T1098.007 — Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/)
- [Microsoft Sentinel alert rules create or update REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules/create-or-update?view=rest-securityinsights-2025-09-01)
