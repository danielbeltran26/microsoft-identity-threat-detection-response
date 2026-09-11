# Identity Threat Detection and Response Runbook

## Purpose

This runbook defines a repeatable analyst workflow for Project 2 identity
incidents. It contains the validated IDTR001 password-spray, IDTR002
successful-authentication-after-failures, IDTR003 high-value-group-change and
IDTR004 integrated identity attack-chain procedures.

The runbook separates four different questions:

1. Did the source identity activity occur?
2. Did the scheduled rule represent it correctly?
3. What identities, hosts and source context are affected?
4. What current-state evidence is required before closure?

## Scope

The current procedure covers:

- Microsoft Sentinel alerts created by `IDTR001 - Password Spray Across
  Accounts`.
- Microsoft Sentinel alerts created by `IDTR002 - Successful Authentication
  After Repeated Failures`.
- Microsoft Sentinel alerts created by `IDTR003 - High-Value Group Membership
  Change`.
- Microsoft Sentinel alerts created by `IDTR004 - Integrated Identity Attack
  Chain`.
- Windows Event IDs `4624`, `4625`, `4728` and `4729` from
  `DC01.corporate.test`.
- The controlled accounts `idtr-user01` through `idtr-user05`.
- Account and Host entity validation.
- Incident grouping, analyst comments, safe-state verification and closure.
- Incident assignment, task tracking, idempotent containment and recovery
  verification.

It is a laboratory runbook. Production use would require organisation-specific
ownership, service-level targets, escalation contacts, approved containment
authority and change records.

## Analyst safety rules

- Do not rerun a simulation while investigating an existing incident.
- Do not enable, unlock, reset or delete an identity solely because it appears
  in an alert.
- Do not map `-`, an empty string or another placeholder as an IP entity.
- Do not infer containment from a removal event or a script success message.
- Validate current Active Directory state directly before closure.
- Do not classify authorised activity as a false positive when the detection
  correctly identified the activity.
- Do not use the VMware snapshot as the first rollback action.

## Detection-health pre-check

Before judging the incident, confirm that the monitoring chain is healthy:

1. Verify that `DC01` is running and Active Directory services are healthy.
2. Confirm current Azure Arc and Azure Monitor Agent state.
3. Confirm the Windows Security Data Collection Rule is associated with
   `DC01`.
4. Run [`Validate-IDTRTelemetryBaseline.kql`](../queries/Validate-IDTRTelemetryBaseline.kql).
5. Confirm a fresh `SecurityEvent` row exists before treating an absent alert as
   a detection failure.
6. Confirm the relevant IDTR001, IDTR002, IDTR003 or IDTR004 rule is enabled and
   retains its validated timing configuration.
7. Review `SentinelHealth` when the interface does not expose execution state
   or a query returns data but no alert appears.

## Common incident workflow

### 1. Confirm the incident

Record:

- Incident number and resource identifier.
- Title, severity and status.
- Creation and last-modified times.
- Alert count and comment count.
- Analytics-rule name and system alert identifier.

Creation time alone is insufficient. A fresh alert may be grouped into an
existing incident and change only its last-modified time and alert count.

### 2. Validate source telemetry

Use the query associated with the incident:

- [`IDTR001-PasswordSpray.kql`](../queries/IDTR001-PasswordSpray.kql)
- [`IDTR002-SuccessAfterFailures.kql`](../queries/IDTR002-SuccessAfterFailures.kql)
- [`IDTR003-HighValueGroupMembershipChange.kql`](../queries/IDTR003-HighValueGroupMembershipChange.kql)
- [`IDTR004-IntegratedIdentityAttackChain.kql`](../queries/IDTR004-IntegratedIdentityAttackChain.kql)

For IDTR001, confirm:

- Event ID `4625`.
- Status `0xc000006d` and substatus `0xc000006a`.
- At least five failed attempts.
- At least five distinct controlled identities.
- `DC01.corporate.test` as the recording host.
- Event time and ingestion time.
- Raw `IpAddress`, `WorkstationName` and `LogonType` values.

For IDTR002, confirm:

- Exactly one Event `4624` success with logon type `3`.
- At least five preceding Event `4625` failures for the same account and host.
- Failure status `0xc000006d` and substatus `0xc000006a`.
- Every failure falls within 30 minutes before the success.
- The success was newly ingested during the relevant 5-minute rule interval.
- Raw source, workstation and authentication-package values, including empty or
  placeholder data.

Do not replace missing source context with assumptions.

For IDTR003, confirm:

- One Event `4728` addition and one Event `4729` removal.
- Addition occurs before removal for the same group and member SID.
- Actor account, target group, member distinguished name and both SIDs match
  the raw records.
- The rule uses the validated 5-to-10-minute ingestion-age window.
- Each source event creates one alert, and related alerts are grouped into one
  incident by their shared mapped entities. Distinguish multiple authorised
  sequences from repeated selection of the same source row.

For IDTR004, confirm:

- At least five Event `4625` invalid-password failures across at least five
  identities.
- Determine whether the successful account appears in `TargetIdentities` and
  count its preceding failures. The final controlled sequence recorded five,
  but the deployed query does not enforce a per-account failure threshold.
- One Event `4624` network success with logon type `3` follows the failures.
- One Event `4728` addition places the successful account in the monitored
  high-value group.
- Every stage occurs within the configured 30-minute correlation window and in
  the correct order.
- The Event `4728` addition was newly ingested in the rule's five-minute
  processing interval.
- The query returns `TimeGenerated = GroupAddTimeUTC`.
- A later Event `4729` removal and direct group-state query are investigated as
  response evidence, not treated as proof that no exposure occurred.

### 3. Determine affected scope

Identify:

- Every targeted account.
- Whether any target is privileged, active, locked or outside the controlled
  laboratory inventory.
- The recording host and any usable source address.
- Whether similar failures affected additional accounts or hosts.
- Whether a later successful authentication or group-membership change exists.

Any identity outside the approved Project 2 manifest changes the incident from
a controlled-lab scenario to an escalation condition.

### 4. Validate entity mapping

Compare alert and incident entities with the raw records:

- Account entity count must match the targeted identities represented by the
  query output.
- Host must resolve to `DC01.corporate.test` for the validated laboratory test.
- IP must be absent when the source field is empty or contains `-`.
- For IDTR003, the actor Account, member Account SID, Host and Security Group
  SID must all match the raw Event `4728` and `4729` fields.
- For IDTR004, the successful target Account, group-change actor Account, Host
  and Security Group SID must match the correlated query output.

Entity mapping is an analyst navigation aid; raw source telemetry remains the
authoritative evidence.

### 5. Review alert and incident grouping

Distinguish among:

- Source-event count.
- Query-result count.
- Alert count.
- Incident count.

Multiple alerts inside one incident may be valid grouping behaviour. For
IDTR001, confirm whether each alert represents a separate rule evaluation and
whether the ingestion-time guard prevented repeated selection of the same
source activity. For IDTR002, confirm that each alert represents one fresh
success result and that only one alert exists for the validated success.

For IDTR004, compare system alert IDs and source-sequence times. Earlier alerts
from separate authorised executions must not be described as duplicates of the
final corrected sequence. Confirm that the final alert ID occurs exactly once,
even when entity-based grouping adds it to an existing incident.

For a fresh response exercise, use
[`Investigate-IDTRIntegratedIncident.kql`](../queries/Investigate-IDTRIntegratedIncident.kql)
to reconstruct the source-event timeline independently of the alert result.

### 6. Validate current Active Directory state

Run [`Test-IDTRFinalState.ps1`](../scripts/Test-IDTRFinalState.ps1) as an
administrator on `DC01`.

The validated safe state is:

```text
DisposableUserCount   : 5
EnabledUserCount      : 0
LockedOutUserCount    : 0
HighValueGroupMembers : 0
```

If any value differs, stop the closure workflow and use
[`Restore-IDTRLabState.ps1`](../scripts/Restore-IDTRLabState.ps1) before
revalidating.

### 7. Decide and respond

Choose actions based on evidence, not the controlled scenario label.

| Finding | Required response |
|---|---|
| Approved controlled test; all objects match manifest; safe state verified | Document and close as Benign Positive / Suspicious But Expected |
| Unexpected account, host or source address | Escalate and preserve evidence |
| Successful authentication follows the failures | Correlate with later-stage identity activity and escalate until explained |
| Controlled user remains enabled or locked | Restore and revalidate before closure |
| High-value group contains a member | Remove only with authorised procedure; verify current membership |
| Source telemetry and mapped entities disagree | Keep incident open and investigate mapping/query logic |

### 8. Document and close

The analyst comment must record:

- What activity occurred.
- Which accounts and host were involved.
- Which rule and alert represented it.
- What source-address limitation existed.
- What response and current-state validation were performed.
- Why the selected classification is correct.

Close only after the saved comment and final incident state have both been
retrieved and validated.

## IDTR001 triage guide

### Detection objective

Identify a horizontal password-spray pattern in which a small number of invalid
password attempts is distributed across multiple accounts, reducing reliance on
per-account failure thresholds.

### Initial triage questions

1. Are all targeted identities in the controlled manifest?
2. Did the failures occur on one host or across several hosts?
3. Is a usable source address present?
4. Did any target later authenticate successfully?
5. Did any target receive high-value group membership?
6. Was the alert generated once after the corrected ingestion guard?
7. Was the alert added to a new or existing incident?
8. Is the current directory state safe?

### Escalation indicators

- Any target outside `idtr-user01` through `idtr-user05`.
- Any real privileged, service or emergency-access identity.
- A successful authentication after the failures.
- A non-laboratory source address or host.
- Activity across multiple domain controllers or endpoints.
- Persistent attempts beyond the controlled test window.
- Unexpected group-membership or account-state changes.
- Incomplete cleanup or disagreement between events and current state.

### Likely benign causes

- An approved controlled password-spray simulation.
- A documented authentication scanner or test platform.
- A known configuration deployment using stale credentials across several
  accounts.

These are hypotheses, not automatic exclusions. Each must be confirmed against
approved context and source evidence.

## IDTR002 triage guide

### Detection objective

Identify a successful network authentication after repeated invalid-password
failures for the same account and host. A valid authentication after guessing
activity requires escalation until the success is explained and its scope is
known.

### Initial triage questions

1. Do the five or more failures precede the success within the rule window?
2. Does the success use the expected logon type and authentication package?
3. Is the account privileged, active, shared, service-owned or outside the
   controlled manifest?
4. Is a reliable source address or workstation present?
5. Did the same account authenticate to other hosts?
6. Did the account perform privileged access or group changes after success?
7. Did the rule produce exactly one alert for the fresh success?
8. Is the current directory and telemetry state safe?

### Escalation indicators

- No approved test or operational explanation for the success.
- A privileged, service, emergency-access or non-laboratory account.
- A usable external or unexpected source address.
- Successes across multiple systems or additional accounts.
- Post-authentication privilege changes, remote execution or suspicious
  PowerShell activity.
- Repeated alerts for the same source success.
- Missing source telemetry or disagreement between raw and mapped entities.
- An enabled or locked controlled account after the test.

### Likely benign causes

- An approved controlled IDTR002 simulation.
- A user correcting a mistyped password after several failures.
- A documented service or application credential correction.

These explanations still require positive confirmation. A success after
failures is not dismissed solely because the account eventually authenticated.

## Severity and escalation guide

| Condition | Suggested handling |
|---|---|
| Controlled accounts only; no success; safe state verified | Medium incident, close as documented Benign Positive |
| Later success or privileged target | Raise priority and escalate |
| Multiple hosts, external source or broad identity scope | Escalate for potential active credential attack |
| Telemetry gap prevents scope determination | Keep open and escalate monitoring-health failure |

## Closure classification guide

| Classification | Use when |
|---|---|
| Benign Positive / Suspicious But Expected | The activity occurred, the detection represented it correctly, and authorised context is proven |
| True Positive | Malicious or unauthorised activity is supported by evidence |
| False Positive | The detection incorrectly represented benign source activity or matched outside its intended logic |
| Undetermined | Evidence is insufficient for a defensible conclusion |

The validated IDTR001 through IDTR004 tests are Benign Positives, not False
Positives, because the suspicious behaviours genuinely occurred and the rules
represented them correctly.

## IDTR003 triage guide

### Detection objective

Identify additions to and removals from a governed high-value global security
group. A removal event does not prove that no access or follow-on activity
occurred while membership existed.

### Initial triage questions

1. Who performed the change, and was that actor authorised?
2. Which member and group SIDs were affected?
3. Is the group genuinely privileged or only a monitoring marker?
4. How long did membership exist?
5. What authentication, endpoint or administrative activity occurred during
   that interval?
6. Did the actor change other high-value groups or identities?
7. Does current Active Directory membership prove that access was removed?
8. Did the rule create one alert per event and group the related alerts once?

### Escalation indicators

- Unexpected actor, member, group SID or recording host.
- Membership in a real administrative, remote-access or sensitive-data group.
- Unapproved change or missing change record.
- Authentication or privileged activity by the member during the exposure
  window.
- Additional group changes by the same actor.
- Membership remains active or current directory state cannot be verified.
- Missing source telemetry, failed rule execution or inconsistent entity
  mapping.

### Likely benign causes

- An approved IDTR003 simulation using the synthetic group.
- An authorised access-management change with a valid approval record.
- A documented temporary-access workflow followed by verified removal.

These explanations require evidence. A later removal does not automatically
make the original addition benign.

## IDTR004 triage guide

### Detection objective

Identify a progression from password spraying to successful use of a targeted
domain account and a later high-value group addition. The correlated chain is a
higher-confidence escalation signal than any stage considered alone.

### Initial triage questions

1. Do the failures cover the required number of identities and include the
   account that later succeeds?
2. Is the successful authentication expected for the account, host, protocol
   and time?
3. Does the member derived from Event `4728` match the successful account?
4. Who performed the group addition, and was that actor authorised?
5. Is the target group privileged, sensitive or only a monitoring marker?
6. What did the account do between authentication and verified containment?
7. Is the final alert unique, or was it grouped with alerts from genuinely
   separate executions?
8. Do direct account, lockout and group-membership checks prove a safe state?

### Escalation indicators

- Any target, actor, host or group outside the approved laboratory inventory.
- A successful authentication without a documented authorised explanation.
- Membership in a real privileged, remote-access or sensitive-data group.
- Endpoint, PowerShell, remote-execution or additional authentication activity
  after the success.
- Membership remains active or the target account remains enabled.
- Missing source telemetry, failed analytics execution or mismatched entities.
- Multiple correlated incidents across hosts, identities or administrative
  actors.

### Likely benign causes

- An approved integrated-chain simulation with independently verified cleanup.
- A documented security validation exercise with exact source identifiers and
  change approval.

Operational mistakes do not become benign merely because membership was later
removed. The full sequence, authorisation and current state must all be proven.

## IDTR004 investigation-response procedure

Use this procedure only after a fresh incident and attached alert have been
verified.

1. Record the incident number, resource name, system alert ID and creation
   time.
2. Assign the incident to the responsible analyst and change its status to
   Active.
3. Create separate tasks for timeline validation, identity containment and
   recovery plus closure documentation.
4. Validate the six-stage event contract with the investigation query: five
   spray identities, nine failures, five failures for the successful account,
   one network success, one addition and one removal in the correct order.
5. Compare the target Account, actor Account, Host and Security Group entities
   with the source fields. Record the absence of an IP when no reliable source
   address exists.
6. Complete the timeline task only after the source-result count and mapped
   entities pass validation.
7. Run
   [`Invoke-IDTRIncidentContainment.ps1`](../scripts/Invoke-IDTRIncidentContainment.ps1)
   as an administrator on `DC01`. Zero applied changes are acceptable only when
   direct readback proves the target is disabled and unlocked and the monitored
   group is empty.
8. Complete the containment task after the full controlled-object state passes.
9. Run
   [`Test-IDTRRecoveryState.ps1`](../scripts/Test-IDTRRecoveryState.ps1), then
   confirm its fresh Event `4688` in `SecurityEvent`.
10. Complete the recovery task, save one analyst record containing the evidence
    and limitations, and retrieve the incident to validate task and comment
    counts.
11. Close only after all tasks are Complete and the required classification is
    supported by the evidence.

Never re-enable an already contained identity merely to demonstrate a response
change. Containment is a verified state, not a mutation count.

## Required analyst comment template

```text
Activity:
Affected identities:
Host and source context:
Rule and alert identifiers:
Incident-grouping result:
Investigation findings:
Response performed:
Current-state validation:
Classification and rationale:
Known data limitations:
```

## Evidence checklist

- Persistent rule configuration.
- Fresh local source events.
- Fresh cloud-ingested events.
- Generated alert and available alert identifier.
- Incident grouping and alert count.
- Account, Host and available IP entities.
- Corrected-rule duplicate-control result.
- Integrated-chain stage counts and sequence order.
- Analytics-rule health state when rule execution is disputed.
- Direct final Active Directory state.
- Saved analyst comment.
- Assigned owner, Active status and investigation tasks.
- Idempotent containment output and direct directory readback.
- Fresh post-containment local and cloud telemetry.
- Completed task count before closure.
- Persistently validated closure classification.

## Interface contingency

Use the graphical Microsoft Sentinel or Defender interface first. If the
relevant page repeatedly redirects or cannot complete the required operation:

1. Confirm the service and workspace remain healthy through read-only queries.
2. Use an official supported management interface only for the blocked action.
3. Retrieve the persisted resource after the operation.
4. Capture final validated state rather than transient command output.
5. Document the interface limitation and fallback honestly.

## Runbook maintenance

Update this runbook after each completed detection milestone. New procedures
must be based on validated telemetry, alert behaviour, response evidence and
actual platform constraints—not on untested assumptions.

## References

- [Investigate incidents in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/investigate-incidents)
- [Microsoft Sentinel scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview)
- [Handle ingestion delay in scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay)
- [Microsoft Windows Event 4624 — An account was successfully logged on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft Windows Event 4625 — An account failed to log on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [MITRE ATT&CK T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [Microsoft Audit Security Group Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)
- [MITRE ATT&CK T1098.007 — Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/)
- [Monitor analytics-rule health and integrity](https://learn.microsoft.com/en-us/azure/sentinel/monitor-analytics-rule-integrity)
- [Turn on Microsoft Sentinel auditing and health monitoring](https://learn.microsoft.com/en-us/azure/sentinel/enable-monitoring)
- [Microsoft Sentinel incidents create or update REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/create-or-update?view=rest-securityinsights-2025-09-01)
- [Microsoft Sentinel incident comments create or update REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incident-comments/create-or-update?view=rest-securityinsights-2025-09-01)
- [Navigate and triage incidents in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/incident-navigate-triage)
- [Microsoft Sentinel incident tasks create or update REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incident-tasks/create-or-update?view=rest-securityinsights-2025-09-01)
- [List alerts attached to a Microsoft Sentinel incident](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-alerts?view=rest-securityinsights-2025-09-01)
- [List entities attached to a Microsoft Sentinel incident](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-entities?view=rest-securityinsights-2025-09-01)
