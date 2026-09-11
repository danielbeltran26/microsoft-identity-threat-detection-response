# IDTR002 — Successful Authentication After Repeated Failures

## Detection objective

IDTR002 identifies a successful Windows network authentication that follows at
least five invalid-password failures for the same controlled account and host
within 30 minutes. A success after repeated failures can indicate that password
guessing eventually found a valid credential, so the success is treated as the
fresh anchor event rather than as evidence that the earlier failures were
harmless.

The validated laboratory sequence used Events `4625` and `4624` for
`CORPORATE\idtr-user01` on `DC01.corporate.test`. The scenario was authorised,
remained below the domain lockout threshold and ended with the account disabled,
unlocked and with a zero bad-password count.

## Validated rule configuration

| Property | Persisted value |
|---|---|
| Display name | `IDTR002 - Successful Authentication After Repeated Failures` |
| Rule identifier | `874fc3b9-8fa2-47fc-a402-9abffe00c6c6` |
| Status | Enabled |
| Severity | Medium |
| Query frequency | 5 minutes |
| Query period | 45 minutes |
| Trigger | Greater than 0 |
| Event grouping | Alert per result |
| Incident creation | Enabled |
| Incident grouping | Selected entities, 5-hour lookback |
| Entity mappings | Account and Host |
| Custom detail | `AuthPackage` from `AuthenticationPackageName` |
| Tactics | Credential Access, Initial Access |
| Techniques | T1110, T1078 |

The 45-minute search horizon combines the 30-minute behaviour window, a
10-minute ingestion-delay allowance and one 5-minute rule interval. Only a
success ingested during the latest rule interval can anchor a result, preventing
the same success from being selected repeatedly by overlapping executions.

## Detection query

The deployed query is stored as
[`IDTR002-SuccessAfterFailures.kql`](../queries/IDTR002-SuccessAfterFailures.kql).
Its key controls are:

1. Select Event `4625` failures for the controlled identities on `DC01` with
   status `0xc000006d` and substatus `0xc000006a`.
2. Select Event `4624` network successes with logon type `3`.
3. Use `ingestion_time()` to admit only newly ingested successes.
4. Join success and failure records by account and computer.
5. Require each failure to precede the success and fall within 30 minutes.
6. Require at least five matching failures.
7. Produce Account and Host components for entity mapping without fabricating
   unavailable source information.

## Controlled validation method

The reusable
[`Invoke-IDTRSuccessfulLogonAfterFailures.ps1`](../scripts/Invoke-IDTRSuccessfulLogonAfterFailures.ps1)
script performs the laboratory sequence with safety checks and guaranteed
cleanup:

- Confirms the target is one of the isolated `IDTR-Lab` users.
- Requires the target to start disabled and unlocked.
- Reads the effective lockout policy and refuses a sequence that could reach
  the threshold.
- Generates a temporary random password in memory and never prints it.
- Temporarily enables the account.
- Calls the Windows `LogonUser` API with network logon type `3` for five known
  invalid passwords and one correct password.
- Disables the account in a `finally` block.
- Independently validates the resulting Security events and final directory
  state.

The successful authentication resets the account's bad-password count. The
final test therefore proves both that the intended sequence occurred and that
the disposable account returned to its safe disabled state.

## Source-event validation

The corrected sequence ran from `2026-08-27 15:32:58 UTC` to
`15:33:07 UTC`.

| Check | Validated result |
|---|---|
| Failed authentications | 5 |
| Successful authentications | 1 |
| Failure status and substatus | Correct |
| Successful logon type | 3 |
| Sequence order | Five failures before one success |
| Final account enabled | False |
| Final account locked out | False |
| Final bad-password count | 0 |

Cloud ingestion independently returned five failures and one success. The first
failure occurred at `2026-08-27T15:33:00.7745532Z`, the success at
`2026-08-27T15:33:05.8149849Z`, and the last relevant record was ingested by
`2026-08-27T15:33:59.9248014Z`.

## Alert and incident validation

IDTR002 produced exactly one alert at `2026-08-27 15:40:21.164 UTC`. A later
duplicate-control query still found one alert, with identical earliest and
latest generation times.

The alert created Incident `6`:

| Property | Validated value |
|---|---|
| Incident resource name | `9993109a-735a-4897-9b39-7d04dcccd29b` |
| Title | `IDTR002 - Successful Authentication After Repeated Failures` |
| Initial severity | Medium |
| Initial status | New |
| Created UTC | `2026-08-27 15:40:36` |
| Alert count | 1 |

The incident-alert endpoint independently confirmed that Incident `6` contained
the validated IDTR002 alert. The system alert identifier is intentionally not
recorded here because it was not required for the permanent evidence set.

## Entity validation

The incident contained exactly these mapped entities:

| Entity kind | Mapped value |
|---|---|
| Account | `CORPORATE\idtr-user01` |
| Host | `DC01.corporate.test` |

No IP entity was mapped. The local network authentication did not provide a
reliable remote source address, so the rule and documentation preserve that
limitation instead of inventing one.

## Investigation and closure

The analyst record documented the authorised sequence, source events, entity
mappings, lack of reliable source IP, duplicate-control result and final safe
state. Incident `6` was then closed as **Benign Positive / Suspicious But
Expected**. This is not a False Positive: the suspicious authentication pattern
genuinely occurred and the detection represented it correctly, but the activity
was authorised and controlled.

Final independent validation showed:

| Control | Result |
|---|---:|
| Disposable users | 5 |
| Enabled disposable users | 0 |
| Locked disposable users | 0 |
| Target bad-password count | 0 |
| Members of `IDTR-HighValue-Lab` | 0 |
| Required services stopped | 0 |
| Azure Monitor Agent processes | 1 |

## Troubleshooting decisions

### Authentication method did not generate failure events

The first LDAP-based simulation generated a successful Event `4624` but did not
produce the required Event `4625` failures. It was rejected as unsuitable. The
validated implementation uses the Windows `LogonUser` API with network logon
type `3`, which produced the exact audited sequence.

### Custom-detail key exceeded the service limit

The first rule payload was rejected with HTTP `400` because the custom-detail
key `AuthenticationPackage` exceeded the platform's 20-character limit. The
shorter key `AuthPackage` persisted successfully while retaining
`AuthenticationPackageName` as its source field.

### Incident interface showed no result

The Defender incident page showed zero active incidents even though the alert
had generated. A read-only, paginated incident API request proved that Incident
`6` existed. The investigation then used the official incident alert and entity
endpoints to validate its contents. This interface discrepancy is recorded as a
platform limitation, not treated as evidence that the incident was absent.

## Evidence

- [Validated IDTR002 rule configuration](../screenshots/m04-01-idtr002-validated-rule-configuration.png)
- [Corrected local event sequence](../screenshots/m04-02-idtr002-local-event-sequence.png)
- [Cloud-ingested sequence](../screenshots/m04-03-idtr002-cloud-ingestion.png)
- [Generated alert and Incident 6](../screenshots/m04-04-idtr002-alert-and-incident.png)
- [Mapped Account and Host entities](../screenshots/m04-05-idtr002-mapped-entities.png)
- [Verified safe final state](../screenshots/m04-06-idtr002-verified-safe-state.png)
- [Closed Benign Positive incident](../screenshots/m04-07-idtr002-closed-benign-positive.png)

## Production considerations

- Tune the failure threshold and detection window against representative
  authentication volume rather than copying laboratory values.
- Validate Kerberos, NTLM, SMB, Remote Desktop, VPN, application and cloud
  authentication paths separately because their audit fields differ.
- Apply stronger prioritisation to privileged, service, emergency-access and
  externally sourced authentications.
- Correlate with endpoint, network, Entra and identity-risk telemetry where
  available.
- Measure ingestion delay continuously and adjust the rule horizon and freshness
  guard together.
- Retain direct incident API validation as an operational contingency, not as a
  replacement for fixing interface visibility.

The final cross-milestone technical and repository checks are recorded in
[Repository Completion and Quality Review](Repository-Completion-and-Quality-Review.md).

## References

- [Microsoft Windows Event 4624 — An account was successfully logged on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft Windows Event 4625 — An account failed to log on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft Sentinel scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview)
- [Handle ingestion delay in scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay)
- [Microsoft Sentinel analytics rules create or update REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules/create-or-update?view=rest-securityinsights-2025-09-01)
- [Microsoft Sentinel incident alerts REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-alerts?view=rest-securityinsights-2025-09-01)
- [Microsoft Sentinel incident entities REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-entities?view=rest-securityinsights-2025-09-01)
- [Microsoft Sentinel incident comments REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incident-comments/create-or-update?view=rest-securityinsights-2025-09-01)
- [Microsoft Sentinel incidents create or update REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/create-or-update?view=rest-securityinsights-2025-09-01)
- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
