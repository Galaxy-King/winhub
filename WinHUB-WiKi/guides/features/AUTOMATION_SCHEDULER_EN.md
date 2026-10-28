# Automation Scheduler

[English / Українська](AUTOMATION_SCHEDULER_UA.md)

## Automation Scheduler · how the pieces fit


A schedule runs an approved Workspace template on managed endpoints. It does not back up the WinHUB server. The server calculates the occurrence, records a durable run, queues signed tasks, and waits for authenticated agent results. Agents collect tasks during polling: the planned time is not a guarantee of immediate script startup.

## 1. Create an approved template first


Test your backup or maintenance script on one endpoint. Make it non-interactive, wait for child processes, check external program exit codes, verify the required output, and return an explicit exit code. Save and approve the template in Deployment Builder. Editing a template invalidates its approval; Scheduler will fail closed until it is approved again. Templates with missing variables, revoked permissions or unavailable targets cannot run.

## 2. Create a schedule


New Schedule → enter a name, category and launch reason → select the approved template and allowed host/group → supply template variables. The launch reason is required for automatic execution; Run Now asks for a reason for that particular manual run. A group is resolved when dispatching; review group membership before large deployments.

## 3. Choose a recurrence and check the preview


Once: one local date/time. Daily: every N calendar days. Weekly: selected weekdays every N weeks, anchored to the Monday of the start-date week. For a fortnightly backup choose Weekly, every 2 weeks, Sunday, 03:00. Monthly: every N months on a day number, last day, or first/second/third/fourth/last weekday. A missing day (for example February 31) is skipped, not moved. Fixed interval: elapsed minutes/hours/24-hour days from the start instant; every 30 days differs from monthly. Advanced cron: five fields; it is not an anchored every-two-weeks expression.

Timezone belongs to the schedule, not the browser. Start/end dates are local to that zone; storage and history filters use UTC. The preview displays the next five executions in the selected timezone. Calendar modes skip nonexistent local times during spring DST changes and run the first occurrence once when a local time repeats in autumn. Fixed intervals follow elapsed time. Advanced cron follows APScheduler's timezone rules. Check the preview around DST changes. End date is optional and inclusive at its selected time.

## 4. Separate delivery from execution


Delivery window starts when the server queues the task. Set it longer than the worst expected polling cadence, jitter and preceding host work. Execution time limit starts at agent pickup; it is sent to the agent as its execution budget. Pickup is not proof that the first backup instruction ran. A two-minute return grace allows the final result to arrive. If the budget plus grace elapses without a result, the outcome is Result unknown, never a claimed backup failure or success.

## 5. Prevent overlap and unsafe retries


Skip new occurrence: record Skipped while the preceding run is active or unresolved. Queue one occurrence: retain one waiting occurrence and skip additional overlaps. Disabling the schedule pauses queued occurrences; re-enabling it allows them to continue. Edit/disable does not stop a running script. Do not delete a schedule merely to bypass an unknown run; check the endpoint first.

Missed run: after server recovery, run one coalesced occurrence or skip it. Skip has a five-minute grace for brief scheduling delays. A month's backlog is not replayed. A durable occurrence key prevents two scheduler workers from dispatching the same occurrence. An interrupted claim is shown as unknown rather than automatically dispatched twice.

Delivery retries: extend/retry delivery of the same task only if no agent has accepted it. The delay and new delivery window are explicit. Accepted, running, script-failed or unknown executions are never automatically re-executed. This prevents two backups from running when a result was lost. Configure idempotent scripts and test their recovery separately.

## 6. Define a meaningful result contract


New script schedules use a server-generated wrapper around approved code. It runs a child PowerShell/Bash process on the endpoint, captures its numeric exit code and appends a per-task result trailer. The server parses only that bounded trailer from an authenticated agent result; arbitrary output is never evaluated. Scripts and agent assertions remain trusted operational inputs, not independent proof of a successful restore. A missing/truncated trailer or interrupted execution is Result unknown. Legacy agents can use these wrappers without an update; they still need to support the selected task type.

Success codes: default 0. Warning codes: optional, for example 10. Verification failure codes: default 21. Lists must not overlap. All other returned codes mean Script failed. A warning counts as completed, but is yellow. Codes are defined by your script; an external backup utility may use different codes. Translate them deliberately. For non-script actions and metric templates, native agent status is used; no numeric wrapper contract is asserted.

PowerShell: external command failures do not necessarily throw. Read `$LASTEXITCODE` or `Start-Process -Wait -PassThru` and its ExitCode. Use `$ErrorActionPreference = 'Stop'`, catch exceptions, and explicitly return failure. Bash: check the command status; a later successful `echo` can otherwise hide the backup failure. Avoid backgrounding the actual backup.

```powershell
$ErrorActionPreference = 'Stop'
try {
    # Run your configured backup utility here and wait for it.
    # If its exit code indicates failure: exit 20
    # Run the utility's archive/integrity check here.
    # If verification fails: exit 21
    # Only after both checks succeed: exit 0
} catch {
    Write-Output $_.Exception.Message
    exit 20
}
```


This is a contract illustration, not a ready-to-run backup script. A file existing or having a nonzero size is insufficient to prove integrity. Test a restore on a separate machine and schedule restore verification when appropriate. Tasks run under the agent service account, not your desktop user: drive mappings, credentials, network-share permissions, software paths and environment can differ. Keep secrets in the supported secret-variable mechanism, not task names, launch reasons or logs.

## 7. Read status and history


Schedules shows last result, last occurrence and next occurrence. Run history records each automatic/manual/blocked/skipped run with per-host results, numeric exit code, receipt/completion timestamps, observed duration and delivery retry count. Filter by name/category/source/status/endpoint ID/date; date filters are UTC. Open View log for details (requires Queue access). Only the first 100 permitted host rows are shown per run; use the endpoint-ID filter and Execution Queue for larger jobs. Old tasks from before this upgrade remain in Queue, without invented numeric codes or reconstructed occurrences.

Green Success: accepted success code. Yellow Warning: configured warning code. Yellow Waiting for agent: not accepted yet. Delivery expired: not delivered; the script was not started by this task. Blue Running: accepted, final result not received. Red Script failed: returned failure code. Red Verification failed: configured verification failure code. Dispatch failed: template/permissions/variables/targets prevented dispatch. Partial failure: hosts have different outcomes, at least one failed. Result unknown: execution cannot be confirmed; check the host. Cancelled, Missed, Skipped and Resolved manually are distinct from Success.

## 8. Troubleshoot safely


First identify the stage. No occurrence: check enabled state, start/end/timezone and server scheduler health. Dispatch failed: inspect approval, launch reason, variable values and current owner permissions. Waiting/delivery expired: check Last contact, next polling window, agent access and queue. Script failed: inspect exit code and log on the endpoint. Verification failed: inspect backup output and the verification command. Unknown: confirm all child processes have stopped before a superadmin uses Resolve manually with an audit reason. Resolution records an administrative outcome; it does not stop processes or declare success.

Existing schedules retain their calendar expression and legacy native-result behavior until edited. Saving with the new form enables the explicit result policy. Re-test one host after migration. Run history follows configured history retention; unresolved runs are retained to prevent unsafe retries. New UI and wrappers require a server update, not a mandatory agent rebuild.
