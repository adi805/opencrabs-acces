#!/usr/bin/env bash
# Rerun a CI run once when the only failures are GitHub runner preemptions.
#
# Why this exists: hosted runners occasionally get their VM shut down mid-job.
# The runner agent then prints "The runner has received a shutdown signal" and
# exits 143 (128 + SIGTERM). The job dies before a single test writes a result
# line, so the red check says nothing about the code. Between 2026-10-23 and
# 2026-10-24 that happened five times in a row across five different runners,
# and the same suite passed on the sixth attempt with no code change.
#
# Those preempted jobs conclude `failure` with exit 143, which is what the log
# marker below keys on. A job can also conclude `cancelled`, and that shape was
# invisible to this script until now: it counted only `failure` jobs, so a run
# that went red solely because a job was cancelled was reported as "no
# preempted job found" and left for a human. Three of the last 300 runs failed
# that way, and they are not all the same:
#
#   - "The job was not acquired by Runner of type hosted even after multiple
#     attempts" (44317665357, 44274791211): capacity, the job never ran. The
#     red check says nothing about the code, so a rerun is the repair.
#   - "The job has exceeded the maximum execution time" (44481169085): the job
#     did run and ran out of its own budget. A rerun would burn the same 90
#     minutes, so it is a real failure.
#   - "Canceling since a higher priority waiting request ... exists"
#     (44887271123, whose RUN conclusion is cancelled): concurrency superseded
#     it on purpose. A newer run already carries the truth.
#
# A cancelled job's log is not served (HTTP 404 for every cancelled job
# checked: 134859913423, 136818806286, 136818806561), so its cause is read
# from the check-run annotations instead. Unknown or unreadable annotations
# veto, exactly like an unreadable log does for a failed job.
#
# The dangerous half is the opposite case: a real assertion failure must NEVER
# be rerun, because a green retry would hide a broken test. So a rerun happens
# only when EVERY failed or cancelled job carries the preemption or capacity
# signature. One job without it, or evidence we cannot read, means no rerun.
#
# Usage: auto-rerun-preempted.sh [RUN_ID] [REPO]
#   RUN_ID and REPO may also come from the environment, which is how the
#   workflow passes them. When REPO is absent it is detected with
#   `gh repo view`, so a local DRY_RUN against a historical run needs no setup.
# Env: REPO (owner/name), RUN_ID, MAX_ATTEMPTS (default 6), DRY_RUN (1 = report only)
set -uo pipefail

log() { printf '%s\n' "$*"; }

RUN_ID="${1:-${RUN_ID:-}}"
REPO="${2:-${REPO:-}}"

if [ -z "$REPO" ]; then
    REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null) || true
fi
if [ -z "$REPO" ]; then
    REPO=$(git remote get-url origin 2>/dev/null \
        | sed -E 's#^git@[^:]+:##; s#^https?://[^/]+/##; s#\.git$##') || true
fi
if [ -z "$REPO" ]; then
    log "FAIL: cannot determine repo; pass it as the second argument or set REPO"
    exit 1
fi
if [ -z "$RUN_ID" ]; then
    log "FAIL: run id required; pass it as the first argument or set RUN_ID"
    exit 1
fi

# Total attempts allowed, counting manual reruns. Six, not three: the
# 2026-10-23/24 preemption streak needed exactly six attempts before the same
# suite passed with no code change, so a lower cap would have abandoned a run
# that was going to go green. The cap still exists so a permanently broken
# runner cannot loop forever.
MAX_ATTEMPTS="${MAX_ATTEMPTS:-6}"
DRY_RUN="${DRY_RUN:-0}"

# Markers the runner agent itself emits when its VM is torn down. Both come
# from the agent, never from test output, so they cannot be spoofed by a test
# that merely prints "143".
PREEMPT_MARKERS='has received a shutdown signal|Process completed with exit code 143'

# Check-run annotations that explain a `cancelled` job. The log is 404 for
# these, so the annotation is the only evidence there is.
#   - never acquired a runner: capacity, the job did not run -> rerun
#   - superseded by a newer run: deliberate -> veto
#   - anything else (a human cancel prints only "The operation was canceled."):
#     unknown -> veto
NOT_ACQUIRED_MARKERS='was not acquired by Runner'
SUPERSEDE_MARKERS='higher priority waiting request'
TIMEOUT_MARKERS='exceeded the maximum execution time'

# An aggregator job (ci-gate) fails *because* another job failed, so counting
# it as a real failure would veto every rerun. It is identified two ways: by
# name, and by the relay line it prints. If ci.yml's gate message is ever
# reworded, update RELAY_MARKERS with it; the name check is the backstop.
RELAY_JOB_NAMES="${RELAY_JOB_NAMES:-CI Required Gate}"
RELAY_MARKERS="${RELAY_MARKERS:-One or more CI jobs failed or were cancelled}"

# Fetch a job log. gh refuses to print logs containing terminal escape
# sequences unless --allow-escape-sequences is passed (it exits 1 with an
# empty body otherwise, which reads exactly like "log not found"). Older gh
# builds lack the flag, so fall back rather than dying.
fetch_log() {
    local job_id="$1"
    if gh api "repos/$REPO/actions/jobs/$job_id/logs" --allow-escape-sequences 2>/dev/null; then
        return 0
    fi
    gh api "repos/$REPO/actions/jobs/$job_id/logs" 2>/dev/null
}

# Fetch a job's check-run annotations as one message per line. The job payload
# carries check_run_url, which points at the check run itself: the annotations
# live one segment further, so the suffix is appended here. Getting that wrong
# is not silent: `.[]` on a check-run object walks its values and jq fails with
# "expected an object but got: string".
fetch_annotations() {
    local url="$1"
    [ -n "$url" ] || return 0
    local path="${url#https://api.github.com/}"
    [ "$path" != "$url" ] || return 0
    gh api "$path/annotations" --paginate --jq '.[] | .message'
}

run_json=$(gh api "repos/$REPO/actions/runs/$RUN_ID" 2>/dev/null) || {
    log "FAIL: cannot read run $RUN_ID (check token scope: actions:read)"
    exit 1
}

conclusion=$(printf '%s' "$run_json" | jq -r '.conclusion // "null"')
attempt=$(printf '%s' "$run_json" | jq -r '.run_attempt // 1')
head_sha=$(printf '%s' "$run_json" | jq -r '.head_sha // "unknown"')
head_branch=$(printf '%s' "$run_json" | jq -r '.head_branch // "unknown"')
event=$(printf '%s' "$run_json" | jq -r '.event // "unknown"')

log "run=$RUN_ID event=$event branch=$head_branch sha=${head_sha:0:9} attempt=$attempt conclusion=$conclusion"

# Only a genuinely failed run is a candidate. success/skipped are fine, and a
# `cancelled` RUN is deliberate by definition: concurrency superseded it or a
# human stopped it. The `cancelled` shape this script repairs is a cancelled
# JOB inside a run that concluded `failure`, which is what a gate relaying a
# cancelled dependency produces.
case "$conclusion" in
    failure|timed_out) ;;
    *)
        log "SKIP: conclusion is '$conclusion', nothing to repair"
        exit 0
        ;;
esac

if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
    log "SKIP: attempt $attempt reached the cap of $MAX_ATTEMPTS, leaving this to a human"
    exit 0
fi

# Collect failed and cancelled jobs. Paginate: a matrix run can exceed the
# 30-per-page default.
jobs_json=$(gh api "repos/$REPO/actions/runs/$RUN_ID/jobs?per_page=100" --paginate 2>/dev/null) || {
    log "FAIL: cannot list jobs for run $RUN_ID"
    exit 1
}

candidate_count=$(printf '%s' "$jobs_json" | jq -s '[.[].jobs[] | select(.conclusion == "failure" or .conclusion == "cancelled")] | length')
if [ "$candidate_count" -eq 0 ]; then
    log "SKIP: no job concluded 'failure' or 'cancelled'"
    exit 0
fi
log "failed or cancelled jobs: $candidate_count"

# Every candidate must be preempted, capacity-starved, or a pure relay. A
# single real failure vetoes the rerun.
preempted=0
infra=0
superseded=0
real_failures=0
relayed=0
while IFS=$'\t' read -r job_id job_conclusion job_check_run job_name; do
    [ -n "$job_id" ] || continue

    # Aggregator by name: no log fetch needed.
    case " $RELAY_JOB_NAMES " in
        *" $job_name "*)
            log "  relay: '$job_name' ($job_id)"
            relayed=$((relayed + 1))
            continue
            ;;
    esac

    if [ "$job_conclusion" = "cancelled" ]; then
        # The log is 404 for a cancelled job, so the annotation is the evidence.
        if [ -z "$job_check_run" ]; then
            log "STOP: cancelled job '$job_name' ($job_id) carries no check_run_url; not rerunning blind"
            exit 0
        fi
        ann_err=$(mktemp)
        annotations=$(fetch_annotations "$job_check_run" 2>"$ann_err")
        if [ -z "$annotations" ]; then
            # No annotation is not the same as "nothing wrong". Rerunning blind
            # could paper over a real failure, so stop and say why.
            if [ -s "$ann_err" ]; then
                log "STOP: cancelled job '$job_name' ($job_id) annotation fetch failed: $(head -n 1 "$ann_err")"
            else
                log "STOP: cancelled job '$job_name' ($job_id) has no readable annotation; not rerunning blind"
            fi
            rm -f "$ann_err"
            exit 0
        fi
        rm -f "$ann_err"
        if printf '%s' "$annotations" | grep -Fq "$SUPERSEDE_MARKERS"; then
            log "  superseded: '$job_name' ($job_id) was cancelled by a newer run"
            superseded=$((superseded + 1))
        elif printf '%s' "$annotations" | grep -Fq "$NOT_ACQUIRED_MARKERS"; then
            log "  infra: '$job_name' ($job_id) never got a runner"
            infra=$((infra + 1))
        elif printf '%s' "$annotations" | grep -Fq "$TIMEOUT_MARKERS"; then
            log "  REAL FAILURE: '$job_name' ($job_id) ran and hit its own time limit"
            real_failures=$((real_failures + 1))
        else
            log "  REAL FAILURE: cancelled '$job_name' ($job_id) for a reason this script does not know"
            real_failures=$((real_failures + 1))
        fi
        continue
    fi

    body=$(fetch_log "$job_id")
    if [ -z "$body" ]; then
        # Unreadable log is ambiguous, not evidence. Rerunning blind could
        # paper over a real failure, so stop and say so.
        log "STOP: log for job '$job_name' ($job_id) is unreadable; not rerunning blind"
        exit 0
    fi

    if printf '%s' "$body" | grep -Eq "$PREEMPT_MARKERS"; then
        log "  preempted: '$job_name' ($job_id)"
        preempted=$((preempted + 1))
    elif printf '%s' "$body" | grep -Fq "$RELAY_MARKERS"; then
        # Aggregator by behaviour: it only reported someone else's failure.
        log "  relay: '$job_name' ($job_id)"
        relayed=$((relayed + 1))
    else
        log "  REAL FAILURE: '$job_name' ($job_id) has no shutdown/143 marker"
        real_failures=$((real_failures + 1))
    fi
done <<EOF
$(printf '%s' "$jobs_json" | jq -rs '.[].jobs[] | select(.conclusion == "failure" or .conclusion == "cancelled") | "\(.id)\t\(.conclusion)\t\(.check_run_url // "")\t\(.name)"')
EOF

if [ "$real_failures" -gt 0 ]; then
    log "SKIP: $real_failures job(s) failed or were cancelled for a reason this script does not know; a rerun would hide them"
    exit 0
fi

if [ "$superseded" -gt 0 ]; then
    log "SKIP: $superseded job(s) were superseded by a newer run; that run is the truth, not this one"
    exit 0
fi

if [ $((preempted + infra)) -eq 0 ]; then
    log "SKIP: no preempted or capacity-starved job found (relayed=$relayed); nothing a rerun would fix"
    exit 0
fi

log "every bad job was infrastructure (preempted=$preempted capacity=$infra relayed=$relayed)"

if [ "$DRY_RUN" = "1" ]; then
    log "DRY_RUN: would rerun failed jobs of run $RUN_ID (attempt $attempt -> $((attempt + 1)))"
    exit 0
fi

# POST is the action itself, not a probe. rerun-failed-jobs keeps green jobs
# green and only restarts what died, so a rerun costs minutes not a full cycle.
if gh api -X POST "repos/$REPO/actions/runs/$RUN_ID/rerun-failed-jobs" >/dev/null 2>&1; then
    log "RERUN: restarted failed jobs of run $RUN_ID (attempt $attempt -> $((attempt + 1)))"
else
    log "FAIL: rerun request rejected for run $RUN_ID"
    exit 1
fi
