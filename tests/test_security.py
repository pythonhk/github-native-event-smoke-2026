from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

COMMIT_SHA = "0123456789012345678901234567890123456789"
TEAM_ID = "22222222-2222-4222-8222-222222222222"
ATTEMPT_ID = "33333333-3333-4333-8333-333333333333"


@pytest.fixture
def team_case(
    repo_root: Path,
    tmp_path: Path,
    canonical_copy,
    fixture_json,
    write_json,
    json_digest,
) -> dict[str, Any]:
    team_path = canonical_copy(
        repo_root / "tests/fixtures/team.json", tmp_path / "team.json"
    )
    team = json.loads(team_path.read_text(encoding="utf-8"))

    eventctl_proposal_path = write_json(
        tmp_path / "eventctl-proposal.json",
        team["eventctl_proposal"],
    )
    proposal_digest = json_digest(team_path)
    eventctl_digest = json_digest(eventctl_proposal_path)

    signatures_template_path = canonical_copy(
        repo_root / "tests/fixtures/signatures.json",
        tmp_path / "signatures-template.json",
    )
    signatures_template = json.loads(
        signatures_template_path.read_text(encoding="utf-8")
    )

    pending_signatures = copy.deepcopy(signatures_template)
    pending_signatures["proposal_sha256"] = proposal_digest
    for signature in pending_signatures["signatures"]:
        signature["consent"]["proposal_digest"] = eventctl_digest
    pending_signatures_path = write_json(
        tmp_path / "signatures-pending.json",
        pending_signatures,
    )

    complete_signatures = copy.deepcopy(pending_signatures)
    key_id = "c" * 64
    complete_signatures["signatures"].append(
        {
            "github_id": "103",
            "key_id": key_id,
            "consent": {
                "kind": "team_consent",
                "event_id": "demo-event-2026",
                "actor_id": "103",
                "base_repository": {"id": "123456789"},
                "team_id": TEAM_ID,
                "key_id": key_id,
                "proposal_digest": eventctl_digest,
                "signature": {"key_id": key_id},
            },
        }
    )
    complete_signatures_path = write_json(
        tmp_path / "signatures-complete.json",
        complete_signatures,
    )

    proofs_dir = tmp_path / "proofs"
    proofs_dir.mkdir()
    proof_paths: dict[str, Path] = {}
    for actor_id in ("101", "102", "103"):
        proof = fixture_json(f"tests/fixtures/proofs/{actor_id}.json")
        proof["consent"]["proposal_digest"] = eventctl_digest
        proof_paths[actor_id] = write_json(proofs_dir / f"{actor_id}.json", proof)

    return {
        "team": team_path,
        "pending_signatures": pending_signatures_path,
        "complete_signatures": complete_signatures_path,
        "proofs_dir": proofs_dir,
        "proofs": proof_paths,
    }


@pytest.fixture
def registration_request(
    team_case: dict[str, Any],
    tmp_path: Path,
    write_json,
) -> Path:
    proof = json.loads(team_case["proofs"]["101"].read_text(encoding="utf-8"))
    registration = copy.deepcopy(proof["registration"])
    registration.update(
        {
            "key_epoch": "1",
            "participant_key": {
                "key_id": registration["key_id"],
                "public_key": "PUB101",
            },
            "signature": {"key_id": registration["key_id"]},
            "base_repository": {"id": "123456789"},
        }
    )
    return write_json(tmp_path / "registration.json", registration)


@pytest.fixture
def submission_case(
    repo_root: Path,
    tmp_path: Path,
    fixture_json,
    write_json,
    canonical_copy,
    file_digest,
) -> dict[str, Any]:
    state_path = canonical_copy(
        repo_root / "tests/fixtures/registry-active.json",
        tmp_path / "submission-state.json",
    )
    bundle_path = tmp_path / "bundle.eventctl"
    bundle_path.write_bytes(b"encrypted test bundle\n")
    bundle_digest = file_digest(bundle_path)

    submission = fixture_json("tests/fixtures/submission.json")
    submission["bundle_sha256"] = bundle_digest
    submission["eventctl_request"]["bundle"]["sha256"] = bundle_digest
    request_path = write_json(tmp_path / "submission.json", submission)

    def action_args(
        *,
        request: Path = request_path,
        registry: Path = state_path,
        bundle: Path = bundle_path,
        actual_author: str = "101",
        actual_pr: str = "17",
    ) -> list[str | Path]:
        return [
            "--request",
            request,
            "--registry",
            registry,
            "--bundle",
            bundle,
            "--actual-author",
            actual_author,
            "--actual-pr",
            actual_pr,
            "--actual-pr-id",
            "1700000000000000000",
            "--actual-fork-repository-id",
            "987654321",
            "--actual-head-owner",
            "participant",
            "--actual-head-branch",
            "main",
            "--actual-head-sha",
            "0123456789012345678901234567890123456789",
        ]

    return {
        "state": state_path,
        "bundle": bundle_path,
        "request": request_path,
        "submission": submission,
        "action_args": action_args,
    }


def test_repository_contracts(repo_root: Path, command) -> None:
    shell_files = sorted((repo_root / "scripts").rglob("*.sh"))
    shell_files.append(repo_root / "tools/install-eventctl.sh")
    command(["bash", "-n", *shell_files])
    command(["bash", repo_root / "tools/verify-eventctl-lock.sh"])

    schema_paths = sorted((repo_root / "protocol/schemas/v2").glob("*.json"))
    assert schema_paths
    for schema_path in schema_paths:
        json.loads(schema_path.read_text(encoding="utf-8"))


def test_team_proposal_stages_signatures(team_case, run_script) -> None:
    pending = run_script(
        "scripts/actions/team-proposal.sh",
        "--proposal",
        team_case["team"],
        "--signatures",
        team_case["pending_signatures"],
    )
    assert "PENDING_KEY_PROOFS" in pending.stdout

    ready = run_script(
        "scripts/actions/team-proposal.sh",
        "--proposal",
        team_case["team"],
        "--signatures",
        team_case["complete_signatures"],
    )
    assert "READY_TO_ACTIVATE" in ready.stdout


def test_team_proof_rejects_actor_and_key(
    team_case,
    run_script,
    write_json,
    assert_failed,
) -> None:
    run_script(
        "scripts/actions/team-proof.sh",
        "--proposal",
        team_case["team"],
        "--proof",
        team_case["proofs"]["101"],
        "--actual-author",
        "101",
    )

    wrong_actor = run_script(
        "scripts/actions/team-proof.sh",
        "--proposal",
        team_case["team"],
        "--proof",
        team_case["proofs"]["101"],
        "--actual-author",
        "102",
        check=False,
    )
    assert_failed(wrong_actor)

    wrong_key = json.loads(team_case["proofs"]["101"].read_text(encoding="utf-8"))
    wrong_key["registration"]["participant_key"]["public_key"] = "COPIED-PUBLIC-KEY"
    wrong_key_path = write_json(
        team_case["proofs"]["101"].parent / "101-wrong-key.json",
        wrong_key,
    )
    wrong_key_result = run_script(
        "scripts/actions/team-proof.sh",
        "--proposal",
        team_case["team"],
        "--proof",
        wrong_key_path,
        "--actual-author",
        "101",
        check=False,
    )
    assert_failed(wrong_key_result)


def test_participant_helper_builds_deterministic_signatures(
    team_case,
    run_script,
    write_json,
    canonical_copy,
) -> None:
    consents_dir = team_case["proofs_dir"].parent / "consents"
    consents_dir.mkdir()
    for actor_id, proof_path in team_case["proofs"].items():
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        write_json(consents_dir / f"{actor_id}.json", proof["consent"])

    bundled_path = consents_dir.parent / "bundled-signatures.json"
    run_script(
        "scripts/participant/bundle-team-signatures.sh",
        "--proposal",
        team_case["team"],
        "--consent-dir",
        consents_dir,
        "--out",
        bundled_path,
    )
    complete_path = canonical_copy(
        bundled_path,
        consents_dir.parent / "signatures-from-helper.json",
    )
    run_script(
        "scripts/actions/team-proposal.sh",
        "--proposal",
        team_case["team"],
        "--signatures",
        complete_path,
    )


def test_registration_request_is_actor_bound(
    registration_request,
    run_script,
    assert_failed,
) -> None:
    run_script(
        "scripts/actions/registration.sh",
        "--request",
        registration_request,
        "--actual-author",
        "101",
    )
    wrong_actor = run_script(
        "scripts/actions/registration.sh",
        "--request",
        registration_request,
        "--actual-author",
        "999",
        check=False,
    )
    assert_failed(wrong_actor)


def test_github_pr_metadata_is_projected(
    tmp_path: Path,
    write_json,
    run_script,
) -> None:
    event_path = write_json(
        tmp_path / "github-event.json",
        {
            "repository": {
                "id": 123456789,
                "owner": {"login": "pythonhk"},
                "name": "event",
            },
            "pull_request": {
                "number": 17,
                "id": 1700000000000000000,
                "user": {"id": 101},
                "base": {"ref": "main"},
                "head": {
                    "ref": "submission",
                    "sha": COMMIT_SHA,
                    "repo": {"id": 987654321, "owner": {"login": "participant"}},
                },
            },
        },
    )
    metadata_path = tmp_path / "pr-metadata.json"
    run_script(
        "scripts/admin/prepare-pr-metadata.sh",
        "--github-event",
        event_path,
        "--out",
        metadata_path,
    )
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["kind"] == "github_pr_metadata"
    assert metadata["actor_id"] == "101"
    assert metadata["pull_request"]["base_repository_id"] == "123456789"
    assert metadata["pull_request"]["head_owner"] == "participant"


def test_registration_plan_updates_both_public_registries(
    repo_root: Path,
    tmp_path: Path,
    registration_request: Path,
    fixture_json,
    write_json,
    canonical_copy,
    run_script,
) -> None:
    state = fixture_json("registry/state.json")
    state.update(
        {
            "event_id": "demo-event-2026",
            "phase": "registration_open",
            "enabled": True,
            "revision": 0,
            "users": {},
            "teams": {},
            "memberships": {},
        }
    )
    state_path = write_json(tmp_path / "registration-state.json", state)
    identity_path = canonical_copy(
        repo_root / "registry/identity-registry.json",
        tmp_path / "identity-registry.json",
    )
    registered_state = tmp_path / "registered-state.json"
    registered_identity = tmp_path / "registered-identities.json"
    args = [
        "--state",
        state_path,
        "--identity-registry",
        identity_path,
        "--request",
        registration_request,
        "--actual-author",
        "101",
        "--commit",
        COMMIT_SHA,
        "--out-state",
        registered_state,
        "--out-identity-registry",
        registered_identity,
        "--plan-only",
    ]
    run_script("scripts/admin/register-user.sh", *args)
    registered = json.loads(registered_state.read_text(encoding="utf-8"))
    identities = json.loads(registered_identity.read_text(encoding="utf-8"))
    assert registered["users"]["101"]["key_id"] == "a" * 64
    assert identities["identities"][0]["actor_id"] == "101"

    replay_state = tmp_path / "registered-replay-state.json"
    replay_identity = tmp_path / "registered-replay-identities.json"
    run_script(
        "scripts/admin/register-user.sh",
        "--state",
        registered_state,
        "--identity-registry",
        registered_identity,
        "--request",
        registration_request,
        "--actual-author",
        "101",
        "--commit",
        COMMIT_SHA,
        "--out-state",
        replay_state,
        "--out-identity-registry",
        replay_identity,
        "--plan-only",
    )
    assert replay_state.read_bytes() == registered_state.read_bytes()
    assert replay_identity.read_bytes() == registered_identity.read_bytes()


@pytest.mark.parametrize(
    ("actual_author", "actual_pr"),
    [("999", "17"), ("101", "18")],
)
def test_submission_rejects_authenticated_metadata_substitution(
    submission_case,
    run_script,
    assert_failed,
    actual_author: str,
    actual_pr: str,
) -> None:
    result = run_script(
        "scripts/actions/submission.sh",
        *submission_case["action_args"](
            actual_author=actual_author,
            actual_pr=actual_pr,
        ),
        check=False,
    )
    assert_failed(result)


def test_submission_rejects_inner_pr_mismatch(
    submission_case,
    tmp_path: Path,
    write_json,
    run_script,
    assert_failed,
) -> None:
    request = copy.deepcopy(submission_case["submission"])
    request["eventctl_request"]["pull_request"]["number"] = 999
    request_path = write_json(tmp_path / "submission-inner-pr-mismatch.json", request)
    result = run_script(
        "scripts/actions/submission.sh",
        *submission_case["action_args"](request=request_path),
        check=False,
    )
    assert_failed(result)


def test_submission_replay_is_idempotent_and_fresh_attempts_are_allowed(
    submission_case,
    tmp_path: Path,
    write_json,
    run_script,
    assert_failed,
) -> None:
    applied_state = tmp_path / "submission-applied.json"
    apply_args = [
        "--state",
        submission_case["state"],
        "--request",
        submission_case["request"],
        "--actual-author",
        "101",
        "--pr",
        "17",
        "--bundle",
        submission_case["bundle"],
        "--out",
        applied_state,
        "--plan-only",
    ]
    run_script("scripts/admin/apply-submission.sh", *apply_args)

    replay_state = tmp_path / "submission-replay.json"
    run_script(
        "scripts/admin/apply-submission.sh",
        "--state",
        applied_state,
        "--request",
        submission_case["request"],
        "--actual-author",
        "101",
        "--pr",
        "17",
        "--bundle",
        submission_case["bundle"],
        "--out",
        replay_state,
        "--plan-only",
    )
    assert replay_state.read_bytes() == applied_state.read_bytes()

    altered_bundle = tmp_path / "altered-bundle.eventctl"
    altered_bundle.write_bytes(b"altered replay bundle\n")
    altered_result = run_script(
        "scripts/actions/submission.sh",
        *submission_case["action_args"](
            registry=applied_state,
            bundle=altered_bundle,
        ),
        check=False,
    )
    assert_failed(altered_result)

    fresh_request = copy.deepcopy(submission_case["submission"])
    fresh_attempt_id = "44444444-4444-4444-8444-444444444444"
    fresh_request["attempt_id"] = fresh_attempt_id
    fresh_request["eventctl_request"]["attempt_id"] = fresh_attempt_id
    fresh_request_path = write_json(tmp_path / "submission-fresh.json", fresh_request)
    fresh_state = tmp_path / "submission-fresh-state.json"
    run_script(
        "scripts/admin/apply-submission.sh",
        "--state",
        applied_state,
        "--request",
        fresh_request_path,
        "--actual-author",
        "101",
        "--pr",
        "17",
        "--bundle",
        submission_case["bundle"],
        "--out",
        fresh_state,
        "--plan-only",
    )
    assert len(json.loads(fresh_state.read_text(encoding="utf-8"))["attempts"]) == 2


def test_isolated_scoring_is_payload_bound_and_single_application(
    submission_case,
    tmp_path: Path,
    write_json,
    run_script,
    file_digest,
    assert_failed,
) -> None:
    applied_state = tmp_path / "scoring-input-state.json"
    run_script(
        "scripts/admin/apply-submission.sh",
        "--state",
        submission_case["state"],
        "--request",
        submission_case["request"],
        "--actual-author",
        "101",
        "--pr",
        "17",
        "--bundle",
        submission_case["bundle"],
        "--out",
        applied_state,
        "--plan-only",
    )
    state = json.loads(applied_state.read_text(encoding="utf-8"))
    state["scoring"].update(
        {"enabled": True, "scorer_id": "isolated-test", "scorer_version": "1.0.0"}
    )
    scoring_state = write_json(tmp_path / "scoring-state.json", state)

    payload = tmp_path / "score.payload.json"
    payload.write_text('{"score":42,"grader":"isolated-test"}\n', encoding="utf-8")
    result = {
        "schema": "pythonhk.scoring-result/v2",
        "event_id": "demo-event-2026",
        "attempt_id": ATTEMPT_ID,
        "team_id": TEAM_ID,
        "status": "accepted",
        "payload_sha256": file_digest(payload),
        "scorer_id": "isolated-test",
        "scorer_version": "1.0.0",
        "source_attempt_digest": state["attempts"][ATTEMPT_ID]["request_digest"],
        "issued_at": "2026-08-06T00:00:00Z",
    }
    result_path = write_json(tmp_path / "score.result.json", result)
    run_script(
        "scripts/scoring/validate-result.sh",
        "--state",
        scoring_state,
        "--result",
        result_path,
        "--payload",
        payload,
    )
    scored_state = tmp_path / "scored-state.json"
    apply_args = [
        "--state",
        scoring_state,
        "--result",
        result_path,
        "--payload",
        payload,
        "--commit",
        COMMIT_SHA,
        "--out",
        scored_state,
    ]
    run_script("scripts/admin/apply-score.sh", *apply_args)
    scored = json.loads(scored_state.read_text(encoding="utf-8"))
    assert scored["results"][ATTEMPT_ID]["status"] == "accepted"
    assert scored["attempts"][ATTEMPT_ID]["status"] == "completed"

    duplicate = run_script(
        "scripts/admin/apply-score.sh",
        *["--state", scored_state, *apply_args[2:]],
        check=False,
    )
    assert_failed(duplicate)


def test_registry_views_are_rebuilt_from_authoritative_state(
    submission_case,
    tmp_path: Path,
    run_script,
) -> None:
    applied_state = tmp_path / "views-input-state.json"
    run_script(
        "scripts/admin/apply-submission.sh",
        "--state",
        submission_case["state"],
        "--request",
        submission_case["request"],
        "--actual-author",
        "101",
        "--pr",
        "17",
        "--bundle",
        submission_case["bundle"],
        "--out",
        applied_state,
        "--plan-only",
    )
    users_path = tmp_path / "users-index.json"
    teams_path = tmp_path / "teams-index.json"
    memberships_path = tmp_path / "memberships-index.json"
    submissions_path = tmp_path / "submissions-index.json"
    run_script(
        "scripts/admin/rebuild-views.sh",
        "--state",
        applied_state,
        "--users-out",
        users_path,
        "--teams-out",
        teams_path,
        "--memberships-out",
        memberships_path,
        "--submissions-out",
        submissions_path,
    )
    users = json.loads(users_path.read_text(encoding="utf-8"))
    submissions = json.loads(submissions_path.read_text(encoding="utf-8"))
    assert users["users"]["101"]["github_id"] == "101"
    assert len(submissions["attempts"]) == 1


def test_lifecycle_is_monotonic_and_can_shutdown(
    repo_root: Path,
    tmp_path: Path,
    fixture_json,
    write_json,
    run_script,
    assert_failed,
) -> None:
    state_path = write_json(
        tmp_path / "lifecycle-state.json", fixture_json("registry/state.json")
    )
    open_state = tmp_path / "lifecycle-open.json"
    run_script(
        "scripts/admin/set-lifecycle.sh",
        "--state",
        state_path,
        "--phase",
        "registration_open",
        "--enabled",
        "true",
        "--reason",
        "",
        "--commit",
        COMMIT_SHA,
        "--out",
        open_state,
    )
    frozen_state = tmp_path / "lifecycle-frozen.json"
    run_script(
        "scripts/admin/set-lifecycle.sh",
        "--state",
        open_state,
        "--phase",
        "frozen",
        "--enabled",
        "false",
        "--reason",
        "organizer shutdown",
        "--commit",
        COMMIT_SHA,
        "--out",
        frozen_state,
    )
    frozen = json.loads(frozen_state.read_text(encoding="utf-8"))
    assert frozen["phase"] == "frozen"
    assert frozen["enabled"] is False
    assert frozen["disabled_reason"] == "organizer shutdown"

    backward = run_script(
        "scripts/admin/set-lifecycle.sh",
        "--state",
        frozen_state,
        "--phase",
        "formation_open",
        "--enabled",
        "true",
        "--reason",
        "",
        "--commit",
        COMMIT_SHA,
        "--out",
        tmp_path / "lifecycle-backward.json",
        check=False,
    )
    assert_failed(backward)


def test_team_activation_is_atomic_and_loses_current_state_race(
    repo_root: Path,
    tmp_path: Path,
    fixture_json,
    write_json,
    team_case,
    run_script,
    assert_failed,
) -> None:
    state = fixture_json("registry/state.json")
    state.update(
        {
            "event_id": "demo-event-2026",
            "phase": "formation_open",
            "enabled": True,
            "revision": 0,
            "users": {},
            "teams": {},
            "memberships": {},
        }
    )
    state_path = write_json(tmp_path / "formation-state.json", state)
    activated_state = tmp_path / "activated-state.json"
    args = [
        "--state",
        state_path,
        "--proposal",
        team_case["team"],
        "--signatures",
        team_case["complete_signatures"],
        "--proof-dir",
        team_case["proofs_dir"],
        "--commit",
        COMMIT_SHA,
        "--out",
        activated_state,
        "--plan-only",
    ]
    run_script("scripts/admin/activate-team.sh", *args)
    activated = json.loads(activated_state.read_text(encoding="utf-8"))
    assert activated["memberships"]["101"] == TEAM_ID
    assert activated["memberships"]["103"] == TEAM_ID
    assert activated["revision"] == 1

    race = run_script(
        "scripts/admin/activate-team.sh",
        "--state",
        activated_state,
        "--proposal",
        team_case["team"],
        "--signatures",
        team_case["complete_signatures"],
        "--proof-dir",
        team_case["proofs_dir"],
        "--commit",
        COMMIT_SHA,
        "--out",
        tmp_path / "rejected-state.json",
        "--plan-only",
        check=False,
    )
    assert_failed(race)


def test_workflows_keep_fork_code_out_of_trusted_execution(repo_root: Path) -> None:
    workflow_paths = sorted((repo_root / ".github/workflows").glob("*.yml"))
    assert workflow_paths
    allowed_target_workflows = {
        "team-proposal.yml",
        "team-proof.yml",
        "submission.yml",
        "registration.yml",
    }
    for workflow_path in workflow_paths:
        text = workflow_path.read_text(encoding="utf-8")
        if "pull_request_target" in text:
            assert workflow_path.name in allowed_target_workflows
        assert "checkout.*head" not in text
        assert "github.event.pull_request.head.ref" not in text
