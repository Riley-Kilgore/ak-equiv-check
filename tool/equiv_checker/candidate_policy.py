from __future__ import annotations

from typing import Any, Iterable, Mapping

from .evidence import identity_hash, release_decision_id

POLICY_SCHEMA_VERSION = "equiv-candidate-policy/v1"
STRICT_POLICY_CONFIGURATION = {
    "accepted_required_classifications": [
        "equivalent_under_raw_model",
        "expected_negative_diagnostic",
        "identical",
        "not_applicable",
    ],
    "fail_closed": True,
    "raw_equivalence_required_for_changed_programs": True,
}
SCREENING_POLICY_CONFIGURATION = {
    "accepted_required_classifications": [
        "bounded_equivalent",
        "equivalent_under_raw_model",
        "expected_negative_diagnostic",
        "identical",
        "not_applicable",
    ],
    "preserve_semantic_state": True,
    "publishable": False,
}


def _result_blocker(row: Mapping[str, Any]) -> str:
    value = row.get("evidence_result_id")
    if isinstance(value, str):
        return value
    return identity_hash("missing_obligation_result", dict(row))


def classify_changed_pairs(
    program_pairs: Iterable[Mapping[str, Any]],
    semantic_models: Iterable[Mapping[str, Any]],
    semantic_obligations: Iterable[Mapping[str, Any]],
    obligation_results: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    model_by_id = {
        str(row["semantic_model_id"]): row for row in semantic_models
    }
    obligations_by_pair: dict[str, list[Mapping[str, Any]]] = {}
    for obligation in semantic_obligations:
        obligations_by_pair.setdefault(
            str(obligation["program_pair_id"]), []
        ).append(obligation)
    result_by_obligation = {
        str(row["logical_obligation_id"]): row for row in obligation_results
    }
    classifications: list[dict[str, Any]] = []
    counts = {
        "changed_program_pairs": 0,
        "raw_complete_changed_pairs": 0,
        "bounded_changed_pairs": 0,
        "ledger_complete_changed_pairs": 0,
        "ledger_only_changed_pairs": 0,
        "off_ledger_differences": 0,
        "confirmed_difference_changed_pairs": 0,
        "unsupported_raw_changed_pairs": 0,
        "inconclusive_raw_changed_pairs": 0,
    }
    for pair in sorted(program_pairs, key=lambda row: str(row["program_pair_id"])):
        pair_id = str(pair["program_pair_id"])
        old_hash = pair["old_program_artifact"]["script_sha256"]
        new_hash = pair["new_program_artifact"]["script_sha256"]
        if old_hash == new_hash:
            classifications.append(
                {
                    "program_pair_id": pair_id,
                    "changed": False,
                    "classification": "identical",
                    "raw_classification": "identical",
                    "ledger_classifications": [],
                    "blocking_evidence_ids": [],
                }
            )
            continue
        counts["changed_program_pairs"] += 1
        raw_results: list[Mapping[str, Any]] = []
        ledger_groups: dict[str, list[Mapping[str, Any]]] = {}
        missing_obligations: list[str] = []
        for obligation in obligations_by_pair.get(pair_id, []):
            result = result_by_obligation.get(
                str(obligation["logical_obligation_id"])
            )
            if result is None:
                missing_obligations.append(
                    str(obligation["logical_obligation_id"])
                )
                continue
            model = model_by_id.get(str(obligation["semantic_model_id"]), {})
            profile = str(model.get("input_model", model).get("profile", ""))
            if profile.startswith("raw-uplc"):
                raw_results.append(result)
            elif profile.startswith("ledger-valid"):
                ledger_groups.setdefault(
                    str(obligation["semantic_model_id"]), []
                ).append(result)
        raw_by_kind = {
            str(row["obligation_kind"]): row for row in raw_results
        }
        raw_equivalence = raw_by_kind.get("observational_equivalence")
        raw_completion = [
            raw_by_kind.get("old_program_completion"),
            raw_by_kind.get("new_program_completion"),
        ]
        raw_non_vacuity = raw_by_kind.get("domain_non_vacuity")
        raw_blockers: list[str] = []
        if missing_obligations or raw_equivalence is None:
            raw_classification = "missing_evidence"
            raw_blockers.extend(missing_obligations)
            counts["inconclusive_raw_changed_pairs"] += 1
        elif raw_equivalence.get("status") == "falsified":
            if raw_equivalence.get("replay_reference"):
                raw_classification = "confirmed_non_equivalent"
                counts["confirmed_difference_changed_pairs"] += 1
            else:
                raw_classification = "blaster_falsified_unreplayed"
                counts["inconclusive_raw_changed_pairs"] += 1
            raw_blockers.append(_result_blocker(raw_equivalence))
        elif any(
            row is not None and row.get("status") == "falsified"
            for row in raw_completion
        ):
            raw_classification = "bounded_equivalent"
            raw_blockers.extend(
                _result_blocker(row)
                for row in raw_completion
                if row is not None and row.get("status") != "proven"
            )
            counts["bounded_changed_pairs"] += 1
        elif (
            raw_equivalence.get("status") == "valid"
            and raw_non_vacuity is not None
            and raw_non_vacuity.get("status") == "proven"
            and all(
                row is not None and row.get("status") == "proven"
                for row in raw_completion
            )
        ):
            raw_classification = "equivalent_under_raw_model"
            counts["raw_complete_changed_pairs"] += 1
        elif any(row.get("status") == "unsupported" for row in raw_results):
            raw_classification = "unsupported"
            raw_blockers.extend(
                _result_blocker(row)
                for row in raw_results
                if row.get("status") == "unsupported"
            )
            counts["unsupported_raw_changed_pairs"] += 1
        elif any(row.get("status") == "timeout" for row in raw_results):
            raw_classification = "timeout"
            raw_blockers.extend(
                _result_blocker(row)
                for row in raw_results
                if row.get("status") == "timeout"
            )
            counts["inconclusive_raw_changed_pairs"] += 1
        else:
            raw_classification = "inconclusive"
            raw_blockers.extend(_result_blocker(row) for row in raw_results)
            counts["inconclusive_raw_changed_pairs"] += 1

        ledger_classifications: list[dict[str, Any]] = []
        ledger_complete = False
        for model_id, results in sorted(ledger_groups.items()):
            by_kind = {
                str(row["obligation_kind"]): row for row in results
            }
            equivalence = by_kind.get("ledger_observational_equivalence")
            completions = [
                by_kind.get("old_program_completion"),
                by_kind.get("new_program_completion"),
            ]
            non_vacuity = by_kind.get("ledger_domain_non_vacuity")
            complete = bool(
                equivalence
                and equivalence.get("status") == "valid"
                and non_vacuity
                and non_vacuity.get("status") == "proven"
                and all(
                    row is not None and row.get("status") == "proven"
                    for row in completions
                )
            )
            ledger_complete = ledger_complete or complete
            ledger_classifications.append(
                {
                    "semantic_model_id": model_id,
                    "classification": (
                        "equivalent_under_ledger_model"
                        if complete
                        else "ledger_model_incomplete"
                    ),
                }
            )
        if ledger_complete:
            counts["ledger_complete_changed_pairs"] += 1
        if ledger_complete and raw_classification != "equivalent_under_raw_model":
            counts["ledger_only_changed_pairs"] += 1
        if ledger_complete and raw_classification in {
            "confirmed_non_equivalent",
            "blaster_falsified_unreplayed",
        }:
            counts["off_ledger_differences"] += 1
            final_classification = "off_ledger_difference"
        else:
            final_classification = raw_classification
        classifications.append(
            {
                "program_pair_id": pair_id,
                "changed": True,
                "classification": final_classification,
                "raw_classification": raw_classification,
                "ledger_classifications": ledger_classifications,
                "blocking_evidence_ids": sorted(set(raw_blockers)),
            }
        )
    raw_partition = (
        counts["raw_complete_changed_pairs"]
        + counts["bounded_changed_pairs"]
        + counts["confirmed_difference_changed_pairs"]
        + counts["unsupported_raw_changed_pairs"]
        + counts["inconclusive_raw_changed_pairs"]
    )
    counts["raw_partition_exhaustive"] = int(
        raw_partition == counts["changed_program_pairs"]
    )
    return classifications, counts


def derive_candidate_decisions(
    *,
    evidence_run_id: str,
    selected_policy: str,
    pair_classifications: Iterable[Mapping[str, Any]],
    task_results: Iterable[Mapping[str, Any]],
    source_results: Iterable[Mapping[str, Any]],
    counts: Mapping[str, Any],
    candidate_clean: bool,
    candidate_committed: bool,
    evidence_verified: bool,
    ci_provenance_valid: bool,
) -> dict[str, Any]:
    if selected_policy not in {"strict", "screening"}:
        raise ValueError("selected policy must be strict or screening")
    strict_blockers: set[str] = set()
    screening_blockers: set[str] = set()
    for pair in pair_classifications:
        classification = str(pair["classification"])
        blockers = set(pair.get("blocking_evidence_ids", [])) or {
            identity_hash(
                "program_pair_policy_blocker",
                {
                    "program_pair_id": pair["program_pair_id"],
                    "classification": classification,
                },
            )
        }
        if classification not in STRICT_POLICY_CONFIGURATION[
            "accepted_required_classifications"
        ]:
            strict_blockers.update(blockers)
        if classification not in SCREENING_POLICY_CONFIGURATION[
            "accepted_required_classifications"
        ]:
            screening_blockers.update(blockers)
    passing_tasks = {
        "benchmark_passed",
        "check_passed",
        "compile_passed",
        "configuration_passed",
        "documentation_passed",
        "equivalence_passed",
        "expected_negative_diagnostic",
        "not_applicable",
    }
    for task in task_results:
        if task.get("strict_relevance") is False:
            continue
        if task.get("classification") not in passing_tasks:
            blocker = str(
                task.get("blocking_evidence_id")
                or identity_hash(
                    "task_policy_blocker",
                    {
                        "task_id": task.get("task_id"),
                        "classification": task.get("classification"),
                    },
                )
            )
            strict_blockers.add(blocker)
            screening_blockers.add(blocker)
    for source in source_results:
        if source.get("inputs_verified") is not True:
            blocker = str(
                source.get("blocking_evidence_id")
                or identity_hash(
                    "source_input_blocker",
                    {"source_id": source.get("source_id")},
                )
            )
            strict_blockers.add(blocker)
            screening_blockers.add(blocker)

    strict_decision_id = release_decision_id(
        evidence_run_id_value=evidence_run_id,
        policy_name="strict",
        policy_schema_version=POLICY_SCHEMA_VERSION,
        policy_configuration=STRICT_POLICY_CONFIGURATION,
    )
    screening_decision_id = release_decision_id(
        evidence_run_id_value=evidence_run_id,
        policy_name="screening",
        policy_schema_version=POLICY_SCHEMA_VERSION,
        policy_configuration=SCREENING_POLICY_CONFIGURATION,
    )
    strict_decision = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "decision_id": strict_decision_id,
        "evidence_run_id": evidence_run_id,
        "policy": "strict",
        "policy_configuration": STRICT_POLICY_CONFIGURATION,
        "decision": "pass" if not strict_blockers else "fail",
        "blocking_evidence_ids": sorted(strict_blockers),
        "counts": dict(counts),
    }
    screening_decision = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "decision_id": screening_decision_id,
        "evidence_run_id": evidence_run_id,
        "policy": "screening",
        "policy_configuration": SCREENING_POLICY_CONFIGURATION,
        "decision": "pass" if not screening_blockers else "fail",
        "blocking_evidence_ids": sorted(screening_blockers),
        "publishable": False,
        "counts": dict(counts),
    }
    selected = (
        strict_decision if selected_policy == "strict" else screening_decision
    )
    publishable = bool(
        selected_policy == "strict"
        and strict_decision["decision"] == "pass"
        and candidate_clean
        and candidate_committed
        and evidence_verified
        and ci_provenance_valid
    )
    selected_decision_id = identity_hash(
        "selected_release_decision",
        {
            "evidence_run_id": evidence_run_id,
            "selected_policy": selected_policy,
            "policy_decision_id": selected["decision_id"],
        },
    )
    selected_decision = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "selected_decision_id": selected_decision_id,
        "evidence_run_id": evidence_run_id,
        "strict_decision_id": strict_decision_id,
        "screening_decision_id": screening_decision_id,
        "strict_decision": strict_decision["decision"],
        "screening_decision": screening_decision["decision"],
        "selected_policy": selected_policy,
        "selected_decision": selected["decision"],
        "blocking_evidence_ids": selected["blocking_evidence_ids"],
        "publishable": publishable,
        "evidence_suitability": (
            "release" if publishable else "development_only"
        ),
    }
    return {
        "strict": strict_decision,
        "screening": screening_decision,
        "selected": selected_decision,
    }
