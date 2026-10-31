from reachfix.depgraph import synthesis as synthesis_module
from reachfix.depgraph.synthesis import MAX_GRAPH_FACTS, build_evidence, chain, check_answer, synthesize_answer

ADVISORY = {"vulnerability_id": "GHSA-74fj-2j2h-c42q", "aliases": ["CVE-2022-0155"], "severity": "HIGH",
            "summary": "follow-redirects leaks headers", "source_url": "https://osv.dev/vulnerability/GHSA-74fj-2j2h-c42q"}


def exposure_row(version, depth, severity="HIGH", vuln=None, project="npm:axios@0.21.1"):
    path = [project] + [f"npm:mid{i}@1.0.0" for i in range(depth - 1)] + [version]
    return {**ADVISORY, "vulnerability_id": vuln or ADVISORY["vulnerability_id"], "severity": severity,
            "project": project, "lockfile_doc_id": "lockfile:npm:axios@0.21.1", "version_id": version,
            "path": path, "depth": depth, "fixed_in": ["npm:follow-redirects@1.14.7"]}


def exposure_result(rows, totals=None, total_results=None):
    return {"query": "q", "route": "relational", "executed_route": "relational", "pattern": "exposure",
            "projects": ["npm:axios@0.21.1"], "results": rows, "total_results": total_results or len(rows),
            "totals": totals or {}, "warnings": []}


def test_chain_uses_the_plans_readable_form():
    assert chain(["npm:axios@0.21.1", "npm:follow-redirects@1.13.1"]) == "axios@0.21.1 → depends_on → follow-redirects@1.13.1"


def test_exposure_evidence_tags_chains_and_uses_router_totals():
    totals = {"npm:axios@0.21.1": {"advisories": 7, "vulnerable_versions": 3, "by_severity": {"HIGH": 5, "LOW": 2},
                                   "max_depth": 4}}
    evidence = build_evidence(exposure_result([exposure_row("npm:follow-redirects@1.13.1", 1)], totals, 300))

    assert evidence["chains"] == ["axios@0.21.1 → depends_on → follow-redirects@1.13.1 "
                                  "[VULNERABLE: GHSA-74fj-2j2h-c42q / CVE-2022-0155, HIGH]"]
    assert "Fixed in: follow-redirects@1.14.7" in evidence["facts"][0]
    assert evidence["totals"][0] == "axios@0.21.1: 7 advisories on 3 vulnerable versions (5 high, 2 low); deepest at 4 hops."
    assert "1 most severe of 300" in evidence["totals"][1]


def test_exposure_facts_rank_worst_first_and_cap():
    rows = [exposure_row(f"npm:p{i}@1.0.0", 1, "LOW", vuln=f"GHSA-low{i}") for i in range(MAX_GRAPH_FACTS)]
    rows.append(exposure_row("npm:bad@1.0.0", 5, "CRITICAL", vuln="GHSA-crit"))
    evidence = build_evidence(exposure_result(rows))

    assert len(evidence["facts"]) == MAX_GRAPH_FACTS and "GHSA-crit" in evidence["facts"][0]
    assert any(f"{MAX_GRAPH_FACTS} most severe of {MAX_GRAPH_FACTS + 1}" in t for t in evidence["totals"])


def test_empty_exposure_says_none_known_not_safe():
    evidence = build_evidence(exposure_result([]))
    assert evidence["totals"] == ["No known vulnerable dependency found for axios@0.21.1 in this dataset."]


def test_neighbor_facts_label_advisories_with_their_cve():
    result = {"query": "q", "route": "relational", "executed_route": "relational", "pattern": "neighbors",
              "advisories": [ADVISORY], "results": [{
                  "source": {"node_id": "GHSA-74fj-2j2h-c42q", "name": "GHSA-74fj-2j2h-c42q"},
                  "node_id": "npm:follow-redirects@1.14.7", "name": "follow-redirects@1.14.7",
                  "relation": "FIXED_IN", "direction": "out", "provenance": [], "properties": {}}]}
    evidence = build_evidence(result)

    assert evidence["facts"] == ["GHSA-74fj-2j2h-c42q / CVE-2022-0155 --FIXED_IN--> follow-redirects@1.14.7"]
    assert check_answer("CVE-2022-0155 is fixed in 1.14.7 [G1].", evidence)["ungrounded_ids"] == []


def test_check_answer_flags_invented_ids_and_markers():
    evidence = build_evidence(exposure_result([exposure_row("npm:follow-redirects@1.13.1", 1)]))
    checks = check_answer("Exposed to CVE-2022-0155 [G1] and CVE-2099-0001 [G7, A2].", evidence)

    assert checks["ungrounded_ids"] == ["CVE-2099-0001"]
    assert checks["unknown_markers"] == ["A2", "G7"] and checks["cited_markers"] == ["G1"]


def test_synthesize_normalizes_unicode_hyphens_and_fullwidth_brackets(monkeypatch):
    raw = "Yes: GHSA" + "‑" + "74fj" + "‑" + "2j2h" + "‑" + "c42q 【G1】 – high."
    monkeypatch.setattr(synthesis_module, "generate_text", lambda *a, **k: raw)

    out = synthesize_answer(exposure_result([exposure_row("npm:follow-redirects@1.13.1", 1)]), client=None)

    assert out["answer"] == "Yes: GHSA-74fj-2j2h-c42q [G1] – high."  # the en dash is left alone
    assert out["checks"] == {"unknown_markers": [], "ungrounded_ids": [], "ungrounded_versions": [], "cited_markers": ["G1"]}
    assert out["citations"]["advisories"][0]["url"] == ADVISORY["source_url"]


def test_chunks_become_A_markers_with_previews(monkeypatch):
    monkeypatch.setattr(synthesis_module, "generate_text", lambda *a, **k: "See [A1].")
    chunk = {"chunk_id": "GHSA-x::0", "doc_id": "GHSA-x", "aliases": ["CVE-2020-9"], "summary": "s",
             "affected_packages": ["x"], "source_url": "u", "text": "t" * 1000}
    result = {"query": "q", "route": "semantic", "executed_route": "semantic", "chunks": [chunk], "warnings": []}

    out = synthesize_answer(result, client=None)

    [cite] = out["citations"]["chunks"]
    assert cite["marker"] == "A1" and len(cite["snippet"]) == 300
    assert check_answer("CVE-2020-9 [A1]", build_evidence(result))["ungrounded_ids"] == []


def test_spaced_package_versions_are_rejoined(monkeypatch):
    monkeypatch.setattr(synthesis_module, "generate_text", lambda *a, **k: "jws @3.2.2 and semver @ 5.6.0 are affected; email me @ noon [" + chr(0x200B) + "G1]")
    out = synthesize_answer(exposure_result([exposure_row("npm:follow-redirects@1.13.1", 1)]), client=None)
    assert out["answer"] == "jws@3.2.2 and semver@5.6.0 are affected; email me @ noon [G1]"


def remediation_result():
    plan = {"status": "blocked", "package": "minimatch", "lowest_safe_version": "3.0.5", "target_version": "3.0.5"}
    row = {"project": "npm:mocha@8.4.0", "lockfile_doc_id": "lockfile:npm:mocha@8.4.0", "version_id": "npm:minimatch@3.0.4",
           "path": ["npm:mocha@8.4.0", "npm:minimatch@3.0.4"], "depth": 1, "advisories": [ADVISORY], "plan": plan,
           "actions": ['mocha@8.4.0 declares minimatch "3.0.4".', "Upgrade the project: mocha 8.4.0 -> 10.6.0."],
           "resolved": True}
    return {"query": "q", "route": "relational", "executed_route": "relational", "pattern": "remediation",
            "executed_pattern": "remediation", "results": [row], "total_results": 1, "warnings": [],
            "totals": {"copies": 1, "by_status": {"blocked": 1}, "fully_resolved": 1, "projects": ["npm:mocha@8.4.0"]}}


def test_remediation_facts_carry_the_plan_and_router_totals():
    evidence = build_evidence(remediation_result())

    [fact] = evidence["facts"]
    assert fact.startswith("In mocha@8.4.0: mocha@8.4.0 → depends_on → minimatch@3.0.4 [VULNERABLE: GHSA-74fj-2j2h-c42q")
    assert "excludes every fixed version" in fact and "minimatch@3.0.5" in fact and "mocha 8.4.0 -> 10.6.0" in fact
    assert evidence["totals"][0] == ("1 vulnerable dependency copy planned across mocha@8.4.0: "
                                     "a dependent's declared range excludes every fixed version: 1.")
    assert [a["vulnerability_id"] for a in evidence["advisories"]] == ["GHSA-74fj-2j2h-c42q"]


def test_remediation_fact_says_why_the_lowest_fix_is_skipped():
    result = remediation_result()
    result["results"][0]["plan"].update(target_version="3.0.8", lowest_safe_still_affected_by=["GHSA-b", "GHSA-c"])
    [fact] = build_evidence(result)["facts"]
    assert ("Lowest version outside every targeted advisory's range: minimatch@3.0.5, but it is still affected by "
            "2 other advisories in this dataset, so the plan targets minimatch@3.0.8 instead.") in fact


def test_check_answer_flags_versions_the_evidence_never_gives():
    evidence = build_evidence(remediation_result())
    checks = check_answer("Upgrade to mocha@10.6.0 [G1]; minimatch@3.0.5 is fixed, not minimatch@3.1.2.", evidence)
    assert checks["ungrounded_versions"] == ["minimatch@3.1.2"]
    assert check_answer("Scoped names work: @babel/core@7.0.0 [G1].", evidence)["ungrounded_versions"] == ["@babel/core@7.0.0"]


def test_synthesize_joins_versions_spaced_with_narrow_no_break_spaces(monkeypatch):
    monkeypatch.setattr(synthesis_module, "generate_text", lambda *a, **k: "Upgrade express\u202f@\u202f4.22.0 [G1].")
    out = synthesize_answer(remediation_result(), client=None)
    assert out["answer"] == "Upgrade express@4.22.0 [G1]."


def test_synthesize_strips_padding_inside_citation_brackets(monkeypatch):
    monkeypatch.setattr(synthesis_module, "generate_text",
                        lambda *a, **k: "Yes [ G1 ]. Upgrade [ G1, A2 ]; see [G1 ] and [ other text ].")
    out = synthesize_answer(remediation_result(), client=None)
    assert out["answer"] == "Yes [G1]. Upgrade [G1, A2]; see [G1] and [ other text ]."


def test_synthesize_drops_citations_of_the_totals(monkeypatch):
    monkeypatch.setattr(synthesis_module, "generate_text",
                        lambda *a, **k: "1 copy, fixable without an override [Exact totals]. Upgrade [G1] [ exact totals ].")
    out = synthesize_answer(remediation_result(), client=None)
    assert out["answer"] == "1 copy, fixable without an override. Upgrade [G1]."


def no_llm(*a, **k):
    raise AssertionError("a declined question must not call the LLM")


def test_off_topic_is_declined_without_an_llm_call(monkeypatch):
    monkeypatch.setattr(synthesis_module, "generate_text", no_llm)
    result = {"query": "write me a poem", "route": "off_topic", "executed_route": "off_topic", "warnings": []}

    out = synthesize_answer(result, client=None)

    assert out["declined"] == "off_topic" and out["answer"] == synthesis_module.DECLINED_ANSWERS["off_topic"]
    assert out["checks"] == {"unknown_markers": [], "ungrounded_ids": [], "ungrounded_versions": [], "cited_markers": []}


def test_semantic_with_no_chunks_left_is_declined(monkeypatch):
    monkeypatch.setattr(synthesis_module, "generate_text", no_llm)
    result = {"query": "q", "route": "semantic", "executed_route": "semantic", "chunks": [], "warnings": ["w"]}
    out = synthesize_answer(result, client=None)
    assert out["declined"] == "no_match" and out["warnings"] == ["w"]


def test_answered_questions_are_not_declined(monkeypatch):
    monkeypatch.setattr(synthesis_module, "generate_text", lambda *a, **k: "Yes [G1].")
    assert synthesize_answer(exposure_result([exposure_row("npm:follow-redirects@1.13.1", 1)]), client=None)["declined"] is None
