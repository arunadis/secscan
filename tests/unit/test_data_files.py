"""Unit tests for the shipped knowledge bases (T017, Phase 2).

These four data files are the extensibility seam required by FR-013c, FR-022d and
FR-025b: adding a stack, rule, or control must be a data change. The tests below
therefore assert the *contracts* of the data — including the invariants that keep
Principle V (Honest Uncertainty) enforceable — rather than the current contents,
so extending a file does not break them.
"""

from __future__ import annotations

import json
from datetime import date

import pytest

from pipeline import applicability, controls, cwe, resources, stack_currency, stacks

DATA_FILES = ("applicability.json", "framework_controls.json", "stacks.json", "eol.json", "usage_patterns.json")


# --------------------------------------------------------------- shared shape


@pytest.mark.parametrize("name", DATA_FILES)
def test_every_data_file_is_versioned_and_dated(name: str) -> None:
    document = json.loads(resources.data_path(name).read_text())
    assert document["version"], f"{name} must carry a version"
    date.fromisoformat(document["dataset_date"])  # raises if malformed


@pytest.mark.parametrize("name", DATA_FILES)
def test_data_files_load_deterministically(name: str) -> None:
    """Same bytes in, same object out — twice (Principle I)."""
    path = resources.data_path(name)
    assert json.loads(path.read_text()) == json.loads(path.read_text())


# ------------------------------------------------------------- applicability


def test_applicability_rules_reference_known_cwes() -> None:
    for identifier in applicability.governed_cwes():
        assert identifier in cwe.known_cwes()
        for alternative in applicability.alternatives_for(identifier):
            assert alternative in cwe.known_cwes(), (
                f"{identifier} names alternative {alternative}, which is absent from "
                "the shipped taxonomy — the remap would be unrepresentable"
            )


def test_applicability_never_suppresses_on_an_unknown() -> None:
    """FR-013a/FR-015c: an unknown must never be a basis for ruling a class out."""
    governed = applicability.governed_cwes()[0]
    assert applicability.is_possible_on(governed, {"undetermined"}) == "undetermined"
    assert applicability.is_possible_on(governed, set()) == "undetermined"


def test_applicability_has_no_opinion_on_ungoverned_classes() -> None:
    """A class the relation does not govern is never disproved by it."""
    assert applicability.is_possible_on("CWE-89", {"browser-client"}) is True
    assert applicability.requires_any("CWE-89") == ()


def test_applicability_undetermined_cannot_satisfy_a_requirement() -> None:
    """Guarded in the loader: 'undetermined' in requires_any would invert the rule."""
    for identifier in applicability.governed_cwes():
        assert applicability.UNDETERMINED not in applicability.requires_any(identifier)


def test_applicability_encodes_the_benchmark_case() -> None:
    """The misclassification the independent review found must now be catchable."""
    assert applicability.is_possible_on("CWE-918", {"browser-client"}) is False
    assert applicability.is_possible_on("CWE-918", {"server-request-issuer"}) is True
    # FR-015a: a reachable sibling that does issue server-side requests keeps it.
    assert (
        applicability.is_possible_on("CWE-918", {"browser-client", "server-request-issuer"})
        is True
    )
    assert set(applicability.alternatives_for("CWE-918")) == {"CWE-20", "CWE-116"}


# --------------------------------------------------------- framework controls


def test_controls_state_escaping_default_explicitly() -> None:
    """FR-022c: presence of a framework is not evidence of a control."""
    for framework in controls.frameworks():
        assert isinstance(framework["escapes_by_default"], bool)


def test_controls_include_frameworks_that_do_not_escape_by_default() -> None:
    """Jinja2 and JSP are the counterexamples that make the flag necessary."""
    assert controls.escapes_by_default("jinja2") is False
    assert controls.escapes_by_default("jsp") is False
    assert controls.escapes_by_default("angular") is True


def test_unrecognized_framework_is_unknown_not_absent() -> None:
    """`None` (unassessed) must be distinguishable from `False` (determined)."""
    assert controls.escapes_by_default("no-such-framework") is None
    assert controls.framework("no-such-framework") is None
    assert controls.controls_for("no-such-framework", "CWE-79") == ()


def test_controls_mitigate_known_cwes_and_declare_bypasses() -> None:
    for framework in controls.frameworks():
        for control in framework["controls"]:
            assert control["mitigates"]
            for identifier in control["mitigates"]:
                assert identifier in cwe.known_cwes()
            assert control["bypasses"], (
                f"{control['id']} declares no bypass, so it could never be "
                "discredited (FR-022)"
            )


def test_bypass_syntaxes_are_deduped_and_sorted() -> None:
    syntaxes = controls.all_bypass_syntaxes()
    assert syntaxes == tuple(sorted(set(syntaxes)))
    assert "bypassSecurityTrustHtml" in syntaxes
    assert "dangerouslySetInnerHTML" in syntaxes


# ------------------------------------------------------------------- stacks


def test_grammar_backed_languages_match_the_loaded_grammars() -> None:
    """FR-025a/FR-030d scope: the descriptor set must not drift from reality.

    `stacks.json` is the single answer to "the languages the code model parses".
    If a grammar is added or removed without updating the descriptors, template
    and ecosystem coverage silently stops matching code coverage.
    """
    from pipeline import extract

    described = set(stacks.grammar_backed_languages())
    # Template grammars are excluded: they describe *how markup is parsed*, not a
    # code language with a package ecosystem. Requiring a "primary package
    # ecosystem for HTML" would be meaningless (research.md A1).
    loaded = set(extract.supported_languages()) - set(extract.TEMPLATE_LANGUAGES)
    assert loaded <= described, f"grammars with no stack descriptor: {loaded - described}"


def test_every_grammar_backed_language_has_a_template_form_and_ecosystem() -> None:
    for language in stacks.grammar_backed_languages():
        assert stacks.template_forms_for(language), f"{language} declares no template form"
        assert stacks.ecosystem_for(language), f"{language} declares no package ecosystem"


def test_languages_sharing_an_ecosystem_count_once() -> None:
    """FR-030d: five language entries span four ecosystems, not five."""
    languages = stacks.grammar_backed_languages()
    ecosystems = stacks.ecosystems_for_grammar_backed()
    assert len(ecosystems) < len(languages)
    assert stacks.ecosystem_for("typescript") == stacks.ecosystem_for("tsx") == "npm"


def test_non_grammar_backed_suffixes_impose_no_requirement() -> None:
    """`.sql` and `.tf` are enumerated but not grammar-backed (research.md A1)."""
    assert "sql" not in stacks.grammar_backed_languages()
    assert "terraform" not in stacks.grammar_backed_languages()


def test_tsx_uses_the_jsx_capable_grammar_entry_point() -> None:
    """The defect research.md A1 found: .tsx parsed with the non-JSX grammar."""
    assert stacks.language_entry("tsx")["grammar"].endswith("language_tsx")


def test_template_suffixes_map_to_forms() -> None:
    suffixes = stacks.template_suffixes()
    assert ".html" in suffixes
    assert "html" in suffixes[".html"]
    assert ".tsx" in suffixes and "jsx" in suffixes[".tsx"]


def test_file_classes_cover_the_benchmark_files() -> None:
    """The file classes whose absence changed a conclusion in the benchmark."""
    assert stacks.file_class_for("package.json") == "dependency-manifest"
    assert stacks.file_class_for("firebase.json") == "deploy-config"
    assert stacks.file_class_for("database.rules.json") == "datastore-rules"
    assert stacks.file_class_for("ngsw-config.json") == "client-cache-config"
    assert stacks.file_class_for("some_random_file.txt") is None


def test_every_ecosystem_declares_an_adapter_and_capability() -> None:
    for ecosystem in stacks.all_ecosystems():
        assert ecosystem["audit_adapter"]
        assert ecosystem["capability"] in (
            "native-advisory",
            "coordinates-plus-offline-match",
        )


# -------------------------------------------------------------- eol / currency


def test_staleness_is_reportable() -> None:
    """Spec Assumptions: stale support data must never read as current."""
    age, stale = stack_currency.staleness(stack_currency.dataset_date())
    assert age == 0 and stale is False
    threshold = stack_currency.staleness_threshold_days()
    far_future = date.fromordinal(stack_currency.dataset_date().toordinal() + threshold + 1)
    age, stale = stack_currency.staleness(far_future)
    assert stale is True and age > threshold


def test_unmapped_product_is_undetermined_not_supported() -> None:
    """Principle V: absence of data is never evidence of support."""
    status = stack_currency.status_for("definitely-not-a-package", "1.0.0")
    assert status.past_eol is None
    assert status.determined is False
    assert status.reason


def test_unknown_cycle_is_undetermined() -> None:
    status = stack_currency.status_for("nodejs", "999.0.0")
    assert status.past_eol is None
    assert "cycle" in (status.reason or "")


def test_cycle_without_published_eol_is_undetermined() -> None:
    status = stack_currency.status_for("react", "18.2.0", today=date(2026, 8, 30))
    assert status.past_eol is None
    assert status.reason == "no end-of-support date published"


def test_benchmark_stack_is_detected_as_past_support() -> None:
    """The exposure the review ranked #1 and the scan never assessed."""
    today = date(2026, 8, 30)
    for identifier, version in (
        ("@angular/core", "9.0.1"),
        ("typescript", "3.7.5"),
        ("rxjs", "6.5.4"),
    ):
        status = stack_currency.status_for(identifier, version, today=today)
        assert status.past_eol is True, f"{identifier} {version} should be past support"
        assert status.eol_date


def test_supported_version_is_not_flagged() -> None:
    status = stack_currency.status_for("nodejs", "22.1.0", today=date(2026, 8, 30))
    assert status.past_eol is False


def test_longest_matching_cycle_wins() -> None:
    """'3.10' must not be matched by the '3.1' prefix."""
    status = stack_currency.status_for("python", "3.10.4", today=date(2026, 8, 30))
    assert status.cycle == "3.10"
