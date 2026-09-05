"""T033: the versioned regimes dataset (feature 015, FR-020)."""

from __future__ import annotations

from pipeline import business_flow


class TestDataset:
    def test_v1_ships_the_three_named_regimes(self):
        dataset = business_flow.regimes_dataset()
        ids = {regime["id"] for regime in dataset["regimes"]}
        assert ids == {"gdpr", "ccpa", "hipaa"}
        assert dataset["version"] == "1"
        assert dataset["dataset_date"]

    def test_every_regime_has_obligations_and_category_signals(self):
        for regime in business_flow.regimes_dataset()["regimes"]:
            assert regime["name"]
            assert regime["obligations"], regime["id"]
            assert regime["regulated_data_categories"], regime["id"]
            for obligation in regime["obligations"]:
                assert obligation["id"].startswith(regime["id"] + "-")
                assert obligation["title"] and obligation["summary"]
                assert obligation["flow_patterns"]

    def test_detection_signals_drive_categories(self):
        dataset = business_flow.regimes_dataset()
        assert business_flow.detect_categories(
            "shop:src/app.py#signup_email", dataset
        ) == ["personal-data"]
        assert business_flow.detect_categories(
            "clinic:src/records.py#patient_diagnosis", dataset
        ) == ["health-data"]
        assert business_flow.detect_categories(
            "shop:src/util.py#hash_string", dataset
        ) == []  # no false proximity

    def test_wording_is_risk_framed_not_legal(self):
        """FR-021: obligations are phrased as expected flow shapes (potential risk),
        never as legal determinations."""
        for regime in business_flow.regimes_dataset()["regimes"]:
            for obligation in regime["obligations"]:
                assert "should" in obligation["summary"].lower()
                assert "must" not in obligation["summary"].lower()
