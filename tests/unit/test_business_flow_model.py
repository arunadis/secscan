"""T017: deterministic business-flow reconstruction (feature 015, FR-006/015/016)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline import business_flow
from pipeline.state import ArtifactStore


def _node(node_id: str, *, repo: str, path: str, type: str = "function",
          symbol: str | None = None, route: str | None = None,
          annotations: list[str] | None = None) -> dict:
    node = {
        "id": node_id,
        "repo": repo,
        "path": path,
        "type": type,
        "annotations": annotations or [],
    }
    if symbol:
        node["symbol"] = symbol
    if route:
        node["route"] = route
    return node


def _edge(source: str, target: str, kind: str, **extra: object) -> dict:
    return {"from": source, "to": target, "type": kind, **extra}


def single_repo_graph() -> dict:
    """The flow-app shape: seeded order flow plus a safe authenticated profile."""
    return {
        "nodes": [
            _node("shop:src/app.py#@/order/start", repo="shop", path="src/app.py",
                  type="endpoint", symbol="order_start", route="/order/start",
                  annotations=["trust_boundary", "user_controlled_input"]),
            _node("shop:src/app.py#order_start", repo="shop", path="src/app.py",
                  symbol="order_start"),
            _node("shop:src/app.py#@/order/apply-staff-discount", repo="shop",
                  path="src/app.py", type="endpoint",
                  symbol="order_apply_staff_discount",
                  route="/order/apply-staff-discount",
                  annotations=["trust_boundary", "user_controlled_input"]),
            _node("shop:src/app.py#order_apply_staff_discount", repo="shop",
                  path="src/app.py", symbol="order_apply_staff_discount"),
            _node("shop:<datastore>#orders", repo="shop", path="<datastore>",
                  type="datastore", symbol="orders"),
            _node("shop:src/app.py#@/profile", repo="shop", path="src/app.py",
                  type="endpoint", symbol="profile_view", route="/profile",
                  annotations=["trust_boundary", "user_controlled_input",
                               "authentication_required"]),
            _node("shop:src/app.py#profile_view", repo="shop", path="src/app.py",
                  symbol="profile_view", annotations=["authentication_required"]),
        ],
        "edges": [
            _edge("shop:src/app.py#@/order/start", "shop:src/app.py#order_start", "handler"),
            _edge("shop:src/app.py#@/order/apply-staff-discount",
                  "shop:src/app.py#order_apply_staff_discount", "handler"),
            _edge("shop:src/app.py#order_apply_staff_discount",
                  "shop:<datastore>#orders", "writes"),
            _edge("shop:src/app.py#@/profile", "shop:src/app.py#profile_view", "handler"),
        ],
    }


def workspace(members, integrations=None):
    return {
        "id": "ws-test",
        "source": "auto-discovered",
        "members": [{"name": name, "path": name} for name in members],
        "integrations": integrations or [],
    }


@pytest.fixture
def store(tmp_path: Path) -> ArtifactStore:
    return ArtifactStore(tmp_path)


class TestReconstruction:
    def test_one_flow_per_entry_point(self, store: ArtifactStore):
        doc = business_flow.build_flows(store, workspace(["shop"]), single_repo_graph())
        assert len(doc["flows"]) == 3
        names = sorted(flow["name"] for flow in doc["flows"])
        assert names == ["/order/apply-staff-discount", "/order/start", "/profile"]
        assert store.exists("business-flows.json")

    def test_steps_are_ordered_entry_first(self, store: ArtifactStore):
        doc = business_flow.build_flows(store, workspace(["shop"]), single_repo_graph())
        discount = next(
            f for f in doc["flows"] if f["name"] == "/order/apply-staff-discount"
        )
        assert discount["steps"][0]["operation"] == "entry"
        assert any(step["operation"] == "mutation" for step in discount["steps"])

    def test_actor_declared_from_annotations(self, store: ArtifactStore):
        doc = business_flow.build_flows(store, workspace(["shop"]), single_repo_graph())
        profile = next(f for f in doc["flows"] if f["name"] == "/profile")
        assert profile["actor"]["kind"] == "authenticated"
        assert profile["actor"]["determination"] == "declared"
        assert not profile["partial"]

    def test_anonymous_actor_is_inferred_not_assumed_declared(self, store: ArtifactStore):
        doc = business_flow.build_flows(store, workspace(["shop"]), single_repo_graph())
        order = next(f for f in doc["flows"] if f["name"] == "/order/start")
        assert order["actor"]["kind"] == "anonymous"
        assert order["actor"]["determination"] == "inferred"
        assert not order["partial"]

    def test_role_without_named_role_is_undetermined(self, store: ArtifactStore):
        graph = single_repo_graph()
        for node in graph["nodes"]:
            if node["id"] == "shop:src/app.py#@/order/start":
                node["annotations"].append("authorization_required")
        doc = business_flow.build_flows(store, workspace(["shop"]), graph)
        order = next(f for f in doc["flows"] if f["name"] == "/order/start")
        assert order["actor"]["kind"] == "role"
        assert order["actor"]["determination"] == "undetermined"
        assert order["partial"]
        assert "actor-undetermined" in order["gap_reasons"]
        assert {
            entry["flow_id"]: entry["gap_reasons"]
            for entry in doc["coverage"]["partial"]
        }[order["id"]] == ["actor-undetermined"]

    def test_stable_ids_across_runs(self, store: ArtifactStore):
        first = business_flow.build_flows(store, workspace(["shop"]), single_repo_graph())
        second = business_flow.build_flows(
            store, workspace(["shop"]), single_repo_graph()
        )
        assert [f["id"] for f in first["flows"]] == [f["id"] for f in second["flows"]]


def _client_file_node(repo: str, hosts: list[str]) -> dict:
    """A caller file that talks to the given hosts (enricher-derived)."""
    node = _node(
        f"{repo}:src/client.py", repo=repo, path="src/client.py", type="file",
        annotations=["external_system"] if hosts else [],
    )
    if hosts:
        node["outbound_hosts"] = hosts
    return node


class TestCrossRepoStitching:
    def test_declared_integration_stitches_steps(self, store: ArtifactStore):
        graph = {
            "nodes": [
                _client_file_node("web", ["api"]),
                _node("api:src/orders.py#@POST /v1/orders", repo="api",
                      path="src/orders.py", type="endpoint", symbol="create_order",
                      route="/v1/orders",
                      annotations=["trust_boundary", "user_controlled_input"]),
                _node("api:src/orders.py#create_order", repo="api",
                      path="src/orders.py", symbol="create_order"),
            ],
            "edges": [
                _edge("api:src/orders.py#@POST /v1/orders",
                      "api:src/orders.py#create_order", "handler"),
            ],
        }
        declared = [
            {
                "from_repo": "web",
                "to_repo": "api",
                "type": "sync-api",
                "endpoints_or_channels": ["POST /v1/orders"],
                "declared": True,
            }
        ]
        doc = business_flow.build_flows(
            store, workspace(["web", "api"], declared), graph
        )
        flow = next(
            f for f in doc["flows"] if f["name"] == "src/client.py"
        )
        repos = {step["node_id"].split(":", 1)[0] for step in flow["steps"]}
        assert repos == {"web", "api"}  # FR-015: stitched, repo-attributed
        legs = [s["integration_leg"] for s in flow["steps"] if "integration_leg" in s]
        assert legs == [{"type": "sync-api", "target_repo": "api"}]
        assert not flow["partial"]

    def test_undeclared_hop_makes_flow_partial(self, store: ArtifactStore):
        graph = {
            "nodes": [
                _client_file_node("web", ["worker"]),
                _node("worker:src/jobs.py#@POST /jobs", repo="worker",
                      path="src/jobs.py", type="endpoint", symbol="run_job",
                      route="/jobs",
                      annotations=["trust_boundary", "user_controlled_input"]),
            ],
            "edges": [],
        }
        doc = business_flow.build_flows(
            store, workspace(["web", "worker"]), graph
        )
        flow = next(f for f in doc["flows"] if f["name"] == "src/client.py")
        assert flow["partial"]
        assert flow["gap_reasons"] == ["integration-undeclared"]
        # The undeclared repo's steps MUST NOT be stitched in (FR-016).
        assert all(
            not step["node_id"].startswith("worker:") for step in flow["steps"]
        )

    def test_third_party_host_is_not_a_hop(self, store: ArtifactStore):
        graph = {"nodes": [_client_file_node("web", ["cdn.thirdparty.example"])],
                 "edges": []}
        doc = business_flow.build_flows(
            store, workspace(["web"]), graph
        )
        flow = doc["flows"][0]
        assert not flow["partial"]
        assert all(step["node_id"].startswith("web:") for step in flow["steps"])
