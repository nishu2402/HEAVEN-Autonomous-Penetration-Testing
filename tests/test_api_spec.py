"""Tests for spec-driven API surface discovery (heaven/vulnscan/api_spec).

Pure and deterministic — no network. Covers OpenAPI v2 + v3, Postman v2, GraphQL
introspection, concrete-URL expansion, and the authorization matrix planner +
analyser (BFLA and missing-authentication detection), and confirms the emitted
findings enrich to complete taxonomy.
"""

from __future__ import annotations

import asyncio

import pytest

from heaven.vulnscan import api_spec as A
from heaven.devsecops.vuln_kb import enrich_finding


# ── OpenAPI v3 ───────────────────────────────────────────────────────────────

_OAPI_V3 = {
    "openapi": "3.0.1",
    "info": {"title": "Shop", "version": "2.1"},
    "servers": [{"url": "https://api.shop.test/v2"}],
    "security": [{"bearer": []}],
    "paths": {
        "/orders/{orderId}": {
            "parameters": [{"in": "path", "name": "orderId"}],
            "get": {"operationId": "getOrder",
                    "parameters": [{"in": "query", "name": "expand"}]},
            "delete": {"operationId": "deleteOrder"},
        },
        "/health": {"get": {"operationId": "health", "security": []}},
        "/admin/users": {"post": {"operationId": "createUser",
                                  "requestBody": {"content": {}}}},
    },
}


def test_openapi_v3_parses_operations_and_security():
    spec = A.load_api_spec(_OAPI_V3)
    assert spec.fmt == "openapi"
    assert spec.title == "Shop" and spec.version == "2.1"
    assert spec.base_urls == ["https://api.shop.test/v2"]
    ops = {o.operation_id: o for o in spec.operations}
    assert set(ops) == {"getOrder", "deleteOrder", "health", "createUser"}
    # Path param collected from the shared path-item level.
    assert ops["getOrder"].path_params == ("orderId",)
    assert ops["getOrder"].query_params == ("expand",)
    # Global security applies…
    assert ops["getOrder"].requires_auth is True
    # …but an explicit `security: []` overrides it to public.
    assert ops["health"].requires_auth is False
    assert ops["createUser"].has_body is True


def test_openapi_to_urls_expands_templates_and_query():
    spec = A.load_api_spec(_OAPI_V3)
    urls = spec.to_urls()
    assert "https://api.shop.test/v2/orders/1?expand=1" in urls
    assert "https://api.shop.test/v2/health" in urls
    assert "https://api.shop.test/v2/admin/users" in urls
    # Base-url override replaces the spec's server.
    urls2 = spec.to_urls(base_url="http://127.0.0.1:8000")
    assert any(u.startswith("http://127.0.0.1:8000/orders/1") for u in urls2)


# ── OpenAPI v2 (Swagger) ─────────────────────────────────────────────────────

def test_swagger_v2_host_basepath_schemes():
    doc = {
        "swagger": "2.0",
        "host": "legacy.test", "basePath": "/api", "schemes": ["https", "http"],
        "paths": {"/ping": {"get": {"operationId": "ping"}}},
    }
    spec = A.load_api_spec(doc)
    assert spec.base_urls == ["https://legacy.test/api"]
    assert spec.to_urls() == ["https://legacy.test/api/ping"]


# ── Postman v2 ───────────────────────────────────────────────────────────────

def test_postman_collection_walks_folders_and_normalises_paths():
    doc = {
        "info": {"name": "Coll", "_postman_id": "x"},
        "item": [
            {"name": "folder", "item": [
                {"name": "get user", "request": {
                    "method": "GET",
                    "url": {"raw": "https://p.test/users/:id?full=1",
                            "path": ["users", ":id"],
                            "query": [{"key": "full", "value": "1"}]},
                    "auth": {"type": "bearer"}}},
            ]},
            {"name": "login", "request": {
                "method": "POST", "url": "https://p.test/login",
                "body": {"mode": "raw", "raw": "{}"}}},
        ],
    }
    spec = A.load_api_spec(doc)
    assert spec.fmt == "postman"
    ops = {o.operation_id: o for o in spec.operations}
    assert ops["get user"].path == "/users/{id}"      # :id → {id}
    assert ops["get user"].query_params == ("full",)
    assert ops["get user"].requires_auth is True       # auth block present
    assert ops["login"].has_body is True
    assert ops["login"].requires_auth is False
    assert "https://p.test" in spec.base_urls


# ── GraphQL introspection ────────────────────────────────────────────────────

def test_graphql_introspection_extracts_queries_and_mutations():
    doc = {"data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [
                {"name": "me", "args": []},
                {"name": "user", "args": [{"name": "id"}]}]},
            {"name": "Mutation", "fields": [
                {"name": "deleteUser", "args": [{"name": "id"}]}]},
        ],
    }}}
    spec = A.load_api_spec(doc, base_url="https://g.test")
    assert spec.fmt == "graphql"
    ids = {o.operation_id for o in spec.operations}
    assert ids == {"query.me", "query.user", "mutation.deleteUser"}
    assert all(o.method == "POST" and o.path == "/graphql" for o in spec.operations)
    assert spec.to_urls() == ["https://g.test/graphql"]


def test_unrecognised_spec_raises():
    with pytest.raises(ValueError):
        A.load_api_spec({"random": "object"})


# ── Authorization matrix ─────────────────────────────────────────────────────

def test_plan_auth_matrix_covers_roles_and_anonymous():
    spec = A.load_api_spec(_OAPI_V3)
    cases = A.plan_auth_matrix(spec, roles=["admin", "user"],
                               privileged_roles={"admin"})
    # Anonymous rows only for auth-required ops (getOrder, deleteOrder, createUser).
    anon = [c for c in cases if c.role == ""]
    assert {c.operation.operation_id for c in anon} == {
        "getOrder", "deleteOrder", "createUser"}
    # 'user' on an auth-required op is expected NOT allowed (admin is privileged).
    user_get = [c for c in cases
                if c.role == "user" and c.operation.operation_id == "getOrder"][0]
    assert user_get.expected_allowed is False
    admin_get = [c for c in cases
                 if c.role == "admin" and c.operation.operation_id == "getOrder"][0]
    assert admin_get.expected_allowed is True


def test_analyze_flags_missing_auth_for_anonymous_success():
    op = A.APIOperation("POST", "/admin/users", operation_id="createUser",
                        security=("bearer",))
    case = A.AuthMatrixCase(role="", operation=op, expected_allowed=False)
    hit = A.analyze_auth_result(case, 200)
    assert hit and hit["vuln_type"] == "api_broken_auth"
    # A 401/403 to anonymous is correct behaviour — no finding.
    assert A.analyze_auth_result(case, 401) is None


def test_analyze_flags_bfla_for_unprivileged_success():
    op = A.APIOperation("DELETE", "/orders/{orderId}", operation_id="deleteOrder",
                        security=("bearer",))
    case = A.AuthMatrixCase(role="user", operation=op, expected_allowed=False)
    hit = A.analyze_auth_result(case, 200)
    assert hit and hit["vuln_type"] == "api_bfla"
    # An expected-allowed role succeeding is fine.
    ok = A.AuthMatrixCase(role="admin", operation=op, expected_allowed=True)
    assert A.analyze_auth_result(ok, 200) is None


def test_run_auth_matrix_with_injected_runner():
    spec = A.load_api_spec(_OAPI_V3)
    cases = A.plan_auth_matrix(spec, roles=["user"], privileged_roles={"admin"})

    async def fake_request(role, op, url):
        # The API is broken: it lets a 'user' delete orders and lets anonymous
        # create users, but correctly 401s anonymous on the others.
        if op.operation_id == "deleteOrder" and role == "user":
            return 200
        if op.operation_id == "createUser" and role == "":
            return 200
        return 401 if role == "" else 403

    findings = asyncio.run(A.run_auth_matrix(cases, fake_request,
                                             base_url="http://127.0.0.1:8000"))
    kinds = sorted(f["vuln_type"] for f in findings)
    assert "api_bfla" in kinds
    assert "api_broken_auth" in kinds
    for f in findings:
        assert f.get("target", "").startswith("http://127.0.0.1:8000")


# ── Emitted findings enrich to taxonomy ──────────────────────────────────────

def test_auth_findings_enrich_to_taxonomy():
    op = A.APIOperation("DELETE", "/orders/{id}", security=("bearer",))
    bfla = A.analyze_auth_result(
        A.AuthMatrixCase(role="user", operation=op, expected_allowed=False), 200)
    miss = A.analyze_auth_result(
        A.AuthMatrixCase(role="", operation=op, expected_allowed=False), 200)
    for f in (bfla, miss):
        e = enrich_finding(f)
        assert e.get("cwe"), f
        assert "2025" in e.get("owasp", ""), f
        assert e.get("mitre_technique"), f
