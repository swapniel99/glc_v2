"""V9 compatibility shim — assert that the routes S9 and S10 client
code call against the V9 gateway exist with the same shape on glc_v1.

These tests do not exercise the upstream LLM calls (no live keys in
CI); they verify the route surface, OpenAPI schema, request validation,
and the listings endpoints return the expected V9 keys.
"""

from __future__ import annotations


def test_v9_routes_are_registered(app_client):
    openapi = app_client.get("/openapi.json").json()
    paths = set(openapi["paths"].keys())
    for p in [
        "/v1/chat",
        "/v1/chat/batch",
        "/v1/vision",
        "/v1/embed",
        "/v1/cost/by_agent",
        "/v1/providers",
        "/v1/capabilities",
        "/v1/status",
        "/v1/routers",
        "/v1/calls",
        "/v1/embedders",
    ]:
        assert p in paths, f"missing V9 route {p}"


def test_new_s11_routes_are_registered(app_client):
    openapi = app_client.get("/openapi.json").json()
    paths = set(openapi["paths"].keys())
    for p in [
        "/v1/transcribe",
        "/v1/speak",
        "/v1/control/kill",
        "/v1/control/pair",
        "/v1/control/pair/confirm",
        "/v1/control/presence",
    ]:
        assert p in paths


def test_v1_providers_shape_unchanged(app_client, install_token):
    headers = {"Authorization": f"Bearer {install_token}"}
    r = app_client.get("/v1/providers", headers=headers)
    assert r.status_code == 200
    body = r.json()
    # V9 shape: order, providers, shortcuts, limits, models
    for k in ("order", "providers", "shortcuts", "limits", "models"):
        assert k in body


def test_v1_status_shape_unchanged(app_client, install_token):
    headers = {"Authorization": f"Bearer {install_token}"}
    r = app_client.get("/v1/status", headers=headers)
    assert r.status_code == 200
    body = r.json()
    for k in ("order", "live", "today", "limits"):
        assert k in body


def test_v1_capabilities_returns_per_provider_caps(app_client, install_token):
    headers = {"Authorization": f"Bearer {install_token}"}
    r = app_client.get("/v1/capabilities", headers=headers)
    assert r.status_code == 200
    body = r.json()
    # Even with zero providers wired, the shape must be a dict.
    assert isinstance(body, dict)


def test_v1_cost_by_agent_returns_dict(app_client, install_token):
    headers = {"Authorization": f"Bearer {install_token}"}
    r = app_client.get("/v1/cost/by_agent", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, dict)


def test_read_endpoints_enforce_auth(app_client):
    endpoints = [
        "/v1/embedders",
        "/v1/cost/by_agent",
        "/v1/providers",
        "/v1/capabilities",
        "/v1/status",
        "/v1/routers",
        "/v1/calls",
    ]
    for url in endpoints:
        # Missing token -> 401
        r = app_client.get(url)
        assert r.status_code == 401, f"{url} did not return 401 on missing token"

        # Bad token -> 403
        r = app_client.get(url, headers={"Authorization": "Bearer badtoken"})
        assert r.status_code == 403, f"{url} did not return 403 on bad token"


def test_chat_requires_valid_bearer_token(app_client, install_token):
    payload = {"prompt": "hi", "provider": "no_such_provider"}
    assert app_client.post("/v1/chat", json=payload).status_code == 401
    assert app_client.post("/v1/chat", json=payload, headers={"Authorization": "Bearer badtoken"}).status_code == 403

    r = app_client.post("/v1/chat", json=payload, headers={"Authorization": f"Bearer {install_token}"})
    # If no providers wired at all, the validation hits 400; if they are
    # wired, the candidate list is empty (also 400).
    assert r.status_code in (400, 503)


def test_data_plane_endpoints_require_bearer_token(app_client):
    requests = [
        ("/v1/chat", {"prompt": "hi"}),
        ("/v1/chat/batch", {"calls": []}),
        ("/v1/vision", {"prompt": "hi", "image": "https://example.com/image.png"}),
        ("/v1/embed", {"text": "hi"}),
        ("/v1/transcribe", {"audio_b64": ""}),
        ("/v1/speak", {"text": "hi"}),
    ]
    for url, payload in requests:
        assert app_client.post(url, json=payload).status_code == 401, f"{url} did not require a bearer token"


def test_chat_request_minimal_body_validates(app_client, install_token):
    """The request body schema accepts a bare prompt with no provider."""
    # We don't care about the upstream call result — just that Pydantic
    # accepts the body shape (i.e., not a 422).
    r = app_client.post("/v1/chat", json={"prompt": "hi"}, headers={"Authorization": f"Bearer {install_token}"})
    assert r.status_code != 422


def test_embed_request_413_on_oversize(app_client, install_token):
    huge = "x" * 9000
    r = app_client.post("/v1/embed", json={"text": huge}, headers={"Authorization": f"Bearer {install_token}"})
    # 413 if embedders exist; 503 if none configured at all.
    assert r.status_code in (413, 503)


def test_healthz(app_client):
    r = app_client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_docs_disabled_in_production(monkeypatch):
    import importlib

    from fastapi.testclient import TestClient

    # Set env to production
    monkeypatch.setenv("GLC_ENV", "production")

    # Reload glc.main to apply environment changes
    import glc.main
    importlib.reload(glc.main)

    client = TestClient(glc.main.app)

    # Ensure docs endpoints are disabled (should return 404)
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404

    # Ensure index page does not mention /docs
    r = client.get("/")
    assert r.status_code == 200
    assert "/docs" not in r.text

    # Restore environment and reload to avoid breaking other tests
    monkeypatch.setenv("GLC_ENV", "development")
    importlib.reload(glc.main)
