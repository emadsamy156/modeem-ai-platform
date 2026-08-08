"""Phase 2C tests — secure Odoo connectivity detection.

No real servers are contacted: network behavior is mocked at the httpx
transport layer (httpx.MockTransport) or the connector layer.
"""

import ipaddress
import json
import uuid
import xmlrpc.client

import httpx
import pytest

from app.integrations.odoo import connector, security
from app.integrations.odoo import http as safe_http
from app.integrations.odoo.errors import SAFE_ERROR_CODES, ConnectorError
from app.integrations.odoo.schemas import TestOutcome
from app.models import AuditLog, Connection
from tests.test_auth_security import _client, _csrf, _login
from tests.test_connections import SECRET, TestingSession, _create


def _xmlrpc_response(value) -> bytes:
    return xmlrpc.client.dumps((value,), methodresponse=True).encode()


def _version_payload(major: int) -> dict:
    return {
        "server_version": f"{major}.0",
        "server_version_info": [major, 0, 0, "final", 0, ""],
        "server_serie": f"{major}.0",
        "protocol_version": 1,
    }


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )


def _make_handler(*, major=18, auth_uid=7, enterprise_count=0, json2_status=None):
    """Standard fake Odoo server handler."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/xmlrpc/2/common"):
            params, method = xmlrpc.client.loads(request.content.decode())
            if method == "version":
                return httpx.Response(200, content=_xmlrpc_response(_version_payload(major)))
            if method == "authenticate":
                _db, _login_v, secret, _ = params
                if secret == SECRET or secret == "valid-api-key":
                    return httpx.Response(200, content=_xmlrpc_response(auth_uid))
                return httpx.Response(200, content=_xmlrpc_response(False))
        if url.endswith("/xmlrpc/2/object"):
            return httpx.Response(200, content=_xmlrpc_response(enterprise_count))
        if "/json/2/" in url:
            if json2_status is not None:
                return httpx.Response(json2_status, json={"error": "denied"})
            auth = request.headers.get("Authorization", "")
            if auth == "bearer valid-api-key":
                return httpx.Response(200, json=0)
            return httpx.Response(401, json={"error": "unauthorized"})
        return httpx.Response(404)

    return handler


@pytest.fixture()
def allow_outbound(monkeypatch):
    """Bypass DNS/IP checks for pure transport tests (tested separately)."""
    monkeypatch.setattr(
        security, "enforce_outbound_policy", lambda url, environment: None
    )


@pytest.fixture()
def mock_transport(monkeypatch, allow_outbound):
    """Route the connector's client through a fake Odoo server."""
    state = {"handler": _make_handler()}
    monkeypatch.setattr(
        safe_http, "build_client", lambda: _mock_client(lambda r: state["handler"](r))
    )
    return state


def _run_test(auth_mode="auto", login="user", secret=SECRET, database="db1"):
    return connector.test_connection(
        base_url="https://odoo.example.com",
        database=database,
        auth_mode=auth_mode,
        login=login,
        secret=secret,
        environment="development",
    )


# --- 1-3: version detection ---------------------------------------------------


@pytest.mark.parametrize("major", [16, 18, 19])
def test_version_detection(mock_transport, major):
    mock_transport["handler"] = _make_handler(major=major)
    out = _run_test()
    assert out.success is True
    assert out.odoo_version == f"{major}.0"
    assert out.odoo_major == major


# --- 4-5: legacy auth -----------------------------------------------------------


def test_legacy_password_authentication(mock_transport):
    out = _run_test(auth_mode="password", secret=SECRET)
    assert out.success and out.transport == "xmlrpc"


def test_legacy_api_key_authentication(mock_transport):
    """API keys usable in the password position on Odoo 16/18."""
    mock_transport["handler"] = _make_handler(major=16)
    out = _run_test(auth_mode="api_key", secret="valid-api-key")
    assert out.success and out.transport == "xmlrpc"


# --- 6-8: transport selection ---------------------------------------------------


def test_odoo19_json2_selected_for_api_key(mock_transport):
    mock_transport["handler"] = _make_handler(major=19)
    out = _run_test(auth_mode="api_key", secret="valid-api-key")
    assert out.success and out.transport == "json2"
    assert out.capabilities.get("json2") is True


def test_odoo19_password_mode_stays_legacy(mock_transport):
    mock_transport["handler"] = _make_handler(major=19)
    out = _run_test(auth_mode="password", secret=SECRET)
    assert out.success and out.transport == "xmlrpc"


def test_auto_mode_never_sends_bearer(mock_transport):
    """auto must not guess the secret is an API key / JSON-2 bearer token."""
    seen_bearer = []
    base = _make_handler(major=19)

    def spy(request: httpx.Request) -> httpx.Response:
        if "/json/2/" in str(request.url):
            seen_bearer.append(request.headers.get("Authorization"))
        return base(request)

    mock_transport["handler"] = spy
    out = _run_test(auth_mode="auto", secret=SECRET)
    assert out.success and out.transport == "xmlrpc"
    assert seen_bearer == []  # no JSON-2 request was ever made


def test_json2_unavailable_falls_back_to_legacy(mock_transport):
    mock_transport["handler"] = _make_handler(major=19, json2_status=404)
    out = _run_test(auth_mode="api_key", secret="valid-api-key")
    assert out.success and out.transport == "xmlrpc"
    assert out.capabilities.get("json2") is False
    assert out.capabilities.get("json2_fallback") == "legacy_xmlrpc"


# --- 9-10: version handling ------------------------------------------------------


def test_unknown_major_handled_by_capabilities(mock_transport):
    mock_transport["handler"] = _make_handler(major=21)
    out = _run_test()
    assert out.success is True
    assert out.odoo_major == 21
    assert out.capabilities.get("version_support") == "best_effort"


def test_invalid_version_response_rejected(mock_transport):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=_xmlrpc_response({"something": "else"})
        )

    mock_transport["handler"] = handler
    out = _run_test()
    assert out.success is False
    assert out.error_code == "unsupported_response"


# --- 11-12: failure safety --------------------------------------------------------


def test_authentication_failure_safe_code(mock_transport):
    out = _run_test(secret="wrong-secret")
    assert out.success is False
    assert out.error_code == "authentication_failed"
    assert out.error_code in SAFE_ERROR_CODES


def test_raw_upstream_error_never_leaks(mock_transport):
    marker = "SUPER-SECRET-UPSTREAM-TRACEBACK-XYZ"

    def handler(request: httpx.Request) -> httpx.Response:
        fault = xmlrpc.client.dumps(
            xmlrpc.client.Fault(1, f"Traceback: {marker}"), methodresponse=True
        )
        return httpx.Response(200, content=fault.encode())

    mock_transport["handler"] = handler
    out = _run_test()
    assert out.success is False
    assert out.error_code in SAFE_ERROR_CODES
    assert marker not in json.dumps(out.__dict__, default=str)


# --- SSRF / outbound policy (20-25) ------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8069",
        "http://127.0.0.1:8069",
        "http://[::1]:8069",
    ],
)
def test_loopback_destinations_blocked(url):
    with pytest.raises(ConnectorError) as exc:
        security.enforce_outbound_policy(url, environment="development")
    assert exc.value.code == "blocked_destination"


@pytest.mark.parametrize(
    "ip",
    ["10.0.0.5", "172.16.1.1", "192.168.1.10", "169.254.169.254", "169.254.0.9"],
)
def test_private_and_metadata_ips_blocked(ip):
    assert security._is_blocked_ip(ipaddress.ip_address(ip)) is True


def test_private_hostname_blocked(monkeypatch):
    monkeypatch.setattr(
        security.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("192.168.0.10", 443))],
    )
    with pytest.raises(ConnectorError) as exc:
        security.enforce_outbound_policy(
            "https://internal.example.com", environment="development"
        )
    assert exc.value.code == "blocked_destination"


def test_mixed_dns_with_private_ip_blocked(monkeypatch):
    monkeypatch.setattr(
        security.socket,
        "getaddrinfo",
        lambda *a, **k: [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("10.0.0.5", 443)),
        ],
    )
    with pytest.raises(ConnectorError) as exc:
        security.enforce_outbound_policy(
            "https://mixed.example.com", environment="development"
        )
    assert exc.value.code == "blocked_destination"


def test_dns_error_maps_to_safe_code(monkeypatch):
    def boom(*a, **k):
        raise security.socket.gaierror("nope")

    monkeypatch.setattr(security.socket, "getaddrinfo", boom)
    out = connector.test_connection(
        base_url="https://does-not-resolve.example.invalid",
        database="db",
        auth_mode="auto",
        login="u",
        secret="s",
        environment="development",
    )
    assert out.success is False
    assert out.error_code == "dns_resolution_failed"


# --- 26-28: client hardening --------------------------------------------------------


def test_redirects_not_followed(allow_outbound, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

    monkeypatch.setattr(safe_http, "build_client", lambda: _mock_client(handler))
    out = _run_test()
    assert out.success is False
    assert out.error_code in SAFE_ERROR_CODES


def test_client_config_hardened():
    client = safe_http.build_client()
    try:
        assert client.follow_redirects is False
        assert client.trust_env is False
        assert client.headers["User-Agent"].startswith("Modeem-AI-Platform/")
    finally:
        client.close()
    # No API exists to disable TLS verification: build_client takes no args.
    import inspect

    assert inspect.signature(safe_http.build_client).parameters == {}
    assert "verify=True" in inspect.getsource(safe_http.build_client)


def test_timeout_maps_to_safe_error(allow_outbound, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("boom")

    monkeypatch.setattr(safe_http, "build_client", lambda: _mock_client(handler))
    out = _run_test()
    assert out.success is False
    assert out.error_code == "connection_timeout"


# --- Endpoint tests (13-19, 30-32) ----------------------------------------------------


def _stub_outcome(monkeypatch, outcome: TestOutcome):
    import app.integrations.odoo.connector as conn_mod

    monkeypatch.setattr(conn_mod, "test_connection", lambda **kw: outcome)


_SUCCESS = TestOutcome(
    success=True,
    odoo_version="18.0",
    odoo_major=18,
    edition="community",
    transport="xmlrpc",
    capabilities={"legacy_xmlrpc": True},
)


def test_endpoint_success_persists_metadata(roles_seed, monkeypatch):
    _stub_outcome(monkeypatch, _SUCCESS)
    client = _client()
    _login(client, "owner@example.com")
    cid = _create(client).json()["id"]
    res = client.post(f"/api/v1/connections/{cid}/test", headers=_csrf(client))
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    assert body["odoo_version"] == "18.0"
    assert body["transport"] == "xmlrpc"
    assert SECRET not in res.text

    db = TestingSession()
    conn = db.get(Connection, uuid.UUID(cid))
    assert conn.last_test_status == "success"
    assert conn.last_tested_at is not None
    assert conn.detected_odoo_version == "18.0"
    assert conn.detected_odoo_major == 18
    assert conn.selected_transport == "xmlrpc"
    assert conn.last_test_error_code is None
    assert json.loads(conn.capabilities_json)["legacy_xmlrpc"] is True
    db.close()


def test_endpoint_failure_preserves_previous_metadata(roles_seed, monkeypatch):
    client = _client()
    _login(client, "owner@example.com")
    cid = _create(client).json()["id"]
    _stub_outcome(monkeypatch, _SUCCESS)
    assert client.post(f"/api/v1/connections/{cid}/test", headers=_csrf(client)).status_code == 200

    _stub_outcome(
        monkeypatch, TestOutcome(success=False, error_code="server_unreachable")
    )
    res = client.post(f"/api/v1/connections/{cid}/test", headers=_csrf(client))
    assert res.status_code == 200
    assert res.json()["success"] is False
    assert res.json()["error_code"] == "server_unreachable"

    db = TestingSession()
    conn = db.get(Connection, uuid.UUID(cid))
    assert conn.last_test_status == "error"
    assert conn.last_test_error_code == "server_unreachable"
    # Previously detected good metadata is preserved.
    assert conn.detected_odoo_version == "18.0"
    assert conn.selected_transport == "xmlrpc"
    db.close()


def test_edition_unknown_does_not_fail_connection(mock_transport):
    """Edition check failing → unknown, but the test still succeeds."""

    base = _make_handler(major=18)

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/xmlrpc/2/object"):
            fault = xmlrpc.client.dumps(
                xmlrpc.client.Fault(3, "Access Denied"), methodresponse=True
            )
            return httpx.Response(200, content=fault.encode())
        return base(request)

    mock_transport["handler"] = handler
    out = _run_test()
    assert out.success is True
    assert out.edition == "unknown"


def test_endpoint_credentials_never_in_response_or_audit(roles_seed, monkeypatch):
    _stub_outcome(monkeypatch, _SUCCESS)
    client = _client()
    _login(client, "owner@example.com")
    cid = _create(client).json()["id"]
    res = client.post(f"/api/v1/connections/{cid}/test", headers=_csrf(client))
    assert SECRET not in res.text
    assert "Authorization" not in res.text
    db = TestingSession()
    for entry in db.query(AuditLog).all():
        dump = str(entry.metadata_json)
        assert SECRET not in dump
        assert "password_or_api_key" not in dump
    audit = (
        db.query(AuditLog)
        .filter(AuditLog.action == "connection.test_succeeded")
        .one()
    )
    assert audit.resource_id == cid
    db.close()


def test_endpoint_cross_tenant_404(roles_seed, monkeypatch):
    _stub_outcome(monkeypatch, _SUCCESS)
    client_a = _client()
    _login(client_a, "owner@example.com")
    cid = _create(client_a).json()["id"]
    client_b = _client()
    _login(client_b, "owner-b@example.com")
    res = client_b.post(f"/api/v1/connections/{cid}/test", headers=_csrf(client_b))
    assert res.status_code == 404


@pytest.mark.parametrize("role", ["viewer", "member", "manager"])
def test_endpoint_read_roles_cannot_test(roles_seed, monkeypatch, role):
    _stub_outcome(monkeypatch, _SUCCESS)
    owner = _client()
    _login(owner, "owner@example.com")
    cid = _create(owner).json()["id"]
    client = _client()
    _login(client, f"{role}@example.com")
    res = client.post(f"/api/v1/connections/{cid}/test", headers=_csrf(client))
    assert res.status_code == 403


@pytest.mark.parametrize("role", ["owner", "admin"])
def test_endpoint_owner_admin_can_test(roles_seed, monkeypatch, role):
    _stub_outcome(monkeypatch, _SUCCESS)
    client = _client()
    _login(client, f"{role}@example.com")
    cid = _create(client, name=f"T {role}").json()["id"]
    res = client.post(f"/api/v1/connections/{cid}/test", headers=_csrf(client))
    assert res.status_code == 200


def test_endpoint_requires_csrf(roles_seed, monkeypatch):
    _stub_outcome(monkeypatch, _SUCCESS)
    client = _client()
    _login(client, "owner@example.com")
    cid = _create(client).json()["id"]
    assert client.post(f"/api/v1/connections/{cid}/test").status_code == 403
    assert (
        client.post(
            f"/api/v1/connections/{cid}/test", headers={"X-CSRF-Token": "forged"}
        ).status_code
        == 403
    )


def test_endpoint_disabled_connection_rejected(roles_seed, monkeypatch):
    _stub_outcome(monkeypatch, _SUCCESS)
    client = _client()
    _login(client, "owner@example.com")
    cid = _create(client).json()["id"]
    client.delete(f"/api/v1/connections/{cid}", headers=_csrf(client))
    res = client.post(f"/api/v1/connections/{cid}/test", headers=_csrf(client))
    assert res.status_code == 409


# --- 33: no business-data endpoints ------------------------------------------------


def test_no_business_data_endpoints_exist():
    """No connection-level business-data synchronization endpoint exists."""
    from app.api.connections import router

    paths = [r.path for r in router.routes]
    assert paths  # sanity
    for path in paths:
        for banned in ("partner", "invoice", "employee", "sync", "sale", "stock", "record"):
            assert banned not in path.lower(), path


def test_auth_mode_persisted_and_validated(roles_seed):
    client = _client()
    _login(client, "owner@example.com")
    payload = {
        "name": "AK Conn",
        "provider": "odoo",
        "base_url": "https://ak.example.com",
        "database_name": "db",
        "username": "u",
        "auth_mode": "api_key",
        "credentials": {"login": "u", "password_or_api_key": SECRET},
    }
    res = client.post("/api/v1/connections", json=payload, headers=_csrf(client))
    assert res.status_code == 201
    assert res.json()["auth_mode"] == "api_key"
    cid = res.json()["id"]
    # default is auto
    res2 = _create(client, name="Default Conn")
    assert res2.json()["auth_mode"] == "auto"
    # invalid mode rejected
    payload["name"] = "Bad"
    payload["auth_mode"] = "bearer"
    assert (
        client.post("/api/v1/connections", json=payload, headers=_csrf(client)).status_code
        == 422
    )
    # patchable
    res = client.patch(
        f"/api/v1/connections/{cid}", json={"auth_mode": "password"}, headers=_csrf(client)
    )
    assert res.json()["auth_mode"] == "password"
