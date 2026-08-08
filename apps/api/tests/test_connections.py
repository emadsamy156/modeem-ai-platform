"""Security tests for tenant-scoped Connections (Phase 2B)."""

import base64
import os
import uuid

import pytest

from app.core.security import hash_password
from app.models import AuditLog, Connection, TenantMembership, User
from app.services import credential_crypto
from app.services.credential_crypto import (
    CredentialDecryptionError,
    EncryptionConfigError,
    decrypt_credentials,
    encrypt_credentials,
    validate_encryption_key,
)
from tests.test_auth_security import (
    PASSWORD,
    TestingSession,
    _client,
    _csrf,
    _fresh_db,  # noqa: F401 — autouse fixture reuse
    _login,
    seed,  # noqa: F401 — fixture reuse
)

TEST_KEY = base64.urlsafe_b64encode(os.urandom(32)).decode()

SECRET = "odoo-api-key-123"


@pytest.fixture(autouse=True)
def _encryption_key(monkeypatch):
    monkeypatch.setenv("CONNECTION_ENCRYPTION_KEY", TEST_KEY)
    from app.core.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture()
def roles_seed(seed):  # noqa: F811
    """Add one user per role in tenant A, plus tenant B owner."""
    db = TestingSession()
    users = {}
    for role in ("owner", "admin", "manager", "member", "viewer"):
        u = User(
            email=f"{role}@example.com",
            full_name=role.title(),
            password_hash=hash_password(PASSWORD),
        )
        db.add(u)
        db.flush()
        db.add(TenantMembership(tenant_id=seed["tenant_a"], user_id=u.id, role=role))
        users[role] = u.id
    owner_b = User(
        email="owner-b@example.com",
        full_name="Owner B",
        password_hash=hash_password(PASSWORD),
    )
    db.add(owner_b)
    db.flush()
    db.add(TenantMembership(tenant_id=seed["tenant_b"], user_id=owner_b.id, role="owner"))
    db.commit()
    db.close()
    return {**seed, "users": users}


def _payload(name="Odoo Prod", secret=SECRET):
    return {
        "name": name,
        "provider": "odoo",
        "base_url": "https://example.odoo.com",
        "database_name": "proddb",
        "username": "api-user",
        "credentials": {"login": "api-user", "password_or_api_key": secret},
    }


def _create(client, name="Odoo Prod", secret=SECRET):
    return client.post(
        "/api/v1/connections", json=_payload(name, secret), headers=_csrf(client)
    )


# --- Crypto service ---------------------------------------------------------


def test_key_validation():
    assert len(validate_encryption_key(TEST_KEY)) == 32
    with pytest.raises(EncryptionConfigError):
        validate_encryption_key("")
    with pytest.raises(EncryptionConfigError):
        validate_encryption_key("not-base64!!!")
    with pytest.raises(EncryptionConfigError):
        validate_encryption_key(base64.urlsafe_b64encode(b"short").decode())


def test_encrypt_decrypt_roundtrip_and_random_nonce():
    t, c = uuid.uuid4(), uuid.uuid4()
    payload = {"login": "x", "password_or_api_key": SECRET}
    blob1, v1 = encrypt_credentials(payload, tenant_id=t, connection_id=c)
    blob2, _ = encrypt_credentials(payload, tenant_id=t, connection_id=c)
    assert blob1 != blob2  # random nonce per encryption
    assert v1 == credential_crypto.ENCRYPTION_VERSION
    assert SECRET.encode() not in blob1
    assert decrypt_credentials(blob1, tenant_id=t, connection_id=c) == payload


def test_tampered_ciphertext_fails():
    t, c = uuid.uuid4(), uuid.uuid4()
    blob, _ = encrypt_credentials({"a": "b"}, tenant_id=t, connection_id=c)
    tampered = blob[:-1] + bytes([blob[-1] ^ 0xFF])
    with pytest.raises(CredentialDecryptionError):
        decrypt_credentials(tampered, tenant_id=t, connection_id=c)


def test_aad_binds_connection_and_tenant():
    t, c = uuid.uuid4(), uuid.uuid4()
    blob, _ = encrypt_credentials({"a": "b"}, tenant_id=t, connection_id=c)
    with pytest.raises(CredentialDecryptionError):
        decrypt_credentials(blob, tenant_id=t, connection_id=uuid.uuid4())
    with pytest.raises(CredentialDecryptionError):
        decrypt_credentials(blob, tenant_id=uuid.uuid4(), connection_id=c)


def test_production_rejects_missing_or_invalid_key(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_SECRET", "x" * 48)
    monkeypatch.setenv("CONNECTION_ENCRYPTION_KEY", "")
    get_settings.cache_clear()
    with pytest.raises(EncryptionConfigError):
        get_settings()
    get_settings.cache_clear()
    monkeypatch.setenv("CONNECTION_ENCRYPTION_KEY", "invalid")
    with pytest.raises(EncryptionConfigError):
        get_settings()
    get_settings.cache_clear()


# --- API: storage & responses ----------------------------------------------


def test_plaintext_not_stored_and_responses_safe(roles_seed):
    client = _client()
    _login(client, "owner@example.com")
    res = _create(client)
    assert res.status_code == 201
    body = res.json()
    # Response contains only safe metadata.
    text = res.text
    assert SECRET not in text
    assert "encrypted_credentials" not in body
    assert "nonce" not in text
    assert body["has_credentials"] is True

    db = TestingSession()
    conn = db.query(Connection).one()
    assert SECRET.encode() not in (conn.encrypted_credentials or b"")
    # Decryptable only via the backend service with correct AAD.
    creds = decrypt_credentials(
        conn.encrypted_credentials, tenant_id=conn.tenant_id, connection_id=conn.id
    )
    assert creds["password_or_api_key"] == SECRET
    db.close()

    listing = client.get("/api/v1/connections")
    assert listing.status_code == 200
    assert SECRET not in listing.text
    assert "encrypted_credentials" not in listing.text


def test_metadata_update_preserves_secret_and_new_secret_replaces(roles_seed):
    client = _client()
    _login(client, "owner@example.com")
    cid = _create(client).json()["id"]
    db = TestingSession()
    blob_before = db.query(Connection).one().encrypted_credentials
    db.close()

    res = client.patch(
        f"/api/v1/connections/{cid}",
        json={"database_name": "newdb"},
        headers=_csrf(client),
    )
    assert res.status_code == 200
    db = TestingSession()
    conn = db.query(Connection).one()
    assert conn.encrypted_credentials == blob_before  # preserved
    db.close()

    res = client.patch(
        f"/api/v1/connections/{cid}",
        json={"credentials": {"login": "api-user", "password_or_api_key": "new-secret"}},
        headers=_csrf(client),
    )
    assert res.status_code == 200
    db = TestingSession()
    conn = db.query(Connection).one()
    assert conn.encrypted_credentials != blob_before  # replaced
    creds = decrypt_credentials(
        conn.encrypted_credentials, tenant_id=conn.tenant_id, connection_id=conn.id
    )
    assert creds["password_or_api_key"] == "new-secret"
    db.close()


def test_url_validation(roles_seed):
    client = _client()
    _login(client, "owner@example.com")
    for bad in (
        "ftp://example.com",
        "not-a-url",
        "https://user:password@example.com",
        "https://",
    ):
        payload = _payload()
        payload["base_url"] = bad
        res = client.post("/api/v1/connections", json=payload, headers=_csrf(client))
        assert res.status_code == 422, bad


# --- Tenant isolation --------------------------------------------------------


def test_tenant_isolation(roles_seed):
    client_a = _client()
    _login(client_a, "owner@example.com")
    cid = _create(client_a).json()["id"]

    client_b = _client()
    _login(client_b, "owner-b@example.com")
    # list: does not see tenant A connections
    assert client_b.get("/api/v1/connections").json() == []
    # read by UUID: 404, not 403 (no existence leak)
    assert client_b.get(f"/api/v1/connections/{cid}").status_code == 404
    # patch / disable / credentials replace: 404
    assert (
        client_b.patch(
            f"/api/v1/connections/{cid}",
            json={"name": "stolen"},
            headers=_csrf(client_b),
        ).status_code
        == 404
    )
    assert (
        client_b.patch(
            f"/api/v1/connections/{cid}",
            json={"credentials": {"login": "x", "password_or_api_key": "y"}},
            headers=_csrf(client_b),
        ).status_code
        == 404
    )
    assert (
        client_b.delete(f"/api/v1/connections/{cid}", headers=_csrf(client_b)).status_code
        == 404
    )


# --- Roles --------------------------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "member", "manager"])
def test_read_only_roles_cannot_write(roles_seed, role):
    owner = _client()
    _login(owner, "owner@example.com")
    cid = _create(owner).json()["id"]

    client = _client()
    _login(client, f"{role}@example.com")
    # can list/read
    assert client.get("/api/v1/connections").status_code == 200
    assert client.get(f"/api/v1/connections/{cid}").status_code == 200
    # cannot create/update/disable
    assert _create(client, name="Other").status_code == 403
    assert (
        client.patch(
            f"/api/v1/connections/{cid}", json={"name": "x"}, headers=_csrf(client)
        ).status_code
        == 403
    )
    assert (
        client.delete(f"/api/v1/connections/{cid}", headers=_csrf(client)).status_code == 403
    )


@pytest.mark.parametrize("role", ["owner", "admin"])
def test_owner_admin_can_write(roles_seed, role):
    client = _client()
    _login(client, f"{role}@example.com")
    res = _create(client, name=f"Conn {role}")
    assert res.status_code == 201
    cid = res.json()["id"]
    assert (
        client.patch(
            f"/api/v1/connections/{cid}", json={"name": f"Conn {role} 2"}, headers=_csrf(client)
        ).status_code
        == 200
    )
    res = client.delete(f"/api/v1/connections/{cid}", headers=_csrf(client))
    assert res.status_code == 200
    assert res.json()["status"] == "disabled"
    assert res.json()["is_active"] is False


# --- CSRF ----------------------------------------------------------------------


def test_write_endpoints_require_csrf(roles_seed):
    client = _client()
    _login(client, "owner@example.com")
    cid = _create(client).json()["id"]
    # missing token
    assert client.post("/api/v1/connections", json=_payload("X")).status_code == 403
    assert (
        client.patch(f"/api/v1/connections/{cid}", json={"name": "x"}).status_code == 403
    )
    assert client.delete(f"/api/v1/connections/{cid}").status_code == 403
    # invalid token
    bad = {"X-CSRF-Token": "forged"}
    assert (
        client.post("/api/v1/connections", json=_payload("X"), headers=bad).status_code
        == 403
    )


# --- Misc ------------------------------------------------------------------------


def test_duplicate_name_within_tenant_rejected(roles_seed):
    client = _client()
    _login(client, "owner@example.com")
    assert _create(client).status_code == 201
    assert _create(client).status_code == 409
    # Same name in another tenant is fine.
    client_b = _client()
    _login(client_b, "owner-b@example.com")
    assert _create(client_b).status_code == 201


def test_audit_logs_contain_no_credentials(roles_seed):
    client = _client()
    _login(client, "owner@example.com")
    cid = _create(client).json()["id"]
    client.patch(
        f"/api/v1/connections/{cid}",
        json={"credentials": {"login": "api-user", "password_or_api_key": "rotated"}},
        headers=_csrf(client),
    )
    client.delete(f"/api/v1/connections/{cid}", headers=_csrf(client))

    db = TestingSession()
    actions = {
        a.action for a in db.query(AuditLog).filter(AuditLog.resource_type == "connection")
    }
    assert {"connection.created", "connection.credentials_replaced", "connection.disabled"} <= actions
    for entry in db.query(AuditLog).all():
        dump = str(entry.metadata_json)
        assert SECRET not in dump
        assert "rotated" not in dump
        assert "password_or_api_key" not in dump
    db.close()


def test_unconfigured_key_fails_clearly(roles_seed, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setenv("CONNECTION_ENCRYPTION_KEY", "")
    get_settings.cache_clear()
    client = _client()
    _login(client, "owner@example.com")
    res = _create(client)
    assert res.status_code == 503
    assert "CONNECTION_ENCRYPTION_KEY" in res.json()["detail"]
