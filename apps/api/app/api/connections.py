"""Tenant-scoped Connection CRUD (Phase 2B).

- Every query scopes id AND tenant_id in one ORM filter (no fetch-then-check).
- 404 for cross-tenant access so other tenants' UUIDs leak nothing.
- Writes: owner/admin only, CSRF required. Reads: any active member.
- Responses never contain credentials, ciphertext, or nonces.
- NO external/Odoo network call exists anywhere in this module.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.csrf import require_csrf
from app.api.deps import (
    TenantContext,
    get_current_tenant,
    get_current_user,
    get_db,
    require_role,
)
from app.core.config import get_settings
from app.models import Connection, User
from app.schemas.connections import (
    ConnectionCreate,
    ConnectionOut,
    ConnectionUpdate,
    validate_base_url,
)
from app.services.audit import record_audit
from app.services.credential_crypto import EncryptionConfigError, encrypt_credentials

router = APIRouter(prefix="/api/v1")

_WRITE_ROLES = ("owner", "admin")


def _to_out(conn: Connection) -> ConnectionOut:
    return ConnectionOut(
        id=conn.id,
        name=conn.name,
        provider=conn.provider,
        base_url=conn.base_url,
        database_name=conn.database_name,
        username=conn.username,
        status=conn.status,
        is_active=conn.is_active,
        has_credentials=conn.encrypted_credentials is not None,
        last_tested_at=conn.last_tested_at,
        last_test_status=conn.last_test_status,
        created_at=conn.created_at,
        updated_at=conn.updated_at,
    )


def _scoped_get(db: Session, ctx: TenantContext, connection_id: uuid.UUID) -> Connection:
    conn = (
        db.query(Connection)
        .filter(Connection.id == connection_id, Connection.tenant_id == ctx.tenant.id)
        .first()
    )
    if conn is None:
        # 404 (not 403) so existence in another tenant is not leaked.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found"
        )
    return conn


def _checked_base_url(value: str) -> str:
    settings = get_settings()
    try:
        return validate_base_url(
            value, require_https=settings.environment == "production"
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


def _encrypt_or_503(payload: dict, *, tenant_id: uuid.UUID, connection_id: uuid.UUID):
    try:
        return encrypt_credentials(
            payload, tenant_id=tenant_id, connection_id=connection_id
        )
    except EncryptionConfigError as exc:
        # Clear failure when the encryption key is not configured (dev).
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc


@router.get("/connections", response_model=list[ConnectionOut])
def list_connections(
    ctx: TenantContext = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> list[ConnectionOut]:
    rows = (
        db.query(Connection)
        .filter(Connection.tenant_id == ctx.tenant.id)
        .order_by(Connection.created_at.desc())
        .all()
    )
    return [_to_out(c) for c in rows]


@router.get("/connections/{connection_id}", response_model=ConnectionOut)
def get_connection(
    connection_id: uuid.UUID,
    ctx: TenantContext = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> ConnectionOut:
    return _to_out(_scoped_get(db, ctx, connection_id))


@router.post(
    "/connections",
    response_model=ConnectionOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
def create_connection(
    body: ConnectionCreate,
    ctx: TenantContext = Depends(require_role(*_WRITE_ROLES)),
    actor: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ConnectionOut:
    base_url = _checked_base_url(body.base_url)

    duplicate = (
        db.query(Connection)
        .filter(Connection.tenant_id == ctx.tenant.id, Connection.name == body.name)
        .first()
    )
    if duplicate is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A connection with this name already exists",
        )

    connection_id = uuid.uuid4()
    blob, version = _encrypt_or_503(
        body.credentials.model_dump(),
        tenant_id=ctx.tenant.id,
        connection_id=connection_id,
    )

    conn = Connection(
        id=connection_id,
        tenant_id=ctx.tenant.id,
        name=body.name,
        provider=body.provider,
        base_url=base_url,
        database_name=body.database_name,
        username=body.username,
        encrypted_credentials=blob,
        encryption_version=version,
        status="configured",
        created_by_user_id=actor.id,
        updated_by_user_id=actor.id,
    )
    db.add(conn)
    db.flush()
    record_audit(
        db,
        action="connection.created",
        actor_type="user",
        actor_id=str(actor.id),
        tenant_id=ctx.tenant.id,
        resource_type="connection",
        resource_id=str(conn.id),
        metadata={"provider": conn.provider, "name": conn.name},
    )
    return _to_out(conn)


@router.patch(
    "/connections/{connection_id}",
    response_model=ConnectionOut,
    dependencies=[Depends(require_csrf)],
)
def update_connection(
    connection_id: uuid.UUID,
    body: ConnectionUpdate,
    ctx: TenantContext = Depends(require_role(*_WRITE_ROLES)),
    actor: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ConnectionOut:
    conn = _scoped_get(db, ctx, connection_id)
    provided = body.model_fields_set

    if body.name is not None and body.name != conn.name:
        new_name = body.name
        duplicate = (
            db.query(Connection)
            .filter(
                Connection.tenant_id == ctx.tenant.id,
                Connection.name == new_name,
                Connection.id != conn.id,
            )
            .first()
        )
        if duplicate is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A connection with this name already exists",
            )
        conn.name = new_name
    if body.base_url is not None:
        conn.base_url = _checked_base_url(body.base_url)
    # Omitted field -> preserve; explicit JSON null -> clear (nullable metadata).
    if "database_name" in provided:
        conn.database_name = body.database_name
    if "username" in provided:
        conn.username = body.username
    if body.status is not None:
        conn.status = body.status
        conn.is_active = body.status != "disabled"

    credentials_changed = False
    if body.credentials is not None:
        blob, version = _encrypt_or_503(
            body.credentials.model_dump(),
            tenant_id=ctx.tenant.id,
            connection_id=conn.id,
        )
        conn.encrypted_credentials = blob
        conn.encryption_version = version
        credentials_changed = True
    # If no new credential is supplied, the existing encrypted blob is kept.

    conn.updated_by_user_id = actor.id
    record_audit(
        db,
        action=(
            "connection.credentials_replaced" if credentials_changed else "connection.updated"
        ),
        actor_type="user",
        actor_id=str(actor.id),
        tenant_id=ctx.tenant.id,
        resource_type="connection",
        resource_id=str(conn.id),
        metadata={
            "provider": conn.provider,
            "name": conn.name,
            "credentials_changed": credentials_changed,
        },
    )
    db.flush()
    return _to_out(conn)


@router.delete(
    "/connections/{connection_id}",
    response_model=ConnectionOut,
    dependencies=[Depends(require_csrf)],
)
def disable_connection(
    connection_id: uuid.UUID,
    ctx: TenantContext = Depends(require_role(*_WRITE_ROLES)),
    actor: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ConnectionOut:
    """Soft disable — the record and its encrypted credential are retained."""
    conn = _scoped_get(db, ctx, connection_id)
    conn.status = "disabled"
    conn.is_active = False
    conn.updated_by_user_id = actor.id
    record_audit(
        db,
        action="connection.disabled",
        actor_type="user",
        actor_id=str(actor.id),
        tenant_id=ctx.tenant.id,
        resource_type="connection",
        resource_id=str(conn.id),
        metadata={"provider": conn.provider, "name": conn.name},
    )
    db.flush()
    return _to_out(conn)
