"""Authentication and tenant-context routes (Phase 2A)."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps import (
    TenantContext,
    get_active_memberships,
    get_current_tenant,
    get_current_user,
    get_db,
    get_session_payload,
    resolve_tenant_context,
)
from app.core.config import get_settings
from app.core.security import (
    SESSION_COOKIE_NAME,
    create_session_token,
    verify_password,
)
from app.models import Tenant, User
from app.models.user import normalize_email
from app.schemas.auth import (
    CurrentTenantOut,
    LoginRequest,
    MembershipOut,
    MeResponse,
    TenantContextOut,
    TenantSelectRequest,
)
from app.services.audit import record_audit

router = APIRouter(prefix="/api/v1")


def _set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.environment == "production",
        path="/",
    )


@router.post("/auth/login", response_model=MeResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> MeResponse:
    email = normalize_email(body.email)
    user = db.query(User).filter(User.email == email).one_or_none()

    generic_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
    )

    if user is None or not verify_password(user.password_hash, body.password):
        record_audit(
            db,
            action="auth.login_failed",
            actor_type="anonymous",
            actor_id=email,
            metadata={"reason": "invalid_credentials"},
        )
        db.commit()
        raise generic_error

    if not user.is_active:
        record_audit(
            db,
            action="auth.login_failed",
            actor_type="user",
            actor_id=str(user.id),
            metadata={"reason": "inactive_user"},
        )
        db.commit()
        raise generic_error

    memberships = get_active_memberships(db, user)
    tenant_id = memberships[0].tenant_id if memberships else None

    user.last_login_at = datetime.now(UTC)
    token = create_session_token(user.id, tenant_id)
    _set_session_cookie(response, token)

    record_audit(
        db,
        action="auth.login_success",
        actor_type="user",
        actor_id=str(user.id),
        tenant_id=tenant_id,
    )

    return _me_response(db, user, tenant_id)


@router.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    # Best effort: identify the user for the audit trail if a valid cookie exists.
    actor_id: str | None = None
    try:
        payload = get_session_payload(request)
        actor_id = payload.get("sub")
    except HTTPException:
        pass
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    record_audit(
        db,
        action="auth.logout",
        actor_type="user" if actor_id else "anonymous",
        actor_id=actor_id,
    )
    return {"status": "logged_out"}


@router.get("/auth/me", response_model=MeResponse)
def me(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MeResponse:
    payload = get_session_payload(request)
    tid = payload.get("tid")
    tenant_id = None
    if tid:
        import uuid as _uuid

        try:
            tenant_id = _uuid.UUID(tid)
        except ValueError:
            tenant_id = None
    return _me_response(db, user, tenant_id)


@router.post("/auth/tenant", response_model=MeResponse)
def select_tenant(
    body: TenantSelectRequest,
    response: Response,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MeResponse:
    ctx = resolve_tenant_context(db, user, body.tenant_id)
    token = create_session_token(user.id, ctx.tenant.id)
    _set_session_cookie(response, token)
    record_audit(
        db,
        action="auth.tenant_switch",
        actor_type="user",
        actor_id=str(user.id),
        tenant_id=ctx.tenant.id,
        metadata={"superuser_access": ctx.membership is None},
    )
    return _me_response(db, user, ctx.tenant.id)


@router.get("/tenant-context", response_model=TenantContextOut)
def tenant_context(ctx: TenantContext = Depends(get_current_tenant)) -> TenantContextOut:
    """Temporary endpoint proving tenant scoping works."""
    return TenantContextOut(
        tenant_id=ctx.tenant.id, tenant_name=ctx.tenant.name, role=ctx.role
    )


def _me_response(db: Session, user: User, tenant_id) -> MeResponse:
    memberships = get_active_memberships(db, user)
    tenant_ids = [m.tenant_id for m in memberships]
    tenants = (
        {t.id: t for t in db.query(Tenant).filter(Tenant.id.in_(tenant_ids)).all()}
        if tenant_ids
        else {}
    )
    out_memberships = [
        MembershipOut(
            tenant_id=m.tenant_id,
            tenant_name=tenants[m.tenant_id].name if m.tenant_id in tenants else "",
            role=m.role,
        )
        for m in memberships
    ]
    current: CurrentTenantOut | None = None
    if tenant_id is not None:
        m = next((m for m in memberships if m.tenant_id == tenant_id), None)
        if m is not None and m.tenant_id in tenants:
            current = CurrentTenantOut(
                id=m.tenant_id, name=tenants[m.tenant_id].name, role=m.role
            )
        elif user.is_superuser:
            t = db.get(Tenant, tenant_id)
            if t is not None:
                current = CurrentTenantOut(id=t.id, name=t.name, role="superuser")
    return MeResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_superuser=user.is_superuser,
        current_tenant=current,
        memberships=out_memberships,
    )
