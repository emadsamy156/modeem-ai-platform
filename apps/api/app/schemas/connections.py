"""Pydantic schemas for Connections (Phase 2B).

Responses expose only safe metadata — never credentials, ciphertext,
nonces, or encryption details beyond a `has_credentials` boolean.
"""

import uuid
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator


def validate_base_url(value: str, *, require_https: bool) -> str:
    """Validate and normalize a stored base URL.

    Rejects credentials-in-URL, query strings, and fragments; strips any
    trailing slash from the path. Never fetches or resolves the host —
    SSRF/IP/DNS protections are a Phase 2C prerequisite before any
    network call is allowed.
    """
    value = value.strip()
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ValueError("base_url must start with http:// or https://")
    if require_https and parts.scheme != "https":
        raise ValueError("base_url must use https:// in production")
    if not parts.hostname:
        raise ValueError("base_url must include a valid host")
    if parts.username is not None or parts.password is not None:
        raise ValueError(
            "base_url must not contain credentials; store them separately"
        )
    if parts.query:
        raise ValueError("base_url must not contain a query string")
    if parts.fragment:
        raise ValueError("base_url must not contain a fragment")
    path = parts.path.rstrip("/")
    return f"{parts.scheme}://{parts.netloc}{path}"


class OdooCredentials(BaseModel):
    """Secret payload for provider 'odoo'. Stored only encrypted."""

    login: str = Field(min_length=1, max_length=255)
    password_or_api_key: str = Field(min_length=1, max_length=1024)


class ConnectionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    provider: Literal["odoo"]
    base_url: str = Field(max_length=500)
    database_name: str | None = Field(default=None, max_length=200)
    username: str | None = Field(default=None, max_length=200)
    credentials: OdooCredentials

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v


class ConnectionUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v

    base_url: str | None = Field(default=None, max_length=500)
    database_name: str | None = Field(default=None, max_length=200)
    username: str | None = Field(default=None, max_length=200)
    status: Literal["configured", "disabled"] | None = None
    # If supplied: encrypt and replace. If omitted: keep existing secret.
    credentials: OdooCredentials | None = None


class ConnectionOut(BaseModel):
    """Safe metadata only. No secret or ciphertext fields exist here."""

    id: uuid.UUID
    name: str
    provider: str
    base_url: str
    database_name: str | None
    username: str | None
    status: str
    is_active: bool
    has_credentials: bool
    last_tested_at: datetime | None
    last_test_status: str | None
    created_at: datetime
    updated_at: datetime
