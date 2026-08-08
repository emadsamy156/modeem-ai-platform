"""Centralized read-policy registry (Phase 2D).

The API caller NEVER supplies a raw Odoo model name, method name, raw
domain, or raw order string. Callers use a Modeem `resource_key`; every
model, field, filter operator, and order field is allowlisted here.

Phase 2D ships ONLY the technical `countries` resource (res.country) to
validate the generic read infrastructure. Business resources (partners,
invoices, employees, ...) are added only after explicit approval of each
domain — do not add them here speculatively.
"""

from dataclasses import dataclass, field

# Global request-shape bounds for the read-preview phase.
MAX_FILTERS = 5
MAX_REQUESTED_FIELDS = 20
MAX_FILTER_STRING_LENGTH = 200
MAX_FILTER_LIST_ITEMS = 50
MAX_PREVIEW_OFFSET = 1000
DEFAULT_PAGE_SIZE = 25
ABSOLUTE_MAX_PAGE_SIZE = 50

# Small safe operator subset. AND-only semantics; no |, &, !, child_of,
# parent_of, raw domains, or arbitrary operators.
SAFE_OPERATORS = frozenset({"=", "!=", "in", "ilike"})


@dataclass(frozen=True)
class ReadPolicy:
    resource_key: str
    odoo_model: str
    allowed_fields: frozenset[str]
    default_fields: tuple[str, ...]
    allowed_filter_fields: frozenset[str]
    allowed_filter_operators: frozenset[str]
    allowed_order_fields: frozenset[str]
    max_page_size: int = field(default=ABSOLUTE_MAX_PAGE_SIZE)


_COUNTRIES = ReadPolicy(
    resource_key="countries",
    odoo_model="res.country",
    allowed_fields=frozenset({"id", "name", "code"}),
    default_fields=("id", "name", "code"),
    allowed_filter_fields=frozenset({"id", "name", "code"}),
    allowed_filter_operators=SAFE_OPERATORS,
    allowed_order_fields=frozenset({"id", "name", "code"}),
    max_page_size=ABSOLUTE_MAX_PAGE_SIZE,
)

READ_POLICIES: dict[str, ReadPolicy] = {
    _COUNTRIES.resource_key: _COUNTRIES,
}


def get_policy(resource_key: str) -> ReadPolicy | None:
    return READ_POLICIES.get(resource_key)
