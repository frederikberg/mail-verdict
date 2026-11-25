"""
Scoped access keys: what a credential subject may do.

A token subject (auth/principal.py) is either *full* -- everything its user
may do, which is what a person's login is -- or *scoped*: exactly the scopes
of its Grant, never admin whatever its user's role. The grant is stored on the
subject (`user_identities`), managed through api/access_keys.py and read into
the Principal by the resolver.

Two layers enforce it, independently:

1. The gate (auth/middleware.py and, for MCP tools, auth/mcp_gate.py) asks
   this module whether a scoped grant may call a route or a tool. Both
   questions are answered from one table each (ROUTE_SCOPES, TOOL_SCOPES) and
   both are default-deny: a route or tool nobody listed is closed to every
   scoped key, so forgetting one closes it rather than opening it.
2. The data scope (Scope.for_principal) is emptied of the accounts a key holds
   no scope for, so a route the table got wrong still finds no mail or DAV
   data there (rows keyed by user instead of account rely on the table).

docs/access-matrix.md is generated from the two tables and the served app
(scripts/export_access_matrix.py); tests/unit/test_access_matrix.py fails
when the app and the document disagree, and when a route or tool is
reachable that no scope names.

Scopes:

- calendar:read   list calendars, list and read events
- calendar:write  create, edit and delete events; implies calendar:read
- contacts:read   list address books, list, search, resolve and read contacts
- contacts:write  create, edit and delete contacts; implies contacts:read

Everything not named by a scope is for full access only: settings, accounts,
mail, secrets, webhooks, the pipeline, admin, sign-ins and the event stream.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, get_args

from starlette.routing import compile_path

if TYPE_CHECKING:
    from mail_verdict.auth.principal import Principal

logger = logging.getLogger(__name__)

ScopeName = Literal["calendar:read", "calendar:write", "contacts:read", "contacts:write"]
SCOPES: tuple[str, ...] = get_args(ScopeName)
AccessMode = Literal["full", "scoped"]

CALENDAR_READ: ScopeName = "calendar:read"
CALENDAR_WRITE: ScopeName = "calendar:write"
CONTACTS_READ: ScopeName = "contacts:read"
CONTACTS_WRITE: ScopeName = "contacts:write"

# Table values that name no scope: a route any scoped key may call, and the
# MCP transport, open to a key that holds a scope some tool is listed under.
ANY_KEY = "*"
MCP_TRANSPORT = "mcp"

ROUTE_SCOPES: dict[str, str] = {
    "GET /api/me": ANY_KEY,
    "GET /api/openapi.json": ANY_KEY,
    "GET /api/calendars": CALENDAR_READ,
    "GET /api/calendar/events": CALENDAR_READ,
    "GET /api/calendar/events/{object_id}": CALENDAR_READ,
    "POST /api/calendar/events": CALENDAR_WRITE,
    "PATCH /api/calendar/events/{object_id}": CALENDAR_WRITE,
    "DELETE /api/calendar/events/{object_id}": CALENDAR_WRITE,
    "GET /api/addressbooks": CONTACTS_READ,
    "GET /api/contacts": CONTACTS_READ,
    "GET /api/contacts/search": CONTACTS_READ,
    "GET /api/contacts/resolve": CONTACTS_READ,
    "GET /api/contacts/groups": CONTACTS_READ,
    "GET /api/contacts/photo-index": CONTACTS_READ,
    "GET /api/contacts/{contact_id}": CONTACTS_READ,
    "GET /api/contacts/{contact_id}/photo": CONTACTS_READ,
    "POST /api/contacts": CONTACTS_WRITE,
    "PATCH /api/contacts/{contact_id}": CONTACTS_WRITE,
    "DELETE /api/contacts/{contact_id}": CONTACTS_WRITE,
    "GET /mcp/": MCP_TRANSPORT,
    "POST /mcp/": MCP_TRANSPORT,
    "DELETE /mcp/": MCP_TRANSPORT,
}

TOOL_SCOPES: dict[str, str] = {
    "list_calendars": CALENDAR_READ,
    "list_events": CALENDAR_READ,
    "get_event": CALENDAR_READ,
    "create_event": CALENDAR_WRITE,
    "update_event": CALENDAR_WRITE,
    "delete_event": CALENDAR_WRITE,
    "list_addressbooks": CONTACTS_READ,
    "list_contacts": CONTACTS_READ,
    "search_contacts": CONTACTS_READ,
    "get_contact": CONTACTS_READ,
    "create_contact": CONTACTS_WRITE,
    "update_contact": CONTACTS_WRITE,
    "delete_contact": CONTACTS_WRITE,
}


class GrantInvalid(ValueError):
    """A combination of access, scopes and write limits that cannot be
    stored. The message is the code an API answer carries as its detail."""


@dataclass(frozen=True)
class Grant:
    """
    What a scoped subject may do. A principal with no grant is full.

    Attributes:
        scopes: The scopes held (a write scope implies its read scope; see
            holds()).
        calendar_write_ids: The calendars events may be written into, or None
            for every calendar the user can write to.
        addressbook_write_ids: The same for address books and contacts.
    """

    scopes: frozenset[str]
    calendar_write_ids: frozenset[uuid.UUID] | None = None
    addressbook_write_ids: frozenset[uuid.UUID] | None = None

    def holds(self, scope: str) -> bool:
        """Whether the grant carries `scope`, a write scope counting for its
        own read scope."""
        if scope in self.scopes:
            return True
        resource, _, action = scope.partition(":")
        return action == "read" and f"{resource}:write" in self.scopes

    def opens_any_tool(self) -> bool:
        """Whether some MCP tool is listed under a scope the grant holds."""
        return any(self.holds(scope) for scope in set(TOOL_SCOPES.values()))

    def may_write_calendar(self, calendar_id: uuid.UUID | None) -> bool:
        """Whether events may be written into this calendar."""
        return self.calendar_write_ids is None or calendar_id in self.calendar_write_ids

    def may_write_addressbook(self, addressbook_id: uuid.UUID | None) -> bool:
        """Whether contacts may be written into this address book."""
        return self.addressbook_write_ids is None or addressbook_id in self.addressbook_write_ids


@dataclass(frozen=True)
class Refusal:
    """A request a grant does not cover.

    Attributes:
        scope: The scope that would open it, or None when no scope does (a
            route for full access only, or one nobody listed).
    """

    scope: str | None


def grant_from_columns(
    access: str,
    scopes: Iterable[str],
    calendar_write_ids: Iterable[uuid.UUID] | None,
    addressbook_write_ids: Iterable[uuid.UUID] | None,
) -> Grant | None:
    """The grant a `user_identities` row stores, or None for full access."""
    if access == "full":
        return None
    return Grant(
        scopes=frozenset(scopes),
        calendar_write_ids=None if calendar_write_ids is None else frozenset(calendar_write_ids),
        addressbook_write_ids=(
            None if addressbook_write_ids is None else frozenset(addressbook_write_ids)
        ),
    )


def check_fields(
    access: AccessMode,
    scopes: Iterable[str],
    calendar_write_ids: Iterable[uuid.UUID] | None,
    addressbook_write_ids: Iterable[uuid.UUID] | None,
) -> list[str]:
    """
    The scopes to store, sorted and without repeats, once the combination is
    known to be coherent.

    Raises:
        GrantInvalid: Full access carrying scopes or limits; a scope this
            version does not know; a write limit without its write scope.
    """
    held = sorted(set(scopes))
    unknown = [scope for scope in held if scope not in SCOPES]
    if unknown:
        raise GrantInvalid("unknown_scope")
    if access == "full":
        if held or calendar_write_ids is not None or addressbook_write_ids is not None:
            raise GrantInvalid("full_access_carries_no_scopes")
        return []
    if calendar_write_ids is not None and CALENDAR_WRITE not in held:
        raise GrantInvalid("calendar_limit_needs_calendar_write")
    if addressbook_write_ids is not None and CONTACTS_WRITE not in held:
        raise GrantInvalid("addressbook_limit_needs_contacts_write")
    return held


def _compile(table: dict[str, str]) -> list[tuple[str, re.Pattern[str], int, str]]:
    """Each "METHOD /path/{param}" key as (method, pattern, parameter count,
    scope), the pattern built the way Starlette builds a route's own."""
    compiled = []
    for key, scope in table.items():
        method, path = key.split(" ", 1)
        pattern, _, convertors = compile_path(path)
        compiled.append((method, pattern, len(convertors), scope))
    return compiled


_ROUTES = _compile(ROUTE_SCOPES)


def listed_scope(method: str, path: str) -> str | None:
    """
    What ROUTE_SCOPES lists for a request, or None for a route nobody listed.

    Where a path fits several listed patterns (`/contacts/search` also fits
    `/contacts/{contact_id}`), the one with the fewest parameters wins; if
    the remaining candidates disagree the route counts as unlisted, so an
    ambiguity closes rather than opens.
    """
    matches = [
        (parameters, scope)
        for route_method, pattern, parameters, scope in _ROUTES
        if route_method == method and pattern.match(path)
    ]
    if not matches:
        return None
    fewest = min(parameters for parameters, _ in matches)
    scopes = {scope for parameters, scope in matches if parameters == fewest}
    return scopes.pop() if len(scopes) == 1 else None


def refusal_for_route(grant: Grant, method: str, path: str) -> Refusal | None:
    """Why `grant` may not call this request, or None when it may."""
    scope = listed_scope(method, path)
    if scope is None:
        return Refusal(None)
    if scope == ANY_KEY:
        return None
    if scope == MCP_TRANSPORT:
        return None if grant.opens_any_tool() else Refusal(None)
    return None if grant.holds(scope) else Refusal(scope)


def refusal_for_tool(grant: Grant, tool: str) -> Refusal | None:
    """Why `grant` may not see or call this MCP tool, or None when it may."""
    scope = TOOL_SCOPES.get(tool)
    if scope is None:
        return Refusal(None)
    return None if grant.holds(scope) else Refusal(scope)


async def report_refusal(principal: Principal, what: str, refusal: Refusal) -> None:
    """Record that a scoped key asked for something its grant does not cover:
    a log line, the audit trail and the user's alert
    (alerts/access_key_refused.py). `what` names the route ("GET /api/mails")
    or tool ("tool send_mail")."""
    from mail_verdict.alerts.access_key_refused import record_refusal

    logger.warning(
        "Scoped key %s refused %s (needs %s)", principal.subject, what,
        refusal.scope or "full access",
    )
    await record_refusal(principal, what, refusal)
