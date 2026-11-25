"""What a scoped access key can reach, checked against the application that is served.

The route and tool tables in auth/grants.py are default-deny: a route nobody
listed is closed to every scoped key. These tests hold the other half --
that the tables and the served application agree, so nothing is reachable
by accident -- and that docs/access-matrix.md shows what the matcher decides.
"""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from mail_verdict.auth.grants import (
    ANY_KEY,
    MCP_TRANSPORT,
    ROUTE_SCOPES,
    SCOPES,
    TOOL_SCOPES,
    Grant,
    refusal_for_route,
    refusal_for_tool,
)
from tests.e2e.isolation import UI_ROUTES, enumerate_routes, enumerate_tools

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "export_access_matrix.py"
ONE_SCOPE_EACH = [Grant(frozenset({scope})) for scope in SCOPES]
EVERY_SCOPE = Grant(frozenset(SCOPES))


@pytest.fixture(scope="module")
def exporter() -> ModuleType:
    spec = importlib.util.spec_from_file_location("export_access_matrix", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def served(exporter: ModuleType) -> list[str]:
    routes: list[str] = exporter.served_routes()
    assert routes, "no routes enumerated"
    return routes


def _allowed(route: str, grant: Grant, exporter: ModuleType) -> bool:
    method, path = exporter.concrete(route)
    return refusal_for_route(grant, method, path) is None


def test_the_listed_routes_are_exactly_routes_the_application_serves(
    served: list[str],
) -> None:
    assert not sorted(set(ROUTE_SCOPES) - set(served)), "listed but not served"


def test_every_listed_tool_is_a_tool_the_server_offers() -> None:
    offered = asyncio.run(enumerate_tools())

    assert offered, "no tools enumerated"
    assert not sorted(set(TOOL_SCOPES) - offered), "listed but not offered"


def test_the_exporters_route_walk_matches_the_composed_apps(
    served: list[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mail_verdict.config.loader import reset_config

    monkeypatch.setenv("MAIL_VERDICT_DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:1/x")
    reset_config()
    from mail_verdict.server import create_app

    composed = {
        route for route in enumerate_routes(create_app()) - UI_ROUTES
        if not route.split(" ", 1)[1] == "/mcp"
    }

    assert composed <= set(served), f"served but missing from the export: {composed - set(served)}"
    assert {r for r in served if not r.split(" ", 1)[1].startswith("/mcp")} <= composed


def test_a_route_is_opened_exactly_by_the_grants_that_hold_its_scope(
    served: list[str], exporter: ModuleType,
) -> None:
    for route in served:
        wanted = ROUTE_SCOPES.get(route)
        if wanted is None:
            assert not _allowed(route, EVERY_SCOPE, exporter), f"{route} is unlisted but open"
            continue
        # The route resolves to its own entry, not to a pattern that also fits it.
        for grant in ONE_SCOPE_EACH:
            holds = wanted in (ANY_KEY, MCP_TRANSPORT) or grant.holds(wanted)
            assert _allowed(route, grant, exporter) == holds, f"{route} for {grant.scopes}"


def test_no_route_that_changes_anything_sits_under_a_read_scope() -> None:
    writes = [
        route for route, scope in ROUTE_SCOPES.items()
        if scope.endswith(":read") and route.split(" ", 1)[0] != "GET"
    ]

    assert not writes


def test_an_unlisted_tool_is_closed_to_a_key_holding_every_scope() -> None:
    for tool in asyncio.run(enumerate_tools()):
        refused = refusal_for_tool(EVERY_SCOPE, tool) is not None
        assert refused == (tool not in TOOL_SCOPES), tool


def test_the_committed_matrix_is_current(exporter: ModuleType) -> None:
    diff = exporter.stale_diff(exporter.DEFAULT_PATH)

    assert not diff, "Regenerate with: python scripts/export_access_matrix.py\n" + diff


def test_the_check_fails_when_a_route_changes_what_it_opens(
    exporter: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    document = exporter.DEFAULT_PATH.read_text(encoding="utf-8")
    stale = document.replace(
        "| `GET /api/contacts` | `contacts:read`, `contacts:write` |",
        "| `GET /api/contacts` | full access only |",
    )
    assert stale != document
    path = tmp_path / "access-matrix.md"
    path.write_text(stale, encoding="utf-8")

    assert exporter.main(["--check", "--path", str(path)]) == 1
    assert "GET /api/contacts" in capsys.readouterr().out


def test_the_check_fails_when_a_served_route_has_no_row(
    exporter: ModuleType, tmp_path: Path,
) -> None:
    lines = exporter.DEFAULT_PATH.read_text(encoding="utf-8").splitlines(keepends=True)
    path = tmp_path / "access-matrix.md"
    path.write_text("".join(line for line in lines if "`GET /api/stats`" not in line))

    assert exporter.main(["--check", "--path", str(path)]) == 1

