"""
The MCP half of the scoped-access check (auth/grants.py).

The HTTP gate (auth/middleware.py) cannot read a JSON-RPC body, so it only
lets a scoped key reach /mcp/ at all when its grant opens some tool. Which
tools it sees and may call is decided here, by a FastMCP middleware asking
the same module and the same kind of table (TOOL_SCOPES): the tool list is
filtered to what the grant holds, a call to anything else is refused, and a
tool nobody listed is closed to every scoped key. Resources and prompts are
not part of any scope, so a scoped key sees and reads none.

The principal comes from the HTTP request that carried the message
(auth/principal.py), which is the caller of that call, not whoever opened the
MCP session. Full subjects pass through untouched.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from fastmcp.exceptions import PromptError, ResourceError, ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.base import Tool, ToolResult

from mail_verdict.auth.grants import Grant, Refusal, refusal_for_tool, report_refusal
from mail_verdict.auth.principal import Principal, current_principal


def _scoped() -> tuple[Principal, Grant] | None:
    """The calling principal and its grant, or None for a full subject (or a
    call that carries no principal, which no tool serves)."""
    principal = current_principal()
    if principal is None or principal.grant is None:
        return None
    return principal, principal.grant


def refusal_message(refusal: Refusal) -> str:
    """The error text of a refused call: the JSON body a refused REST request
    carries, so clients read one shape."""
    return json.dumps({"detail": "scope_required", "scope": refusal.scope})


class ScopedKeyMiddleware(Middleware):
    """Limits a scoped access key to the tools its grant holds."""

    async def on_list_tools(
        self, context: MiddlewareContext[Any], call_next: Any,
    ) -> Sequence[Tool]:
        tools: Sequence[Tool] = await call_next(context)
        scoped = _scoped()
        if scoped is None:
            return tools
        _, grant = scoped
        return [tool for tool in tools if refusal_for_tool(grant, tool.name) is None]

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: Any,
    ) -> ToolResult:
        scoped = _scoped()
        if scoped is not None:
            principal, grant = scoped
            name = context.message.name
            refusal = refusal_for_tool(grant, name)
            if refusal is not None:
                await report_refusal(principal, f"tool {name}", refusal)
                raise ToolError(refusal_message(refusal))
        result: ToolResult = await call_next(context)
        return result

    async def on_list_resources(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        return [] if _scoped() is not None else await call_next(context)

    async def on_list_resource_templates(
        self, context: MiddlewareContext[Any], call_next: Any,
    ) -> Any:
        return [] if _scoped() is not None else await call_next(context)

    async def on_list_prompts(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        return [] if _scoped() is not None else await call_next(context)

    async def on_read_resource(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        scoped = _scoped()
        if scoped is not None:
            await report_refusal(scoped[0], "resource read", Refusal(None))
            raise ResourceError(refusal_message(Refusal(None)))
        return await call_next(context)

    async def on_get_prompt(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        scoped = _scoped()
        if scoped is not None:
            await report_refusal(scoped[0], "prompt read", Refusal(None))
            raise PromptError(refusal_message(Refusal(None)))
        return await call_next(context)
