"""
What happens when a scoped access key asks for something its grant does not
cover (auth/grants.py).

A key that suddenly asks for mail is the sign of a stolen credential, so a
refusal is recorded twice. The audit trail (`access_key_events`, kind
`refused`) keeps one row per key and route and hour, counting repeats in
`detail.count`; a key probing many different routes is capped at
MAX_ROWS_PER_HOUR rows, further refusals only raising `detail.suppressed` on
the newest. And the key's user gets one `access_key_refused` alert per key
and day, through the ordinary alert and push path.

Called by both gates, on the refusal path: a failure here is logged and never
becomes the answer to the request.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select, text

from mail_verdict.alerts.dispatch import deliver_alert
from mail_verdict.api.events import get_event_ring
from mail_verdict.auth.access_events import record_access_key_event
from mail_verdict.database.connection import get_db_connection
from mail_verdict.database.models import AccessKeyEvent, UserIdentity
from mail_verdict.database.repository import AlertRepository
from mail_verdict.push.vapid import get_vapid_key_repo

if TYPE_CHECKING:
    from mail_verdict.auth.grants import Refusal
    from mail_verdict.auth.principal import Principal

logger = logging.getLogger(__name__)

ALERT_KIND = "access_key_refused"
MAX_ROWS_PER_HOUR = 50
_WINDOW = timedelta(hours=1)
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _generalised(what: str) -> str:
    """A request as one entry of the trail: ids in the path are not told apart."""
    return _UUID.sub("{id}", what)


async def record_refusal(principal: Principal, what: str, refusal: Refusal) -> None:
    """Write the audit row and raise the day's alert for one refusal. Never
    raises: the request is refused whether or not this works."""
    try:
        await _record(principal, _generalised(what), refusal)
    except Exception:
        logger.exception("Could not record a refused access key request")


async def _record(principal: Principal, what: str, refusal: Refusal) -> None:
    db = get_db_connection()
    now = datetime.now(timezone.utc)
    async with db.session() as session:
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext('access_key_refusal'), hashtext(:key))"),
            {"key": principal.subject},
        )
        recent = (
            await session.execute(
                select(AccessKeyEvent)
                .where(
                    AccessKeyEvent.subject == principal.subject,
                    AccessKeyEvent.kind == "refused",
                    AccessKeyEvent.at >= now - _WINDOW,
                )
                .order_by(AccessKeyEvent.at.desc())
            )
        ).scalars().all()
        same = next((row for row in recent if row.detail.get("what") == what), None)
        if same is not None:
            same.detail = {**same.detail, "count": same.detail.get("count", 1) + 1}
        elif len(recent) >= MAX_ROWS_PER_HOUR:
            newest = recent[0]
            newest.detail = {**newest.detail, "suppressed": newest.detail.get("suppressed", 0) + 1}
        else:
            record_access_key_event(
                session, principal.subject, principal.user_id, "refused",
                detail={"what": what, "scope": refusal.scope, "count": 1},
            )
        label = await session.scalar(
            select(UserIdentity.label).where(UserIdentity.subject == principal.subject)
        )

    alert = await AlertRepository(db).create_user_alert(
        user_id=principal.user_id,
        kind=ALERT_KIND,
        dedupe_key=f"access-key-refused:{principal.subject}:{now.date().isoformat()}",
        title="Access key refused",
        body=(
            f"The access key “{label or principal.subject}” asked for {what}, "
            "which its scopes do not allow."
        ),
    )
    if alert is None:
        return
    try:
        vapid_repo = get_vapid_key_repo()
    except RuntimeError:
        vapid_repo = None
    await deliver_alert(db, get_event_ring(), vapid_repo, alert)
