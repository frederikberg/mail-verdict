"""The alert kind `access_key_refused`: a scoped access key asked for something
its scopes do not allow.

It is addressed to the key's user (alerts/access_key_refused.py), once per key
and day.

Revision ID: 0059_access_key_refused_alert
Revises: 0058_access_grants
"""

from __future__ import annotations

from alembic import op

revision: str = "0059_access_key_refused_alert"
down_revision: str | None = "0058_access_grants"
branch_labels: str | None = None
depends_on: str | None = None

_PREVIOUS_ALERT_KINDS = (
    "'mail', 'reminder', 'outbox_stalled', 'glacier_conflict', 'webhook_failed', "
    "'provider_unavailable', 'account_unowned'"
)
_ALERT_KINDS = f"{_PREVIOUS_ALERT_KINDS}, 'access_key_refused'"


def upgrade() -> None:
    op.drop_constraint("ck_alerts_kind", "alerts", type_="check")
    op.create_check_constraint("ck_alerts_kind", "alerts", f"kind IN ({_ALERT_KINDS})")


def downgrade() -> None:
    op.execute("DELETE FROM alerts WHERE kind = 'access_key_refused'")
    op.drop_constraint("ck_alerts_kind", "alerts", type_="check")
    op.create_check_constraint("ck_alerts_kind", "alerts", f"kind IN ({_PREVIOUS_ALERT_KINDS})")
