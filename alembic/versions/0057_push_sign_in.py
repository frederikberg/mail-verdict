"""A push subscription records the sign-in it was registered under.

Revoking a sign-in deletes its devices' subscriptions, so a phone signed out
remotely stops receiving notifications. Existing rows start without a link;
a phone app refreshes its registration at least daily, which records it.

Revision ID: 0057_push_sign_in
Revises: 0056_account_unowned_alert
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "0057_push_sign_in"
down_revision: str | None = "0056_account_unowned_alert"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "push_subscriptions",
        sa.Column(
            "sign_in_id", sa.Uuid(),
            sa.ForeignKey(
                "sign_ins.id", ondelete="CASCADE", name="fk_push_subscriptions_sign_in_id",
            ),
            nullable=True,
        ),
    )
    op.create_index("ix_push_subscriptions_sign_in_id", "push_subscriptions", ["sign_in_id"])


def downgrade() -> None:
    op.drop_index("ix_push_subscriptions_sign_in_id", table_name="push_subscriptions")
    op.drop_column("push_subscriptions", "sign_in_id")
