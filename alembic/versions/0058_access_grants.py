"""Scoped access keys: a grant on each token subject, and an audit trail.

A subject is `full` (everything its user may do, which every existing row
stays) or `scoped` to a list of scopes, optionally with the collections its
writes are confined to. `label` names an access key in the list. The audit
trail has no foreign key onto a subject, so the history of a removed key
stays; its rows go with their user.

Revision ID: 0058_access_grants
Revises: 0057_push_sign_in
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0058_access_grants"
down_revision: str | None = "0057_push_sign_in"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("user_identities", sa.Column("label", sa.Text(), nullable=True))
    op.add_column(
        "user_identities",
        sa.Column("access", sa.Text(), nullable=False, server_default="full"),
    )
    op.add_column(
        "user_identities",
        sa.Column("scopes", postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
    )
    op.add_column(
        "user_identities",
        sa.Column("calendar_write_ids", postgresql.ARRAY(sa.Uuid()), nullable=True),
    )
    op.add_column(
        "user_identities",
        sa.Column("addressbook_write_ids", postgresql.ARRAY(sa.Uuid()), nullable=True),
    )
    op.create_check_constraint(
        "ck_user_identities_access", "user_identities", "access IN ('full', 'scoped')",
    )
    op.create_check_constraint(
        "ck_user_identities_full_has_no_grant", "user_identities",
        "access = 'scoped' OR (scopes = '{}' AND calendar_write_ids IS NULL "
        "AND addressbook_write_ids IS NULL)",
    )

    op.create_table(
        "access_key_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column(
            "user_id", sa.Uuid(),
            sa.ForeignKey("users.id", name="fk_access_key_events_user_id"), nullable=False,
        ),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column(
            "detail", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "kind IN ('created', 'changed', 'revoked', 'refused')",
            name="ck_access_key_events_kind",
        ),
    )
    op.create_index("ix_access_key_events_subject_at", "access_key_events", ["subject", "at"])
    op.create_index("ix_access_key_events_user_id", "access_key_events", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_access_key_events_user_id", table_name="access_key_events")
    op.drop_index("ix_access_key_events_subject_at", table_name="access_key_events")
    op.drop_table("access_key_events")
    op.drop_constraint("ck_user_identities_full_has_no_grant", "user_identities", type_="check")
    op.drop_constraint("ck_user_identities_access", "user_identities", type_="check")
    op.drop_column("user_identities", "addressbook_write_ids")
    op.drop_column("user_identities", "calendar_write_ids")
    op.drop_column("user_identities", "scopes")
    op.drop_column("user_identities", "access")
    op.drop_column("user_identities", "label")
