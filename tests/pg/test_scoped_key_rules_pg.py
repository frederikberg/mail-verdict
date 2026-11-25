"""
What a scoped access key may not do with events and contacts, and the
idempotent event uid, against a real database.

The routes are mounted bare, acting as a key through its Scope: the gate that
decides which routes a key reaches has its own tests, so these hold what the
handlers themselves refuse -- writes outside the calendars and address books
a key is limited to, and anything that would send scheduling mail.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from mail_verdict.api.calendar_events import router as events_router
from mail_verdict.api.contacts import router as contacts_router
from mail_verdict.auth.grants import Grant
from mail_verdict.auth.principal import OWNER_USER_ID
from mail_verdict.auth.scope import Scope
from mail_verdict.calendar import ical, vcard
from mail_verdict.database.connection import DatabaseConnection
from mail_verdict.postimap.actions import create_object
from mail_verdict.settings.service import init_settings_service, reset_settings_service
from tests.helpers.auth import act_as, act_as_owner_of_everything

_EVENTS = "mail_verdict.api.calendar_events.get_db_connection"
_CONTACTS = "mail_verdict.api.contacts.get_db_connection"


@pytest.fixture()
def app(migrated_db: DatabaseConnection) -> FastAPI:
    app = FastAPI()
    app.include_router(events_router)
    app.include_router(contacts_router)
    act_as_owner_of_everything(app, migrated_db)
    return app


@pytest.fixture()
def client(app: FastAPI, migrated_db: DatabaseConnection) -> Iterator[TestClient]:
    with TestClient(app) as c:
        c.portal.call(init_settings_service, migrated_db)
        yield c
        c.portal.call(reset_settings_service)


async def _seed_collection(db: DatabaseConnection, kind: str) -> tuple[uuid.UUID, uuid.UUID]:
    """A DAV account with one collection of `kind`; returns (account, collection)."""
    account_id, collection_id = uuid.uuid4(), uuid.uuid4()
    async with db.session() as session:
        await session.execute(
            text(
                "INSERT INTO dav_accounts (id, name, url, username, password) "
                "VALUES (:id, :name, 'https://dav.example.com/', 'user@example.com', "
                "'\\x00' || convert_to('pw', 'UTF8'))"
            ),
            {"id": account_id, "name": f"dav-{account_id}"},
        )
        await session.execute(
            text(
                "INSERT INTO dav_collections (id, account_id, kind, slug, display_name) "
                "VALUES (:id, :account, :kind, :slug, 'Collection')"
            ),
            {
                "id": collection_id, "account": account_id, "kind": kind,
                "slug": f"c-{collection_id}",
            },
        )
    return account_id, collection_id


async def _seed_event(
    db: DatabaseConnection, account_id: uuid.UUID, calendar_id: uuid.UUID,
    attendee: bool = False,
) -> uuid.UUID:
    data = ical.build_new_event(
        summary="Existing", dtstart=datetime(2026, 9, 10, 10, tzinfo=timezone.utc),
        dtend=datetime(2026, 9, 10, 11, tzinfo=timezone.utc),
        organizer_email="me@example.com" if attendee else None,
        attendees=[("anna@example.com", None)] if attendee else None,
    )
    async with db.session() as session:
        obj = await create_object(
            session, dav_account_id=account_id, collection_id=calendar_id, data=data,
        )
    return obj.id


_GUEST_ON_ONE_OCCURRENCE = (
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n"
    "BEGIN:VEVENT\r\nUID:one-guest\r\nDTSTAMP:20260901T120000Z\r\n"
    "DTSTART:20260910T100000Z\r\nDTEND:20260910T110000Z\r\nSUMMARY:Standup\r\n"
    "RRULE:FREQ=DAILY;COUNT=3\r\nORGANIZER:mailto:me@example.com\r\nEND:VEVENT\r\n"
    "BEGIN:VEVENT\r\nUID:one-guest\r\nRECURRENCE-ID:20260911T100000Z\r\n"
    "DTSTAMP:20260901T120000Z\r\nDTSTART:20260911T120000Z\r\nDTEND:20260911T130000Z\r\n"
    "SUMMARY:Standup with Anna\r\nORGANIZER:mailto:me@example.com\r\n"
    "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:anna@example.com\r\nEND:VEVENT\r\n"
    "END:VCALENDAR\r\n"
)


async def _seed_contact(
    db: DatabaseConnection, account_id: uuid.UUID, addressbook_id: uuid.UUID,
) -> uuid.UUID:
    data = vcard.build_contact(
        summary="Anna Example", emails=[vcard.ContactEmail(email="anna@example.com", type=None)],
    )
    async with db.session() as session:
        obj = await create_object(
            session, dav_account_id=account_id, collection_id=addressbook_id, data=data,
        )
    return obj.id


async def _count(db: DatabaseConnection, query: str, params: dict[str, object]) -> int:
    async with db.session() as session:
        return int(await session.scalar(text(query), params) or 0)


def _key(
    *accounts: uuid.UUID, scopes: set[str], calendars: set[uuid.UUID] | None = None,
    addressbooks: set[uuid.UUID] | None = None,
) -> Scope:
    return Scope(
        user_id=OWNER_USER_ID, is_admin=False, dav_account_ids=frozenset(accounts),
        grant=Grant(frozenset(scopes), frozenset(calendars) if calendars is not None else None,
                    frozenset(addressbooks) if addressbooks is not None else None),
    )


_NEW_EVENT = {
    "summary": "Planned", "dtstart": "2026-09-10T10:00:00+00:00",
    "dtend": "2026-09-10T11:00:00+00:00",
}


# --- the uid ------------------------------------------------------------------


class TestEventUid:
    def test_the_same_uid_in_one_calendar_returns_the_event_already_there(
        self, client: TestClient, migrated_db: DatabaseConnection,
    ) -> None:
        _, calendar = client.portal.call(_seed_collection, migrated_db, "calendar")
        body = {**_NEW_EVENT, "calendar_id": str(calendar), "uid": "todo-1"}
        with patch(_EVENTS, return_value=migrated_db):
            first = client.post("/calendar/events", json=body)
            again = client.post("/calendar/events", json={**body, "summary": "Changed"})

        assert first.status_code == 201 and first.json()["uid"] == "todo-1"
        assert again.status_code == 200
        assert again.json()["object_id"] == first.json()["object_id"]
        assert again.json()["summary"] == "Planned"
        assert client.portal.call(
            _count, migrated_db,
            "SELECT count(*) FROM dav_objects WHERE collection_id = :c", {"c": calendar},
        ) == 1

    def test_the_uid_is_scoped_to_its_calendar_and_free_again_after_a_delete(
        self, client: TestClient, migrated_db: DatabaseConnection,
    ) -> None:
        _, one = client.portal.call(_seed_collection, migrated_db, "calendar")
        _, two = client.portal.call(_seed_collection, migrated_db, "calendar")
        with patch(_EVENTS, return_value=migrated_db):
            first = client.post(
                "/calendar/events", json={**_NEW_EVENT, "calendar_id": str(one), "uid": "x-1"},
            )
            elsewhere = client.post(
                "/calendar/events", json={**_NEW_EVENT, "calendar_id": str(two), "uid": "x-1"},
            )
            deleted = client.delete(f"/calendar/events/{first.json()['object_id']}")
            recreated = client.post(
                "/calendar/events", json={**_NEW_EVENT, "calendar_id": str(one), "uid": "x-1"},
            )

        assert elsewhere.status_code == 201
        assert elsewhere.json()["object_id"] != first.json()["object_id"]
        assert deleted.status_code == 204
        assert recreated.status_code == 201
        assert recreated.json()["object_id"] != first.json()["object_id"]

    def test_a_row_whose_uid_is_not_parsed_yet_is_still_found(
        self, client: TestClient, migrated_db: DatabaseConnection,
    ) -> None:
        """A retry right after the first request meets a row PostIMAP has not
        read yet, its uid column empty."""
        _, calendar = client.portal.call(_seed_collection, migrated_db, "calendar")
        body = {**_NEW_EVENT, "calendar_id": str(calendar), "uid": "unparsed-1"}
        with patch(_EVENTS, return_value=migrated_db):
            first = client.post("/calendar/events", json=body)
            client.portal.call(
                _count, migrated_db,
                "WITH u AS (UPDATE dav_objects SET uid = NULL WHERE collection_id = :c "
                "RETURNING 1) SELECT count(*) FROM u", {"c": calendar},
            )
            again = client.post("/calendar/events", json=body)

        assert again.status_code == 200
        assert again.json()["object_id"] == first.json()["object_id"]

    def test_simultaneous_creates_with_one_uid_make_one_event(
        self, client: TestClient, migrated_db: DatabaseConnection,
    ) -> None:
        _, calendar = client.portal.call(_seed_collection, migrated_db, "calendar")
        body = {**_NEW_EVENT, "calendar_id": str(calendar), "uid": "race-1"}
        statuses: list[int] = []
        start = threading.Barrier(8)

        def create() -> None:
            start.wait()
            statuses.append(client.post("/calendar/events", json=body).status_code)

        with patch(_EVENTS, return_value=migrated_db):
            threads = [threading.Thread(target=create) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        assert sorted(statuses) == [200] * 7 + [201]
        assert client.portal.call(
            _count, migrated_db,
            "SELECT count(*) FROM dav_objects WHERE collection_id = :c", {"c": calendar},
        ) == 1

    def test_a_uid_that_could_not_be_a_file_name_is_refused(
        self, client: TestClient, migrated_db: DatabaseConnection,
    ) -> None:
        _, calendar = client.portal.call(_seed_collection, migrated_db, "calendar")
        with patch(_EVENTS, return_value=migrated_db):
            response = client.post(
                "/calendar/events",
                json={**_NEW_EVENT, "calendar_id": str(calendar), "uid": "../etc"},
            )

        assert response.status_code == 422


# --- a key's calendar rules ------------------------------------------------------


class TestScopedKeyAndEvents:
    def _setup(
        self, client: TestClient, app: FastAPI, db: DatabaseConnection,
    ) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
        account, allowed = client.portal.call(_seed_collection, db, "calendar")
        other_account, other = client.portal.call(_seed_collection, db, "calendar")
        act_as(app, _key(
            account, other_account, scopes={"calendar:write"}, calendars={allowed},
        ))
        return account, allowed, other_account, other

    def test_a_key_writes_only_into_the_calendars_it_is_limited_to(
        self, client: TestClient, app: FastAPI, migrated_db: DatabaseConnection,
    ) -> None:
        _, allowed, _, other = self._setup(client, app, migrated_db)
        with patch(_EVENTS, return_value=migrated_db):
            inside = client.post(
                "/calendar/events", json={**_NEW_EVENT, "calendar_id": str(allowed)},
            )
            outside = client.post(
                "/calendar/events", json={**_NEW_EVENT, "calendar_id": str(other)},
            )

        assert inside.status_code == 201
        assert outside.status_code == 403
        assert outside.json() == {"detail": "collection_not_writable"}

    def test_a_key_cannot_edit_delete_or_move_an_event_outside_its_calendars(
        self, client: TestClient, app: FastAPI, migrated_db: DatabaseConnection,
    ) -> None:
        account, allowed, other_account, other = self._setup(client, app, migrated_db)
        mine = client.portal.call(_seed_event, migrated_db, account, allowed)
        theirs = client.portal.call(_seed_event, migrated_db, other_account, other)
        with patch(_EVENTS, return_value=migrated_db):
            edit = client.patch(f"/calendar/events/{theirs}", json={"summary": "x"})
            delete = client.delete(f"/calendar/events/{theirs}")
            move_out = client.patch(f"/calendar/events/{mine}", json={"calendar_id": str(other)})
            edit_mine = client.patch(f"/calendar/events/{mine}", json={"summary": "Mine"})
            delete_mine = client.delete(f"/calendar/events/{mine}")

        for refused in (edit, delete, move_out):
            assert refused.status_code == 403
            assert refused.json() == {"detail": "collection_not_writable"}
        assert edit_mine.status_code == 200 and edit_mine.json()["summary"] == "Mine"
        assert delete_mine.status_code == 204

    def test_a_key_never_creates_an_event_with_attendees(
        self, client: TestClient, app: FastAPI, migrated_db: DatabaseConnection,
    ) -> None:
        _, allowed, _, _ = self._setup(client, app, migrated_db)
        with patch(_EVENTS, return_value=migrated_db):
            response = client.post(
                "/calendar/events",
                json={
                    **_NEW_EVENT, "calendar_id": str(allowed),
                    "attendees": [{"email": "anna@example.com"}],
                },
            )

        assert response.status_code == 403
        assert response.json() == {"detail": "scope_forbids_scheduling"}
        assert client.portal.call(
            _count, migrated_db,
            "SELECT count(*) FROM dav_objects WHERE collection_id = :c", {"c": allowed},
        ) == 0

    def test_a_key_never_edits_or_deletes_an_event_that_has_attendees(
        self, client: TestClient, app: FastAPI, migrated_db: DatabaseConnection,
    ) -> None:
        account, allowed, _, _ = self._setup(client, app, migrated_db)
        invited = client.portal.call(_seed_event, migrated_db, account, allowed, True)
        with patch(_EVENTS, return_value=migrated_db):
            edit = client.patch(f"/calendar/events/{invited}", json={"summary": "x"})
            delete = client.delete(f"/calendar/events/{invited}")

        for refused in (edit, delete):
            assert refused.status_code == 403
            assert refused.json() == {"detail": "scope_forbids_scheduling"}
        assert client.portal.call(
            _count, migrated_db,
            "SELECT count(*) FROM dav_objects WHERE id = :i AND deleted_at IS NULL", {"i": invited},
        ) == 1

    def test_a_guest_on_one_occurrence_only_counts_as_attendees(
        self, client: TestClient, app: FastAPI, migrated_db: DatabaseConnection,
    ) -> None:
        """The master has no ATTENDEE, one overridden occurrence does: touching
        the event still owes that guest an update or a cancellation."""
        account, allowed, _, _ = self._setup(client, app, migrated_db)

        async def seed() -> uuid.UUID:
            async with migrated_db.session() as session:
                obj = await create_object(
                    session, dav_account_id=account, collection_id=allowed,
                    data=_GUEST_ON_ONE_OCCURRENCE,
                )
            return obj.id

        event = client.portal.call(seed)
        with patch(_EVENTS, return_value=migrated_db):
            edit = client.patch(f"/calendar/events/{event}", json={"summary": "x"})
            delete = client.delete(f"/calendar/events/{event}")

        for refused in (edit, delete):
            assert refused.status_code == 403
            assert refused.json() == {"detail": "scope_forbids_scheduling"}

    def test_a_key_cannot_reuse_the_uid_of_an_event_it_can_see_elsewhere(
        self, client: TestClient, app: FastAPI, migrated_db: DatabaseConnection,
    ) -> None:
        account, allowed, other_account, other = self._setup(client, app, migrated_db)
        act_as_owner_of_everything(app, migrated_db)
        with patch(_EVENTS, return_value=migrated_db):
            theirs = client.post(
                "/calendar/events",
                json={**_NEW_EVENT, "calendar_id": str(other), "uid": "taken-1"},
            )
            act_as(app, _key(account, other_account, scopes={"calendar:write"}))
            twin = client.post(
                "/calendar/events",
                json={**_NEW_EVENT, "calendar_id": str(allowed), "uid": "taken-1"},
            )
            act_as_owner_of_everything(app, migrated_db)
            as_owner = client.post(
                "/calendar/events",
                json={**_NEW_EVENT, "calendar_id": str(allowed), "uid": "taken-1"},
            )

        assert theirs.status_code == 201
        assert twin.status_code == 409 and twin.json() == {"detail": "uid_in_use"}
        assert as_owner.status_code == 201

    def test_full_access_is_not_limited_by_any_of_it(
        self, client: TestClient, migrated_db: DatabaseConnection,
    ) -> None:
        account, calendar = client.portal.call(_seed_collection, migrated_db, "calendar")
        invited = client.portal.call(_seed_event, migrated_db, account, calendar, True)
        with patch(_EVENTS, return_value=migrated_db):
            edit = client.patch(f"/calendar/events/{invited}", json={"summary": "x"})

        assert edit.status_code == 200


# --- a key's address-book rules --------------------------------------------------


def test_a_key_writes_contacts_only_into_the_address_books_it_is_limited_to(
    client: TestClient, app: FastAPI, migrated_db: DatabaseConnection,
) -> None:
    account, allowed = client.portal.call(_seed_collection, migrated_db, "addressbook")
    other_account, other = client.portal.call(_seed_collection, migrated_db, "addressbook")
    mine = client.portal.call(_seed_contact, migrated_db, account, allowed)
    theirs = client.portal.call(_seed_contact, migrated_db, other_account, other)
    act_as(app, _key(
        account, other_account, scopes={"contacts:write"}, addressbooks={allowed},
    ))
    new = {"summary": "Ben", "emails": [{"email": "ben@example.com"}]}

    with patch(_CONTACTS, return_value=migrated_db):
        created = client.post("/contacts", json={**new, "addressbook_id": str(allowed)})
        refused_create = client.post("/contacts", json={**new, "addressbook_id": str(other)})
        refused_edit = client.patch(f"/contacts/{theirs}", json={"summary": "x"})
        refused_delete = client.delete(f"/contacts/{theirs}")
        edited = client.patch(f"/contacts/{mine}", json={"summary": "Anna B"})
        deleted = client.delete(f"/contacts/{mine}")

    assert created.status_code == 201
    for refused in (refused_create, refused_edit, refused_delete):
        assert refused.status_code == 403
        assert refused.json() == {"detail": "collection_not_writable"}
    assert edited.status_code == 200
    assert deleted.status_code == 204
