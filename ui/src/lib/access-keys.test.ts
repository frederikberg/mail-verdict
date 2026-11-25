import { test } from "node:test";
import assert from "node:assert/strict";

import {
  emptyDraft,
  grantBody,
  grantLines,
  grantProblem,
  keyName,
  keyState,
  levelOf,
} from "./access-keys.ts";
import type { AccessKey } from "../types/api.ts";

const NAMES = {
  calendar: new Map([["c1", "Work"], ["c2", "Home"]]),
  contacts: new Map([["b1", "Friends"]]),
};

test("a write scope reads too, and nothing else is implied", () => {
  assert.equal(levelOf(["calendar:write"], "calendar"), "write");
  assert.equal(levelOf(["calendar:write"], "contacts"), "none");
  assert.equal(levelOf(["contacts:read", "calendar:read"], "contacts"), "read");
});

test("an untouched form is never full access and cannot be saved", () => {
  const draft = emptyDraft(true);
  assert.equal(draft.full, false);
  assert.notEqual(grantProblem(draft), null);
  assert.equal(grantProblem({ ...draft, full: true }), null);
});

test("a write limit with nothing chosen is refused, an unlimited one is not", () => {
  const draft = { ...emptyDraft(true), calendar: "write" as const };
  assert.notEqual(grantProblem({ ...draft, calendarLimit: [] }), null);
  assert.equal(grantProblem({ ...draft, calendarLimit: null }), null);
  assert.equal(grantProblem({ ...draft, calendarLimit: ["c1"] }), null);
});

test("every write scope names where it applies, null meaning everywhere", () => {
  const base = { ...emptyDraft(true), calendar: "write" as const, contacts: "write" as const };
  assert.deepEqual(grantBody({ ...base, calendarLimit: ["c1"], addressbookLimit: null }), {
    access: "scoped",
    scopes: ["calendar:write", "contacts:write"],
    calendar_write_ids: ["c1"],
    addressbook_write_ids: null,
  });
  // A read scope names no limit; full access carries neither scopes nor limits.
  const read = grantBody({ ...base, calendar: "read", calendarLimit: ["c1"] });
  assert.equal("calendar_write_ids" in read, false);
  assert.deepEqual(grantBody({ ...base, full: true }), { access: "full" });
});

test("a key of someone else keeps its limit but cannot be given a new write scope", () => {
  const foreign = emptyDraft(false);
  // New write scope: the picker cannot name where, so the form refuses.
  assert.notEqual(grantProblem({ ...foreign, calendar: "write" }), null);
  assert.notEqual(grantProblem({ ...foreign, contacts: "write" }), null);
  // Already held: kept as it was, the stored limit sent back.
  const held = {
    ...foreign,
    calendar: "write" as const,
    calendarLimit: ["c1"],
    held: { calendar: "write" as const, contacts: "none" as const },
  };
  assert.equal(grantProblem(held), null);
  assert.deepEqual(grantBody(held).calendar_write_ids, ["c1"]);
});

test("a write limit says where, an unlimited write says everywhere", () => {
  const key = {
    scopes: ["calendar:write", "contacts:write", "contacts:read"],
    calendar_write_ids: ["c2", "gone"],
    addressbook_write_ids: null,
  };
  assert.deepEqual(grantLines(key, NAMES), [
    "Calendars: can read and change, only in Home, one not listed here",
    "Contacts: can read and change, in every address book",
  ]);
});

test("a key is named by its label, else by its subject", () => {
  assert.equal(keyName({ label: " Sync ", subject: "s" }), "Sync");
  assert.equal(keyName({ label: null, subject: "s" }), "s");
});

test("a key with no sign-in yet is unused, a revoked one signed out", () => {
  const base: Pick<AccessKey, "revoked_at" | "sign_in_id"> = { revoked_at: null, sign_in_id: null };
  assert.equal(keyState(base), "unused");
  assert.equal(keyState({ ...base, sign_in_id: "x" }), "active");
  assert.equal(keyState({ revoked_at: "2026-01-01T00:00:00Z", sign_in_id: "x" }), "signed-out");
});
