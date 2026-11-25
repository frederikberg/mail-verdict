import type { AccessKey, AccessKeyUpdateRequest, AccessScope, AddSubjectRequest } from "@/types/api";

export type Resource = "calendar" | "contacts";
export type Level = "none" | "read" | "write";

/** What a key holds on one resource: a write scope also reads. */
export function levelOf(scopes: readonly string[], resource: Resource): Level {
  if (scopes.includes(`${resource}:write`)) return "write";
  if (scopes.includes(`${resource}:read`)) return "read";
  return "none";
}

/** The scopes that say exactly these levels, nothing implied twice. */
export function scopesFor(levels: Record<Resource, Level>): AccessScope[] {
  const scopes: AccessScope[] = [];
  for (const resource of ["calendar", "contacts"] as const) {
    if (levels[resource] !== "none") scopes.push(`${resource}:${levels[resource]}`);
  }
  return scopes;
}

/** What a key is called in a list: its label, else the subject it signs in as. */
export function keyName(key: Pick<AccessKey, "label" | "subject">): string {
  return key.label?.trim() || key.subject;
}

export type KeyState = "signed-out" | "unused" | "active";

export function keyState(key: Pick<AccessKey, "revoked_at" | "sign_in_id">): KeyState {
  if (key.revoked_at !== null) return "signed-out";
  return key.sign_in_id === null ? "unused" : "active";
}

const RESOURCE_NOUN: Record<Resource, { all: string; one: string }> = {
  calendar: { all: "Calendars", one: "calendars" },
  contacts: { all: "Contacts", one: "address books" },
};

const LEVEL_WORDS: Record<Level, string> = {
  none: "no access",
  read: "can read",
  write: "can read and change",
};

/** Names for the collections a write limit refers to; an id the list no
 * longer has (a deleted calendar) is still said, never dropped. */
export type CollectionNames = {
  calendar: ReadonlyMap<string, string>;
  contacts: ReadonlyMap<string, string>;
};

/** The plain-words lines of a scoped key's grant, one per resource it holds:
 * "Calendars: can read and change, only in Work, Home". */
export function grantLines(
  key: Pick<AccessKey, "scopes" | "calendar_write_ids" | "addressbook_write_ids">,
  names: CollectionNames,
): string[] {
  const lines: string[] = [];
  for (const resource of ["calendar", "contacts"] as const) {
    const level = levelOf(key.scopes, resource);
    if (level === "none") continue;
    const limit = resource === "calendar" ? key.calendar_write_ids : key.addressbook_write_ids;
    let line = `${RESOURCE_NOUN[resource].all}: ${LEVEL_WORDS[level]}`;
    if (level === "write") {
      line += limit
        ? `, only in ${limit.map((id) => names[resource].get(id) ?? "one not listed here").join(", ")}`
        : `, in every ${resource === "calendar" ? "calendar" : "address book"}`;
    }
    lines.push(line);
  }
  return lines;
}

/** What a scoped key can never reach, which is everything not named above. */
export const SCOPED_EXCLUDES = "Mail, settings and every other part of the account are closed to it.";

/** What revoking does, said to whoever is about to. */
export function revokeConsequence(key: Pick<AccessKey, "access" | "user_display_name">): string {
  return `It stops working at once and for good, and it no longer signs in as ${key.user_display_name}. ${
    key.access === "full" ? "It had full access. " : ""
  }To use it again, attach it again.`;
}

/** The form's state: full access, or a level per resource plus optional
 * confinement of the writes to chosen collections (null: every one). */
export interface GrantDraft {
  full: boolean;
  calendar: Level;
  contacts: Level;
  calendarLimit: string[] | null;
  addressbookLimit: string[] | null;
  /** Whether the picker could list the collections: only the signed-in
   * person's own, so a key of someone else keeps whatever limit it has. */
  limitsEditable: boolean;
}

export type GrantBody = Pick<
  AddSubjectRequest & AccessKeyUpdateRequest,
  "access" | "scopes" | "calendar_write_ids" | "addressbook_write_ids"
>;

/** Why a draft cannot be saved yet, said in the form's words, or null. */
export function grantProblem(draft: GrantDraft): string | null {
  if (draft.full) return null;
  if (draft.calendar === "none" && draft.contacts === "none") {
    return "Choose what the key may do, or give it full access.";
  }
  if (draft.limitsEditable) {
    if (draft.calendar === "write" && draft.calendarLimit?.length === 0) {
      return "Choose at least one calendar, or let it change events in every calendar.";
    }
    if (draft.contacts === "write" && draft.addressbookLimit?.length === 0) {
      return "Choose at least one address book, or let it change contacts in every address book.";
    }
  }
  return null;
}

/** The request body a draft stands for. A write limit is named only when
 * the picker could show the collections and the key writes there; leaving
 * it out lets the server clear a limit whose write scope is gone, and keep
 * one this form could not display. */
export function grantBody(draft: GrantDraft): GrantBody {
  if (draft.full) return { access: "full" };
  const body: GrantBody = {
    access: "scoped",
    scopes: scopesFor({ calendar: draft.calendar, contacts: draft.contacts }),
  };
  if (draft.limitsEditable && draft.calendar === "write") {
    body.calendar_write_ids = draft.calendarLimit;
  }
  if (draft.limitsEditable && draft.contacts === "write") {
    body.addressbook_write_ids = draft.addressbookLimit;
  }
  return body;
}

/** The draft an existing key starts from. */
export function draftOf(key: AccessKey, limitsEditable: boolean): GrantDraft {
  return {
    full: key.access === "full",
    calendar: levelOf(key.scopes, "calendar"),
    contacts: levelOf(key.scopes, "contacts"),
    calendarLimit: key.calendar_write_ids,
    addressbookLimit: key.addressbook_write_ids,
    limitsEditable,
  };
}

/** A new key starts limited and holding nothing: full access is something
 * a person chooses, never what an untouched form means. */
export function emptyDraft(limitsEditable: boolean): GrantDraft {
  return {
    full: false,
    calendar: "none",
    contacts: "none",
    calendarLimit: null,
    addressbookLimit: null,
    limitsEditable,
  };
}

const ERROR_WORDS: Record<string, string> = {
  "subject already belongs to a user": "That subject already signs in as someone.",
  unknown_collection: "One of the chosen calendars or address books is not this person's.",
  calendar_limit_needs_calendar_write: "A calendar limit only makes sense when the key may change events.",
  addressbook_limit_needs_contacts_write:
    "An address book limit only makes sense when the key may change contacts.",
  full_access_carries_no_scopes: "Full access cannot also carry a list of things it may do.",
  unknown_scope: "That kind of access does not exist.",
  "this is the subject you are signed in with": "This is the key you are signed in with, so it cannot be changed here.",
};

/** A server refusal of a key change, in plain words; unknown details pass through. */
export function keyErrorText(message: string): string {
  return ERROR_WORDS[message] ?? message;
}
