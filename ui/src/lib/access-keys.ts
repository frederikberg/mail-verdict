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
  /** What the key holds already (none for a new key). Giving a key a write
   * scope it did not hold means naming its limit, which a picker that
   * cannot list the collections cannot do. */
  held: Record<Resource, Level>;
}

export type GrantBody = Pick<
  AddSubjectRequest & AccessKeyUpdateRequest,
  "access" | "scopes" | "calendar_write_ids" | "addressbook_write_ids"
>;

const WRITE_NOUN: Record<Resource, string> = { calendar: "calendar", contacts: "address book" };

/** Why a draft cannot be saved yet, said in the form's words, or null. */
export function grantProblem(draft: GrantDraft): string | null {
  if (draft.full) return null;
  if (draft.calendar === "none" && draft.contacts === "none") {
    return "Choose what the key may do, or give it full access.";
  }
  for (const resource of ["calendar", "contacts"] as const) {
    if (draft[resource] !== "write") continue;
    if (!draft.limitsEditable) {
      if (draft.held[resource] !== "write") {
        return `Choosing which ${WRITE_NOUN[resource]}s it may change needs a list of ${WRITE_NOUN[resource]}s that only that person's own account can show. Attach it as one of your own keys, or leave ${resource === "calendar" ? "calendars" : "contacts"} at Read.`;
      }
      continue;
    }
    const limit = resource === "calendar" ? draft.calendarLimit : draft.addressbookLimit;
    if (limit?.length === 0) {
      return `Choose at least one ${WRITE_NOUN[resource]}, or let it change ${
        resource === "calendar" ? "events" : "contacts"
      } in every ${WRITE_NOUN[resource]}.`;
    }
  }
  return null;
}

/** The request body a draft stands for. Every write scope carries its
 * limit field (null: every collection), because the server refuses a write
 * scope that leaves out where it applies. A key of someone else keeps the
 * limit it has, sent back as it was. */
export function grantBody(draft: GrantDraft): GrantBody {
  if (draft.full) return { access: "full" };
  const body: GrantBody = {
    access: "scoped",
    scopes: scopesFor({ calendar: draft.calendar, contacts: draft.contacts }),
  };
  if (draft.calendar === "write") body.calendar_write_ids = draft.calendarLimit;
  if (draft.contacts === "write") body.addressbook_write_ids = draft.addressbookLimit;
  return body;
}

/** The draft an existing key starts from. */
export function draftOf(key: AccessKey, limitsEditable: boolean): GrantDraft {
  const calendar = levelOf(key.scopes, "calendar");
  const contacts = levelOf(key.scopes, "contacts");
  return {
    full: key.access === "full",
    calendar,
    contacts,
    calendarLimit: key.calendar_write_ids,
    addressbookLimit: key.addressbook_write_ids,
    limitsEditable,
    held: { calendar, contacts },
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
    held: { calendar: "none", contacts: "none" },
  };
}

const ERROR_WORDS: Record<string, string> = {
  "subject already belongs to a user": "That subject already signs in as someone.",
  unknown_collection: "One of the chosen calendars or address books is not this person's.",
  calendar_limit_needs_calendar_write: "A calendar limit only makes sense when the key may change events.",
  addressbook_limit_needs_contacts_write:
    "An address book limit only makes sense when the key may change contacts.",
  full_access_carries_no_scopes: "Full access cannot also carry a list of things it may do.",
  calendar_limit_required:
    "Say which calendars it may change: choose some, or every calendar.",
  addressbook_limit_required:
    "Say which address books it may change: choose some, or every address book.",
  unknown_scope: "That kind of access does not exist.",
  "this is the subject you are signed in with": "This is the key you are signed in with, so it cannot be changed here.",
};

/** A server refusal of a key change, in plain words; unknown details pass through. */
export function keyErrorText(message: string): string {
  return ERROR_WORDS[message] ?? message;
}
