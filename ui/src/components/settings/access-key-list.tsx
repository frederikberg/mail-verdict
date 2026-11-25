"use client";

/**
 * A list of access keys with what each may do, in plain words. Full access
 * is drawn as a red badge so it cannot be mistaken for a limited key. Used
 * read-only for one's own keys in Settings and with actions for everyone's
 * in Administration; the caller supplies the actions.
 */

import type { ReactNode } from "react";
import { KeyRound, ShieldAlert } from "lucide-react";

import { useAddressbooks } from "@/hooks/use-contacts";
import { useCalendars } from "@/hooks/use-calendars";
import { Badge } from "@/components/ui/badge";
import {
  SCOPED_EXCLUDES,
  grantLines,
  keyName,
  keyState,
  type CollectionNames,
} from "@/lib/access-keys";
import { formatRelativeAgo, formatRelativeDate } from "@/lib/format";
import type { AccessKey } from "@/types/api";

/** Names of the signed-in person's own calendars and address books, which
 * is all the API lists; a limit naming anyone else's is said without a name. */
export function useCollectionNames(): CollectionNames {
  const { data: calendars } = useCalendars();
  const { data: addressbooks } = useAddressbooks();
  return {
    calendar: new Map((calendars ?? []).map((c) => [c.id, c.display_name])),
    contacts: new Map((addressbooks ?? []).map((b) => [b.id, b.display_name])),
  };
}

export function FullAccessBadge() {
  return (
    <Badge variant="destructive" data-testid="full-access-badge">
      <ShieldAlert />
      Full access
    </Badge>
  );
}

export function AccessKeyList({
  keys,
  empty,
  showOwner = false,
  actions,
}: {
  keys: AccessKey[];
  empty: string;
  /** Name the person each key signs in as, for a list across people. */
  showOwner?: boolean;
  actions?: (key: AccessKey) => ReactNode;
}) {
  const names = useCollectionNames();

  if (keys.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>;

  return (
    <div className="flex flex-col gap-2">
      {keys.map((key) => {
        const state = keyState(key);
        const lines = grantLines(key, names);
        const name = keyName(key);
        return (
          <div
            key={key.subject}
            data-testid="access-key"
            className="flex items-start gap-2 rounded-lg border px-3 py-2 text-sm"
          >
            <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span
                  className={
                    state === "signed-out" ? "break-all text-muted-foreground line-through" : "break-all"
                  }
                >
                  {name}
                </span>
                {key.access === "full" ? <FullAccessBadge /> : <Badge variant="outline">Limited</Badge>}
                {state === "signed-out" && <Badge variant="destructive">signed out</Badge>}
              </div>
              {key.label && (
                <div className="break-all font-mono text-xs text-muted-foreground">{key.subject}</div>
              )}
              {key.access === "full" ? (
                <p className="mt-1 text-xs text-destructive">
                  Everything {showOwner ? key.user_display_name : "you"} may do, mail and settings
                  included.
                </p>
              ) : (
                <div className="mt-1 text-xs">
                  {lines.length > 0 ? (
                    <ul className="list-disc pl-4">
                      {lines.map((line) => (
                        <li key={line}>{line}</li>
                      ))}
                    </ul>
                  ) : (
                    <p>Nothing: it can do nothing but ask who it is.</p>
                  )}
                  <p className="mt-0.5 text-muted-foreground">{SCOPED_EXCLUDES}</p>
                </div>
              )}
              <div className="mt-1 text-xs text-muted-foreground">
                {showOwner && <>{key.user_display_name} · </>}
                {state === "signed-out"
                  ? `signed out ${formatRelativeAgo(key.revoked_at)}`
                  : state === "unused"
                    ? "not used yet"
                    : `last used ${formatRelativeAgo(key.last_seen_at)}`}
                {key.first_seen_at && <> · first {formatRelativeDate(key.first_seen_at)}</>}
                {key.last_refusal_at && (
                  <>
                    {" · "}
                    <span className="text-foreground">
                      last turned away {formatRelativeAgo(key.last_refusal_at)}
                    </span>
                  </>
                )}
              </div>
            </div>
            {actions && <div className="flex shrink-0 items-center gap-1">{actions(key)}</div>}
          </div>
        );
      })}
    </div>
  );
}
