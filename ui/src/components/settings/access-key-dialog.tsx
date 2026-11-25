"use client";

/**
 * Attach a machine user as an access key, or change one. The choice between
 * limited and full access is made on purpose: the form opens limited and
 * empty, and picking full access turns the whole panel red and says what it
 * gives away.
 */

import { useState } from "react";
import { ShieldAlert } from "lucide-react";

import { OptionSelect } from "@/components/settings/setting-fields";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAddressbooks } from "@/hooks/use-contacts";
import { useCalendars } from "@/hooks/use-calendars";
import { useAdminUsers } from "@/hooks/use-admin";
import { useMe } from "@/hooks/use-me";
import { useAddSubject, useUpdateAccessKey } from "@/hooks/use-sign-ins";
import { ApiError } from "@/lib/api";
import {
  draftOf,
  emptyDraft,
  grantBody,
  grantProblem,
  keyErrorText,
  keyName,
  type GrantDraft,
  type Level,
  type Resource,
} from "@/lib/access-keys";
import { cn } from "@/lib/utils";
import type { AccessKey } from "@/types/api";

const LEVELS: { value: Level; label: string }[] = [
  { value: "none", label: "None" },
  { value: "read", label: "Read" },
  { value: "write", label: "Read and change" },
];

function LevelPicker({
  label,
  value,
  onChange,
}: {
  label: string;
  value: Level;
  onChange: (level: Level) => void;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="flex flex-wrap items-center gap-2">
      <span className="w-24 text-sm font-medium">{label}</span>
      <div className="flex overflow-hidden rounded-lg border">
        {LEVELS.map((level) => (
          <button
            key={level.value}
            type="button"
            role="radio"
            aria-checked={value === level.value}
            onClick={() => onChange(level.value)}
            className={cn(
              "px-3 py-1 text-sm transition-colors not-first:border-l",
              value === level.value ? "bg-primary text-primary-foreground" : "hover:bg-muted",
            )}
          >
            {level.label}
          </button>
        ))}
      </div>
    </div>
  );
}

/** Where a key that may change things may do so: everywhere, or in the
 * ticked collections only. */
function WriteLimit({
  noun,
  options,
  value,
  onChange,
}: {
  noun: string;
  options: { id: string; name: string }[];
  value: string[] | null;
  onChange: (ids: string[] | null) => void;
}) {
  const limited = value !== null;
  // Ids the list no longer holds stay tickable so a stale limit can be dropped.
  const known = new Set(options.map((o) => o.id));
  const all = [
    ...options,
    ...(value ?? []).filter((id) => !known.has(id)).map((id) => ({ id, name: `A ${noun} that no longer exists` })),
  ];
  return (
    <div className="ml-26 flex flex-col gap-1.5 text-sm">
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        <label className="flex items-center gap-1.5">
          <input
            type="radio"
            name={`limit-${noun}`}
            checked={!limited}
            onChange={() => onChange(null)}
          />
          Change in every {noun}
        </label>
        <label className="flex items-center gap-1.5">
          <input
            type="radio"
            name={`limit-${noun}`}
            checked={limited}
            onChange={() => onChange([])}
          />
          Change only in chosen ones
        </label>
      </div>
      {limited && (
        <div className="flex flex-col gap-1 pl-5" role="group" aria-label={`Allowed ${noun}s`}>
          {all.length === 0 && <p className="text-xs text-muted-foreground">None to choose from.</p>}
          {all.map((option) => (
            <label key={option.id} className="flex items-center gap-2">
              <Checkbox
                checked={value.includes(option.id)}
                onCheckedChange={(checked) =>
                  onChange(
                    checked ? [...value, option.id] : value.filter((id) => id !== option.id),
                  )
                }
              />
              {option.name}
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

function GrantEditor({
  draft,
  onChange,
  ownerName,
}: {
  draft: GrantDraft;
  onChange: (draft: GrantDraft) => void;
  ownerName: string;
}) {
  const { data: calendars } = useCalendars();
  const { data: addressbooks } = useAddressbooks();
  const set = (patch: Partial<GrantDraft>) => onChange({ ...draft, ...patch });
  const writableCalendars = (calendars ?? [])
    .filter((c) => c.is_enabled && c.holds_events && !c.read_only)
    .map((c) => ({ id: c.id, name: c.display_name }));
  const writableBooks = (addressbooks ?? [])
    .filter((b) => !b.read_only)
    .map((b) => ({ id: b.id, name: b.display_name }));
  const levelRows: { resource: Resource; label: string }[] = [
    { resource: "calendar", label: "Calendars" },
    { resource: "contacts", label: "Contacts" },
  ];

  return (
    <div className="flex flex-col gap-3">
      <div role="radiogroup" aria-label="Access" className="grid gap-2 sm:grid-cols-2">
        <button
          type="button"
          role="radio"
          aria-checked={!draft.full}
          onClick={() => set({ full: false })}
          className={cn(
            "rounded-lg border px-3 py-2 text-left text-sm",
            !draft.full ? "border-primary bg-primary/5" : "hover:bg-muted",
          )}
        >
          <div className="font-medium">Limited</div>
          <div className="text-xs text-muted-foreground">Only what you choose below.</div>
        </button>
        <button
          type="button"
          role="radio"
          aria-checked={draft.full}
          onClick={() => set({ full: true })}
          className={cn(
            "rounded-lg border px-3 py-2 text-left text-sm",
            draft.full ? "border-destructive bg-destructive/10" : "hover:bg-muted",
          )}
        >
          <div className="flex items-center gap-1.5 font-medium text-destructive">
            <ShieldAlert className="h-4 w-4" />
            Full access
          </div>
          <div className="text-xs text-muted-foreground">Everything {ownerName} may do.</div>
        </button>
      </div>

      {draft.full ? (
        <p
          role="alert"
          className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          A key with full access reads and sends all of {ownerName}&apos;s mail, changes their
          settings and accounts, and can do everything they can. Choose Limited unless this is a
          login that should be a person.
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          {levelRows.map(({ resource, label }) => (
            <div key={resource} className="flex flex-col gap-1.5">
              <LevelPicker
                label={label}
                value={draft[resource]}
                onChange={(level) => set({ [resource]: level })}
              />
              {draft[resource] === "write" && draft.limitsEditable && (
                <WriteLimit
                  noun={resource === "calendar" ? "calendar" : "address book"}
                  options={resource === "calendar" ? writableCalendars : writableBooks}
                  value={resource === "calendar" ? draft.calendarLimit : draft.addressbookLimit}
                  onChange={(ids) =>
                    set(resource === "calendar" ? { calendarLimit: ids } : { addressbookLimit: ids })
                  }
                />
              )}
              {draft[resource] === "write" && !draft.limitsEditable && draft.held[resource] === "write" && (
                <p className="ml-26 text-xs text-muted-foreground">
                  Where it may change things stays as it is. Changing that needs the list from this
                  person&apos;s own account, so it is only offered for your own keys.
                </p>
              )}
            </div>
          ))}
          <p className="text-xs text-muted-foreground">
            Mail, settings and every other part of the account stay closed to a limited key.
          </p>
        </div>
      )}
    </div>
  );
}

function errorText(err: unknown, fallback: string): string {
  return err instanceof ApiError ? keyErrorText(err.message) : fallback;
}

/** Attach a new key to one of the users. */
export function AttachKeyDialog({ onClose }: { onClose: () => void }) {
  const me = useMe();
  const { data: users } = useAdminUsers();
  const add = useAddSubject();
  const [label, setLabel] = useState("");
  const [subject, setSubject] = useState("");
  const [userId, setUserId] = useState(me.user_id);
  const [draft, setDraft] = useState<GrantDraft>(emptyDraft(true));
  const [error, setError] = useState<string | null>(null);

  const mine = userId === me.user_id;
  const owner = users?.find((u) => u.id === userId)?.display_name ?? me.display_name;
  const effective = { ...draft, limitsEditable: mine };
  const problem = grantProblem(effective);

  const submit = () => {
    if (add.isPending || problem || !subject.trim()) return;
    add.mutate(
      {
        userId,
        subject: subject.trim(),
        label: label.trim() || null,
        ...grantBody(effective),
      },
      { onSuccess: onClose, onError: (err) => setError(errorText(err, "Could not attach it")) },
    );
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Attach an access key</DialogTitle>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          The machine user is made at your identity provider; this says whose data it acts on and
          what it may do.
        </p>
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="key-label">Name</Label>
            <Input
              id="key-label"
              value={label}
              placeholder="Calendar sync"
              onChange={(e) => setLabel(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="key-subject">Subject</Label>
            <Input
              id="key-subject"
              value={subject}
              placeholder="the sub claim its tokens carry"
              onChange={(e) => setSubject(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label>Acts on the data of</Label>
            <OptionSelect
              aria-label="Acts on the data of"
              value={userId}
              options={(users ?? []).map((u) => ({ value: u.id, label: u.display_name }))}
              placeholder={me.display_name}
              className="w-full"
              onChange={(v) => setUserId(String(v))}
            />
          </div>
          <GrantEditor draft={effective} onChange={setDraft} ownerName={owner} />
        </div>
        {(error || problem) && (
          <p role="alert" className={cn("text-sm", error ? "text-destructive" : "text-muted-foreground")}>
            {error ?? problem}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={draft.full ? "destructive" : "default"}
            disabled={!subject.trim() || problem !== null || add.isPending}
            onClick={submit}
          >
            {draft.full ? "Attach with full access" : "Attach"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/** Rename a key, or narrow or widen what it may do. */
export function EditKeyDialog({ keyData, onClose }: { keyData: AccessKey; onClose: () => void }) {
  const me = useMe();
  const update = useUpdateAccessKey();
  const mine = keyData.user_id === me.user_id;
  const start = draftOf(keyData, mine);
  const [label, setLabel] = useState(keyData.label ?? "");
  const [draft, setDraft] = useState<GrantDraft>(start);
  const [error, setError] = useState<string | null>(null);

  const problem = grantProblem(draft);
  const widening = draft.full && keyData.access !== "full";

  const submit = () => {
    if (update.isPending || problem) return;
    const trimmed = label.trim();
    update.mutate(
      {
        userId: keyData.user_id,
        subject: keyData.subject,
        data: {
          ...(trimmed !== (keyData.label ?? "") ? { label: trimmed || null } : {}),
          ...grantBody(draft),
        },
      },
      { onSuccess: onClose, onError: (err) => setError(errorText(err, "Could not save it")) },
    );
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Change {keyName(keyData)}</DialogTitle>
        </DialogHeader>
        <p className="break-all font-mono text-xs text-muted-foreground">
          {keyData.subject} · signs in as {keyData.user_display_name}
        </p>
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="edit-key-label">Name</Label>
            <Input id="edit-key-label" value={label} onChange={(e) => setLabel(e.target.value)} />
          </div>
          <GrantEditor draft={draft} onChange={setDraft} ownerName={keyData.user_display_name} />
        </div>
        {(error || problem) && (
          <p role="alert" className={cn("text-sm", error ? "text-destructive" : "text-muted-foreground")}>
            {error ?? problem}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={widening ? "destructive" : "default"}
            disabled={problem !== null || update.isPending}
            onClick={submit}
          >
            {widening ? "Give full access" : "Save"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
