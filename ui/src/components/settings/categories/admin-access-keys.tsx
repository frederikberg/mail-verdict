"use client";

/**
 * Admin > Access keys: every key that signs in as a user -- an agent, a
 * script, an MCP client with a token of its own -- with what it may do.
 * An administrator attaches a machine user as a limited or full key,
 * narrows or widens it, renames it and revokes it.
 */

import { useState } from "react";
import { Plus } from "lucide-react";

import { AttachKeyDialog, EditKeyDialog } from "@/components/settings/access-key-dialog";
import { AccessKeyList } from "@/components/settings/access-key-list";
import { CategoryHeader } from "@/components/settings/blocks";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { useAdminAccessKeys, useRemoveSubject } from "@/hooks/use-sign-ins";
import { useToast } from "@/hooks/use-toast";
import { ApiError } from "@/lib/api";
import { keyErrorText, keyName, revokeConsequence } from "@/lib/access-keys";
import type { AccessKey } from "@/types/api";

export function AdminAccessKeys() {
  const { data: keys, isLoading, error } = useAdminAccessKeys();
  const remove = useRemoveSubject();
  const { push } = useToast();
  const [attaching, setAttaching] = useState(false);
  const [editing, setEditing] = useState<AccessKey | null>(null);
  const [revoking, setRevoking] = useState<AccessKey | null>(null);

  return (
    <div className="flex flex-col gap-4">
      <CategoryHeader
        title="Access keys"
        description="Agents, scripts and other clients that sign in with a token of their own, and what each may do. A key is a machine user at your identity provider; attaching it here says whose data it acts on and how much of it. Changes take effect within a minute."
        actions={
          <Button size="sm" onClick={() => setAttaching(true)}>
            <Plus className="mr-1 h-4 w-4" />
            Attach a key
          </Button>
        }
      />
      {isLoading && <Skeleton className="h-24 w-full" />}
      {error && !keys && (
        <p role="alert" className="text-sm text-destructive">
          {error instanceof ApiError ? error.message : "Could not load the access keys."}
        </p>
      )}
      {keys && (
        <AccessKeyList
          keys={keys}
          showOwner
          empty="No access key is attached yet."
          actions={(key) => (
            <>
              <Button
                variant="outline"
                size="sm"
                aria-label={`Change ${keyName(key)}`}
                onClick={() => setEditing(key)}
              >
                Change
              </Button>
              <Button
                variant="destructive"
                size="sm"
                aria-label={`Revoke ${keyName(key)}`}
                onClick={() => setRevoking(key)}
              >
                Revoke
              </Button>
            </>
          )}
        />
      )}
      {attaching && <AttachKeyDialog onClose={() => setAttaching(false)} />}
      {editing && <EditKeyDialog keyData={editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(open) => !open && setRevoking(null)}
        title={revoking ? `Revoke ${keyName(revoking)}?` : ""}
        description={revoking ? revokeConsequence(revoking) : ""}
        confirmLabel="Revoke"
        isConfirming={remove.isPending}
        onConfirm={() => {
          if (!revoking) return;
          remove.mutate(
            { userId: revoking.user_id, subject: revoking.subject },
            {
              onSettled: () => setRevoking(null),
              onError: (err) =>
                push(err instanceof ApiError ? keyErrorText(err.message) : "Could not revoke it", "error"),
            },
          );
        }}
      />
    </div>
  );
}
