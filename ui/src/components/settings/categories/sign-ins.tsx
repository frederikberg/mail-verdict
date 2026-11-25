"use client";

/**
 * Settings > Signed-in devices: the caller's own phones and browsers, and
 * their access keys with what each may do, each of which they can sign out.
 * Keys are changed by an administrator, not here.
 */

import { useState } from "react";

import { AccessKeyList } from "@/components/settings/access-key-list";
import { CategoryHeader } from "@/components/settings/blocks";
import { SignInList } from "@/components/settings/sign-in-list";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { useOwnAccessKeys, useOwnSignIns, useRevokeOwnSignIn } from "@/hooks/use-sign-ins";
import { useToast } from "@/hooks/use-toast";
import { ApiError } from "@/lib/api";
import { keyName, keyState } from "@/lib/access-keys";
import type { AccessKey } from "@/types/api";

export function SignInsSettings() {
  const { data: signIns, isLoading, error } = useOwnSignIns();
  const { data: keys, error: keysError } = useOwnAccessKeys();
  const revoke = useRevokeOwnSignIn();
  const { push } = useToast();
  const [signingOut, setSigningOut] = useState<AccessKey | null>(null);

  return (
    <div className="flex flex-col gap-4">
      <CategoryHeader
        title="Signed-in devices"
        description="Every phone that has used your account, and your web browsers together. Signing one out takes effect on its next request."
      />
      {isLoading && <Skeleton className="h-24 w-full" />}
      {error && !signIns && (
        <p role="alert" className="text-sm text-destructive">
          {error instanceof ApiError ? error.message : "Could not load your sign-ins."}
        </p>
      )}
      {signIns && (
        <SignInList
          signIns={signIns.filter((signIn) => signIn.kind !== "machine")}
          isRevoking={revoke.isPending}
          empty="Nothing has signed in yet."
          onRevoke={(signIn) =>
            revoke.mutateAsync(signIn.id).catch((err: unknown) =>
              push(err instanceof ApiError ? err.message : "Could not sign it out", "error"),
            )
          }
        />
      )}

      <CategoryHeader
        title="Access keys"
        description="Agents, scripts and other clients that act as you, and what each may do. An administrator changes what a key may do."
      />
      {!keys && !keysError && <Skeleton className="h-16 w-full" />}
      {keysError && !keys && (
        <p role="alert" className="text-sm text-destructive">
          {keysError instanceof ApiError ? keysError.message : "Could not load your access keys."}
        </p>
      )}
      {keys && (
        <AccessKeyList
          keys={keys}
          empty="No access key acts as you."
          actions={(key) =>
            keyState(key) === "active" && (
              <Button
                variant="outline"
                size="sm"
                aria-label={`Sign out ${keyName(key)}`}
                onClick={() => setSigningOut(key)}
              >
                Sign out
              </Button>
            )
          }
        />
      )}
      <ConfirmDialog
        open={signingOut !== null}
        onOpenChange={(open) => !open && setSigningOut(null)}
        title={signingOut ? `Sign out ${keyName(signingOut)}?` : ""}
        description="This access key stops working for good. A replacement is attached again by an administrator."
        confirmLabel="Sign out"
        isConfirming={revoke.isPending}
        onConfirm={() => {
          const signInId = signingOut?.sign_in_id;
          if (!signInId) return;
          void revoke
            .mutateAsync(signInId)
            .catch((err: unknown) =>
              push(err instanceof ApiError ? err.message : "Could not sign it out", "error"),
            )
            .finally(() => setSigningOut(null));
        }}
      />
    </div>
  );
}
