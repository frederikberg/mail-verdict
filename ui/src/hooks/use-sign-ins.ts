/** TanStack Query hooks for signed-in phones, browsers and machine clients. */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { AccessKeyUpdateRequest, AddSubjectRequest, SignIn } from "@/types/api";

export const signInKeys = {
  own: ["sign-ins", "own"] as const,
  ownKeys: ["sign-ins", "access-keys"] as const,
  adminKeys: ["admin", "access-keys"] as const,
  admin: (filter: { userId?: string; kind?: SignIn["kind"] }) =>
    ["admin", "sign-ins", filter.userId ?? "", filter.kind ?? ""] as const,
};

/** The caller's own sign-ins. */
export function useOwnSignIns() {
  return useQuery({ queryKey: signInKeys.own, queryFn: () => api.me.signIns(), staleTime: 15_000 });
}

/** The caller's own access keys, read-only. */
export function useOwnAccessKeys() {
  return useQuery({
    queryKey: signInKeys.ownKeys,
    queryFn: () => api.me.accessKeys(),
    staleTime: 15_000,
  });
}

/** Every access key of every user, for an administrator. */
export function useAdminAccessKeys() {
  return useQuery({
    queryKey: signInKeys.adminKeys,
    queryFn: () => api.admin.accessKeys(),
    staleTime: 15_000,
  });
}

/** Any user's sign-ins, or one kind's, for an administrator. */
export function useAdminSignIns(
  filter: { userId?: string; kind?: SignIn["kind"] },
  options: { enabled?: boolean } = {},
) {
  return useQuery({
    queryKey: signInKeys.admin(filter),
    queryFn: () => api.admin.signIns(filter),
    staleTime: 15_000,
    enabled: options.enabled ?? true,
  });
}

function useInvalidateSignIns() {
  const qc = useQueryClient();
  return () =>
    Promise.all([
      qc.invalidateQueries({ queryKey: ["sign-ins"] }),
      qc.invalidateQueries({ queryKey: ["admin"] }),
    ]);
}

export function useRevokeOwnSignIn() {
  const invalidate = useInvalidateSignIns();
  return useMutation({ mutationFn: (id: string) => api.me.revokeSignIn(id), onSuccess: invalidate });
}

export function useRevokeSignIn() {
  const invalidate = useInvalidateSignIns();
  return useMutation({ mutationFn: (id: string) => api.admin.revokeSignIn(id), onSuccess: invalidate });
}

export function useSignOutUser() {
  const invalidate = useInvalidateSignIns();
  return useMutation({
    mutationFn: (userId: string) => api.admin.signOutUser(userId),
    onSuccess: invalidate,
  });
}

export function useAddSubject() {
  const invalidate = useInvalidateSignIns();
  return useMutation({
    mutationFn: ({ userId, ...data }: { userId: string } & AddSubjectRequest) =>
      api.admin.addSubject(userId, data),
    onSuccess: invalidate,
  });
}

export function useRemoveSubject() {
  const invalidate = useInvalidateSignIns();
  return useMutation({
    mutationFn: ({ userId, subject }: { userId: string; subject: string }) =>
      api.admin.removeSubject(userId, subject),
    onSuccess: invalidate,
  });
}

export function useUpdateAccessKey() {
  const invalidate = useInvalidateSignIns();
  return useMutation({
    mutationFn: ({
      userId,
      subject,
      data,
    }: {
      userId: string;
      subject: string;
      data: AccessKeyUpdateRequest;
    }) => api.admin.updateAccessKey(userId, subject, data),
    onSuccess: invalidate,
  });
}
