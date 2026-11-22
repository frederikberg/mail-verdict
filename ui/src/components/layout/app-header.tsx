"use client";

/**
 * The one header row every page shares -- previously just the sidebar
 * toggle and the connection indicator, the most valuable strip of screen
 * in the app saying nothing actionable. A global search field lives here
 * instead: its shortcut (`/` by default) focuses it from anywhere, and Enter jumps to the full
 * search page with the query already applied, which stays the place for
 * scope, fields and semantic search rather than duplicating any of that
 * here. Enter writes the search page's own query, so on that page it
 * replaces what the page's field holds -- the page reads `?q=` only on
 * mount, and a same-route navigation does not remount it.
 */

import { useEffect, useRef, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useSetAtom } from "jotai";
import { Search } from "lucide-react";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Input } from "@/components/ui/input";
import { ActionsIndicator } from "@/components/layout/actions-indicator";
import { ConnectionIndicator } from "@/components/layout/connection-indicator";
import { isEditableElement } from "@/lib/utils";
import { useShortcutBindings } from "@/lib/shortcut-bindings";
import { matchAction } from "@/lib/shortcuts";
import { searchQueryAtom } from "@/lib/search-prefs";

export function AppHeader() {
  const router = useRouter();
  const pathname = usePathname();
  const setSearchQuery = useSetAtom(searchQueryAtom);
  const [value, setValue] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const bindings = useShortcutBindings();

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (matchAction(e, bindings, "global") !== "focus_search") return;
      if (isEditableElement(e.target)) return;
      e.preventDefault();
      inputRef.current?.focus();
      inputRef.current?.select();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [bindings]);

  const submit = () => {
    const q = value.trim();
    if (!q) return;
    const url = `/search?q=${encodeURIComponent(q)}`;
    setSearchQuery(q);
    // Already on the page: the atom carries the query, and the URL only has
    // to stay in step for a reload -- a router push there would refetch the
    // route's payload for nothing.
    if (pathname === "/search") window.history.replaceState(null, "", url);
    else router.push(url);
  };

  return (
    <div className="flex items-center gap-2 border-b px-2 py-0.5">
      <SidebarTrigger />
      <div className="relative min-w-0 max-w-sm flex-1">
        <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input
          ref={inputRef}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              submit();
            } else if (e.key === "Escape") {
              setValue("");
              inputRef.current?.blur();
            }
          }}
          placeholder="Search mail…"
          aria-label="Search mail"
          className="h-7 pl-7 text-xs"
        />
      </div>
      <div className="ml-auto flex items-center gap-2">
        <ActionsIndicator />
        <ConnectionIndicator />
      </div>
    </div>
  );
}
