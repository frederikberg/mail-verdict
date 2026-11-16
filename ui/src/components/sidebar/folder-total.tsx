import { formatCount } from "@/lib/format";
import { cn } from "@/lib/utils";

/** A folder's total message count, dimmed, in a fixed-width column at the
 * row's right edge so the totals of every row line up whether or not an
 * unread badge sits before them. Shown only with the person's
 * `mail.show_folder_totals` setting on. */
export function FolderTotal({ count, className }: { count: number; className?: string }) {
  return (
    <span
      title={`${count.toLocaleString("en")} message${count === 1 ? "" : "s"}`}
      className={cn(
        "min-w-7 text-right text-xs tabular-nums text-muted-foreground group-data-[collapsible=icon]:hidden",
        className,
      )}
    >
      {formatCount(count)}
    </span>
  );
}
