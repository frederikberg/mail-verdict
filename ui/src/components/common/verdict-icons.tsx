import { createLucideIcon } from "lucide-react";

/** A face with a halo: rules a message not spam. Drawn on Lucide's 24-unit
 * grid with its stroke, so it sits among the other toolbar icons. */
export const NotSpamIcon = createLucideIcon("not-spam", [
  ["ellipse", { cx: "12", cy: "2.6", rx: "7", ry: "1.3", key: "halo" }],
  ["circle", { cx: "12", cy: "15", r: "8", key: "face" }],
  ["path", { d: "M8.8 16.8s1.2 1.6 3.2 1.6 3.2-1.6 3.2-1.6", key: "mouth" }],
  ["path", { d: "M9.3 12.8h.01M14.7 12.8h.01", key: "eyes" }],
]);

/** A face with horns: rules a message spam. */
export const SpamIcon = createLucideIcon("spam", [
  ["path", { d: "M6.3 9.4 4.6 3 9.2 7.5M17.7 9.4 19.4 3l-4.6 4.5", key: "horns" }],
  ["circle", { cx: "12", cy: "15", r: "8", key: "face" }],
  ["path", { d: "M8.8 16.8s1.2 1.6 3.2 1.6 3.2-1.6 3.2-1.6", key: "mouth" }],
  ["path", { d: "M8.7 12.1l1.9 1M15.3 12.1l-1.9 1", key: "eyes" }],
]);
