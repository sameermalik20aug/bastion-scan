/** Severity & verdict presentation helpers, shared across the report UI. */
import type { Severity, WorryVerdict } from "@/types/scan";

/** Sort order for severities, most urgent first. */
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[a] - SEVERITY_RANK[b];
}

/** Tailwind classes for a severity badge (border + soft background + text). */
export function severityBadgeClasses(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "border-red-500/30 bg-red-500/15 text-red-300";
    case "high":
      return "border-orange-500/30 bg-orange-500/15 text-orange-300";
    case "medium":
      return "border-amber-500/30 bg-amber-500/15 text-amber-300";
    case "low":
      return "border-sky-500/30 bg-sky-500/15 text-sky-300";
    case "unknown":
    default:
      return "border-zinc-500/30 bg-zinc-500/15 text-zinc-300";
  }
}

/** A thin accent bar color for the left edge of a vulnerability card. */
export function severityAccentClasses(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "bg-red-500";
    case "high":
      return "bg-orange-500";
    case "medium":
      return "bg-amber-500";
    case "low":
      return "bg-sky-500";
    case "unknown":
    default:
      return "bg-zinc-500";
  }
}

/** Tailwind classes for the "should I worry" verdict pill. */
export function verdictClasses(verdict: WorryVerdict): string {
  switch (verdict) {
    case "Fix now":
      return "border-red-500/30 bg-red-500/15 text-red-300";
    case "Fix this sprint":
      return "border-amber-500/30 bg-amber-500/15 text-amber-300";
    case "Low priority":
      return "border-emerald-500/30 bg-emerald-500/15 text-emerald-300";
  }
}
