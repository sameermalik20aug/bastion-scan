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

/**
 * Severity colours, rederived for a light background. Two design constraints:
 *  - WCAG AA: every `text` colour clears 4.5:1 on its own soft `tint`.
 *  - Colourblind-safe: the scale ramps in lightness (deep red -> orange -> gold)
 *    and then jumps hue to blue for "low", giving a protan/deutan-safe anchor.
 * The label always travels with the colour too, so meaning never rests on hue
 * alone. `fill` is the solid colour used by the severity meter segments.
 */
interface SeverityMeta {
  label: string;
  text: string;
  tint: string;
  border: string;
  fill: string;
}

export const SEVERITY_META: Record<Severity, SeverityMeta> = {
  critical: {
    label: "Critical",
    text: "text-red-800",
    tint: "bg-red-50",
    border: "border-red-200",
    fill: "#dc2626",
  },
  high: {
    label: "High",
    text: "text-orange-800",
    tint: "bg-orange-50",
    border: "border-orange-200",
    fill: "#ea580c",
  },
  medium: {
    label: "Medium",
    text: "text-yellow-800",
    tint: "bg-yellow-50",
    border: "border-yellow-200",
    fill: "#ca8a04",
  },
  low: {
    label: "Low",
    text: "text-blue-800",
    tint: "bg-blue-50",
    border: "border-blue-200",
    fill: "#2563eb",
  },
  unknown: {
    label: "Unknown",
    text: "text-slate-600",
    tint: "bg-slate-100",
    border: "border-slate-200",
    fill: "#94a3b8",
  },
};

/** Tailwind classes for a severity badge (border + soft tint + text). */
export function severityBadgeClasses(severity: Severity): string {
  const m = SEVERITY_META[severity];
  return `${m.border} ${m.tint} ${m.text}`;
}

/** Solid accent colour for the left edge of a vulnerability card. */
export function severityAccentVar(severity: Severity): string {
  return SEVERITY_META[severity].fill;
}

/** Just the readable text colour for a severity (used in the summary line). */
export function severityTextColor(severity: Severity): string {
  return SEVERITY_META[severity].text;
}

/** Tailwind classes for the "should I worry" verdict pill. */
export function verdictClasses(verdict: WorryVerdict): string {
  switch (verdict) {
    case "Fix now":
      return "border-red-200 bg-red-50 text-red-800";
    case "Fix this sprint":
      return "border-yellow-200 bg-yellow-50 text-yellow-800";
    case "Low priority":
      return "border-emerald-200 bg-emerald-50 text-emerald-800";
  }
}
