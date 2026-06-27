/**
 * TypeScript mirror of the backend Pydantic models in
 * `backend/app/models/schemas.py`. Keep these in sync with that file — the names
 * and casing (notably the OSV ecosystem identifiers) are exact.
 */

/** Matches the backend `Severity` Literal. */
export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

/**
 * Matches the backend `Ecosystem` Literal. OSV uses exact, case-sensitive
 * identifiers — do not lowercase these.
 */
export type Ecosystem = "npm" | "PyPI" | "Maven" | "RubyGems";

/**
 * The three verdicts the AI layer is allowed to return (backend `WorryVerdict`).
 * Anything else is rejected server-side and never reaches us.
 */
export type WorryVerdict = "Fix now" | "Fix this sprint" | "Low priority";

/** Mirror of the backend `Vulnerability` model. */
export interface Vulnerability {
  id: string;
  package: string;
  current_version: string;
  severity: Severity;
  summary: string;
  /**
   * Present only when an Anthropic key was supplied. It is EITHER a JSON string
   * encoding an {@link AiExplanation} (the happy path), OR the raw OSV summary
   * (the server's graceful fallback when a model call failed). `null` in no-key
   * mode. Use {@link parseAiExplanation} to handle all three cases.
   */
  ai_explanation: string | null;
  is_direct: boolean;
  fixed_version: string | null;
  is_breaking_upgrade: boolean;
}

/** Mirror of the backend `PackageResult` model. */
export interface PackageResult {
  name: string;
  version: string;
  is_direct: boolean;
  vulnerabilities: Vulnerability[];
}

/** Mirror of the backend `ScanResult` model — the full scan response. */
export interface ScanResult {
  ecosystem: Ecosystem;
  packages: PackageResult[];
  total_packages: number;
  total_vulnerabilities: number;
  /** Regenerated manifest with safe versions substituted; `null` if nothing changed. */
  fixed_manifest: string | null;
  fix_notice: string | null;
  /** One-paragraph AI overview; `null` in no-key mode or if the call failed. */
  executive_summary: string | null;
}

/**
 * The decoded shape of {@link Vulnerability.ai_explanation} on the happy path.
 * Mirrors the backend `VulnExplanation` model.
 */
export interface AiExplanation {
  what_it_is: string;
  real_world_risk: string;
  should_i_worry: WorryVerdict;
  fix_note: string;
}

const WORRY_VERDICTS: ReadonlySet<string> = new Set([
  "Fix now",
  "Fix this sprint",
  "Low priority",
]);

function isAiExplanation(value: unknown): value is AiExplanation {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.what_it_is === "string" &&
    typeof v.real_world_risk === "string" &&
    typeof v.fix_note === "string" &&
    typeof v.should_i_worry === "string" &&
    WORRY_VERDICTS.has(v.should_i_worry)
  );
}

/**
 * Decode `ai_explanation` into one of three render modes:
 *  - `{ kind: "none" }`     — no key was provided (field was `null`).
 *  - `{ kind: "structured" }` — a valid {@link AiExplanation} was returned.
 *  - `{ kind: "fallback" }` — the field was a plain string (OSV summary fallback).
 *
 * This is intentionally defensive so the card renders gracefully no matter what
 * the backend sends.
 */
export type ParsedExplanation =
  | { kind: "none" }
  | { kind: "structured"; value: AiExplanation }
  | { kind: "fallback"; text: string };

export function parseAiExplanation(raw: string | null): ParsedExplanation {
  if (raw === null || raw.trim() === "") return { kind: "none" };
  try {
    const data = JSON.parse(raw);
    if (isAiExplanation(data)) return { kind: "structured", value: data };
  } catch {
    // Not JSON — it's the OSV summary fallback string. Fall through.
  }
  return { kind: "fallback", text: raw };
}
