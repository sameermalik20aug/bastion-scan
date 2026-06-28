/**
 * Lightweight, best-effort client-side manifest inspection.
 *
 * This is ONLY for UX niceties before the real scan returns — showing the
 * auto-detected ecosystem next to the override dropdown, and a package count in
 * the progress text ("Checking N packages against OSV…"). The backend remains
 * the authority: it re-detects and re-parses, and the displayed result always
 * comes from its response.
 */
import type { Ecosystem } from "@/types/scan";

/** Sniff the ecosystem the same way the backend's filename/content heuristics do. */
export function detectEcosystem(opts: {
  filename?: string | null;
  content?: string;
}): Ecosystem | null {
  const name = opts.filename?.toLowerCase() ?? "";
  if (name.endsWith("package.json")) return "npm";
  if (name.includes("requirements") && name.endsWith(".txt")) return "PyPI";
  if (name.endsWith(".gradle") || name === "pom.xml") return "Maven";
  if (name === "gemfile" || name.endsWith(".gemspec")) return "RubyGems";

  const content = opts.content?.trim() ?? "";
  if (content === "") return null;
  return content.startsWith("{") ? "npm" : "PyPI";
}

/**
 * Roughly count the packages in a manifest, so progress can say "N packages".
 * Returns `null` when we can't tell — callers fall back to generic wording.
 */
export function estimatePackageCount(content: string, ecosystem: Ecosystem | null): number | null {
  const text = content.trim();
  if (text === "") return null;

  const looksJson = ecosystem === "npm" || (ecosystem === null && text.startsWith("{"));
  if (looksJson) {
    try {
      const data = JSON.parse(text) as Record<string, unknown>;
      let total = 0;
      for (const section of ["dependencies", "devDependencies"]) {
        const deps = data[section];
        if (deps && typeof deps === "object") total += Object.keys(deps).length;
      }
      return total > 0 ? total : null;
    } catch {
      return null;
    }
  }

  // requirements.txt style: count non-blank, non-comment lines.
  const lines = text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "" && !l.startsWith("#") && !l.startsWith("-"));
  return lines.length > 0 ? lines.length : null;
}
