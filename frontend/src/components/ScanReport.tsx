import { useMemo } from "react";
import { ShieldCheck, Sparkles } from "lucide-react";

import { FixedFileDownload } from "@/components/FixedFileDownload";
import { VulnerabilityCard } from "@/components/VulnerabilityCard";
import { Card, CardContent } from "@/components/ui/card";
import { compareSeverity, SEVERITY_META } from "@/lib/severity";
import type { ScanResult, Severity, Vulnerability } from "@/types/scan";

interface ScanReportProps {
  result: ScanResult;
  /** The original manifest text the user submitted, for the fix diff. */
  originalManifest: string;
}

const SEVERITY_LABELS: Severity[] = ["critical", "high", "medium", "low", "unknown"];

export function ScanReport({ result, originalManifest }: ScanReportProps) {
  const { sortedVulns, severityCounts, vulnerablePackages, nonBreakingFixes } = useMemo(() => {
    const all: Vulnerability[] = result.packages.flatMap((p) => p.vulnerabilities);

    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };
    for (const v of all) counts[v.severity] += 1;

    // A non-breaking fix = a vulnerable package with a known upgrade that does
    // not cross a major/0.x boundary. We never call these "safe": the upgrade is
    // still a suggestion to review, not a verified fix.
    const nonBreaking = new Set(
      all.filter((v) => v.fixed_version && !v.is_breaking_upgrade).map((v) => v.package),
    );

    const sorted = [...all].sort(
      (a, b) => compareSeverity(a.severity, b.severity) || a.package.localeCompare(b.package),
    );

    return {
      sortedVulns: sorted,
      severityCounts: counts,
      vulnerablePackages: result.packages.filter((p) => p.vulnerabilities.length > 0).length,
      nonBreakingFixes: nonBreaking.size,
    };
  }, [result]);

  // All-clear: zero vulnerabilities is a moment worth celebrating.
  if (result.total_vulnerabilities === 0) {
    return <AllClear totalPackages={result.total_packages} />;
  }

  const totalVulns = SEVERITY_LABELS.reduce((sum, s) => sum + severityCounts[s], 0);

  return (
    <div className="space-y-5">
      {/* ── Signature element: the proportional severity meter ──────────────
          This is the one place we spend boldness. Segment widths map to counts,
          the legend carries the exact numbers, and the headline states the
          verdict. Colour encodes severity; the label travels with it so meaning
          never rests on hue alone. */}
      <SeverityMeter
        vulnerablePackages={vulnerablePackages}
        totalPackages={result.total_packages}
        totalVulns={totalVulns}
        severityCounts={severityCounts}
        nonBreakingFixes={nonBreakingFixes}
        ecosystem={result.ecosystem}
      />

      {/* AI executive summary, when present */}
      {result.executive_summary && (
        <Card className="bg-muted/30">
          <CardContent className="flex items-start gap-3 p-5">
            <Sparkles className="mt-0.5 size-4 shrink-0 text-primary" />
            <div className="space-y-1">
              <p className="text-xs font-medium text-muted-foreground">Executive summary</p>
              <p className="text-sm leading-relaxed">{result.executive_summary}</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Suggested fixes diff — only when the fixer rewrote something */}
      {result.fixed_manifest && (
        <FixedFileDownload
          ecosystem={result.ecosystem}
          originalManifest={originalManifest}
          fixedManifest={result.fixed_manifest}
          fixNotice={result.fix_notice}
        />
      )}

      {/* Severity-sorted vulnerability cards */}
      <div className="space-y-4">
        {sortedVulns.map((vuln) => (
          <VulnerabilityCard key={`${vuln.package}-${vuln.id}`} vuln={vuln} />
        ))}
      </div>
    </div>
  );
}

interface SeverityMeterProps {
  vulnerablePackages: number;
  totalPackages: number;
  totalVulns: number;
  severityCounts: Record<Severity, number>;
  nonBreakingFixes: number;
  ecosystem: string;
}

function SeverityMeter({
  vulnerablePackages,
  totalPackages,
  totalVulns,
  severityCounts,
  nonBreakingFixes,
  ecosystem,
}: SeverityMeterProps) {
  const present = SEVERITY_LABELS.filter((s) => severityCounts[s] > 0);

  const ariaSummary = present
    .map((s) => `${severityCounts[s]} ${SEVERITY_META[s].label.toLowerCase()}`)
    .join(", ");

  return (
    <Card>
      <CardContent className="space-y-4 p-5 sm:p-6">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
          <span className="text-2xl font-semibold tracking-tight">{vulnerablePackages}</span>
          <span className="text-sm text-muted-foreground">
            of {totalPackages} packages affected
          </span>
          <span className="ml-auto rounded-md border border-border bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">
            {ecosystem}
          </span>
        </div>

        {/* The proportional bar. Segment widths map to each severity's share of
            all findings, floored to a visible sliver so a lone low never vanishes
            next to a wall of criticals. */}
        <div
          role="img"
          aria-label={`${totalVulns} findings: ${ariaSummary}`}
          className="flex h-2.5 w-full overflow-hidden rounded-full bg-muted"
        >
          {present.map((s) => (
            <div
              key={s}
              className="h-full first:rounded-l-full last:rounded-r-full"
              style={{
                width: `${(severityCounts[s] / totalVulns) * 100}%`,
                minWidth: "0.5rem",
                backgroundColor: SEVERITY_META[s].fill,
              }}
            />
          ))}
        </div>

        {/* Legend — exact counts, with the colour swatch and the label. */}
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
          {present.map((s) => (
            <span key={s} className="flex items-center gap-2">
              <span
                aria-hidden
                className="size-2.5 rounded-full"
                style={{ backgroundColor: SEVERITY_META[s].fill }}
              />
              <span className="font-semibold tabular-nums">{severityCounts[s]}</span>
              <span className="text-muted-foreground">{SEVERITY_META[s].label.toLowerCase()}</span>
            </span>
          ))}

          {nonBreakingFixes > 0 && (
            <span className="flex items-center gap-1.5 text-emerald-700 sm:ml-auto">
              <ShieldCheck className="size-4" />
              <span className="font-medium">
                {nonBreakingFixes} non-breaking {nonBreakingFixes === 1 ? "fix" : "fixes"} available
              </span>
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function AllClear({ totalPackages }: { totalPackages: number }) {
  return (
    <Card className="border-emerald-200 bg-emerald-50/60">
      <CardContent className="flex flex-col items-center gap-3 px-6 py-14 text-center">
        <div className="flex size-14 items-center justify-center rounded-full bg-emerald-100 text-emerald-700">
          <ShieldCheck className="size-7" />
        </div>
        <h2 className="text-xl font-semibold">All clear — no known vulnerabilities</h2>
        <p className="max-w-md text-sm text-muted-foreground">
          Bastion checked{" "}
          <span className="font-medium text-foreground">{totalPackages} packages</span> against the
          OSV database and found nothing to worry about. Nice and tidy.
        </p>
      </CardContent>
    </Card>
  );
}
