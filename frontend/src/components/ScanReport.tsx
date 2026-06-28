import { useMemo } from "react";
import { PartyPopper, ShieldCheck, Sparkles } from "lucide-react";

import { FixedFileDownload } from "@/components/FixedFileDownload";
import { VulnerabilityCard } from "@/components/VulnerabilityCard";
import { Card, CardContent } from "@/components/ui/card";
import { compareSeverity } from "@/lib/severity";
import { cn } from "@/lib/utils";
import type { ScanResult, Severity, Vulnerability } from "@/types/scan";

interface ScanReportProps {
  result: ScanResult;
  /** The original manifest text the user submitted, for the fix diff. */
  originalManifest: string;
}

const SEVERITY_LABELS: Severity[] = ["critical", "high", "medium", "low", "unknown"];

export function ScanReport({ result, originalManifest }: ScanReportProps) {
  const { sortedVulns, severityCounts, vulnerablePackages, safeFixes } = useMemo(() => {
    const all: Vulnerability[] = result.packages.flatMap((p) => p.vulnerabilities);

    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };
    for (const v of all) counts[v.severity] += 1;

    // A "safe fix" = a vulnerable package with a known, non-breaking upgrade.
    const safe = new Set(
      all.filter((v) => v.fixed_version && !v.is_breaking_upgrade).map((v) => v.package),
    );

    const sorted = [...all].sort(
      (a, b) => compareSeverity(a.severity, b.severity) || a.package.localeCompare(b.package),
    );

    return {
      sortedVulns: sorted,
      severityCounts: counts,
      vulnerablePackages: result.packages.filter((p) => p.vulnerabilities.length > 0).length,
      safeFixes: safe.size,
    };
  }, [result]);

  // All-clear: zero vulnerabilities is a moment worth celebrating.
  if (result.total_vulnerabilities === 0) {
    return <AllClear totalPackages={result.total_packages} />;
  }

  // Pick the headline accent from the worst severity present.
  const headlineSeverity: Severity =
    SEVERITY_LABELS.find((s) => severityCounts[s] > 0) ?? "unknown";

  return (
    <div className="space-y-5">
      {/* Summary bar */}
      <Card className={cn("border-l-4", summaryBorder(headlineSeverity))}>
        <CardContent className="flex flex-wrap items-center gap-x-2 gap-y-1 p-5 text-sm">
          <span className="text-base font-semibold">
            {vulnerablePackages} vulnerable
          </span>
          <span className="text-muted-foreground">/ {result.total_packages} packages</span>

          {SEVERITY_LABELS.filter((s) => severityCounts[s] > 0).map((s) => (
            <span key={s} className="flex items-center gap-1.5">
              <span className="text-muted-foreground">·</span>
              <span className={cn("font-medium", severityTextColor(s))}>
                {severityCounts[s]} {s}
              </span>
            </span>
          ))}

          {safeFixes > 0 && (
            <span className="flex items-center gap-1.5">
              <span className="text-muted-foreground">·</span>
              <span className="flex items-center gap-1 font-medium text-primary">
                <ShieldCheck className="size-3.5" />
                {safeFixes} safe {safeFixes === 1 ? "fix" : "fixes"}
              </span>
            </span>
          )}

          <span className="ml-auto rounded-md bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">
            {result.ecosystem}
          </span>
        </CardContent>
      </Card>

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

function AllClear({ totalPackages }: { totalPackages: number }) {
  return (
    <Card className="border-primary/30 bg-primary/5">
      <CardContent className="flex flex-col items-center gap-3 px-6 py-14 text-center">
        <div className="flex size-14 items-center justify-center rounded-full bg-primary/15">
          <PartyPopper className="size-7 text-primary" />
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

function summaryBorder(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "border-l-red-500";
    case "high":
      return "border-l-orange-500";
    case "medium":
      return "border-l-amber-500";
    case "low":
      return "border-l-sky-500";
    default:
      return "border-l-zinc-500";
  }
}

function severityTextColor(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "text-red-400";
    case "high":
      return "text-orange-400";
    case "medium":
      return "text-amber-400";
    case "low":
      return "text-sky-400";
    default:
      return "text-zinc-400";
  }
}
