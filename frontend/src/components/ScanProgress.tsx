import { Check, Loader2 } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/** The pipeline stages, mirroring the backend: parse -> OSV -> (optional) AI. */
export type ScanStage = "parsing" | "osv" | "explaining" | "done";

const STAGE_ORDER: ScanStage[] = ["parsing", "osv", "explaining", "done"];

interface ScanProgressProps {
  stage: ScanStage;
  /** Estimated package count, for the "Checking N packages" line. */
  packageCount: number | null;
  /** Whether AI enrichment is part of this run (a key was supplied). */
  aiEnabled: boolean;
}

interface StepView {
  key: ScanStage;
  label: string;
}

export function ScanProgress({ stage, packageCount, aiEnabled }: ScanProgressProps) {
  const steps: StepView[] = [
    { key: "parsing", label: "Parsing manifest" },
    {
      key: "osv",
      label: packageCount
        ? `Checking ${packageCount} package${packageCount === 1 ? "" : "s"} against OSV`
        : "Checking packages against OSV",
    },
    // Only show the AI step when a key was provided — no-key mode skips it.
    ...(aiEnabled ? [{ key: "explaining" as const, label: "Generating explanations" }] : []),
  ];

  const currentIndex = STAGE_ORDER.indexOf(stage);

  return (
    <Card>
      <CardContent className="space-y-4 p-6">
        {steps.map((step) => {
          const stepIndex = STAGE_ORDER.indexOf(step.key);
          const isDone = currentIndex > stepIndex;
          const isActive = currentIndex === stepIndex;
          return (
            <div key={step.key} className="flex items-center gap-3">
              <span
                className={cn(
                  "flex size-6 shrink-0 items-center justify-center rounded-full border",
                  isDone && "border-primary bg-primary text-primary-foreground",
                  isActive && "border-primary text-primary",
                  !isDone && !isActive && "border-input text-muted-foreground",
                )}
              >
                {isDone ? (
                  <Check className="size-3.5" />
                ) : isActive ? (
                  <Loader2 className="size-3.5 animate-spin" />
                ) : (
                  <span className="size-1.5 rounded-full bg-current" />
                )}
              </span>
              <span
                className={cn(
                  "text-sm",
                  isActive && "font-medium text-foreground",
                  isDone && "text-muted-foreground",
                  !isDone && !isActive && "text-muted-foreground",
                )}
              >
                {step.label}
                {isActive && <span className="ml-0.5 animate-pulse">…</span>}
              </span>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
