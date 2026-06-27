import { useCallback, useEffect, useRef, useState } from "react";
import { ShieldHalf } from "lucide-react";

import { FileUpload, type ScanSubmission } from "@/components/FileUpload";
import { ScanErrorState } from "@/components/ScanErrorState";
import { ScanProgress, type ScanStage } from "@/components/ScanProgress";
import { ScanReport } from "@/components/ScanReport";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScanError, scanManifest } from "@/lib/api";
import { detectEcosystem, estimatePackageCount } from "@/lib/manifest";
import type { ScanResult } from "@/types/scan";

type Status = "idle" | "scanning" | "success" | "error";

interface ProgressMeta {
  packageCount: number | null;
  aiEnabled: boolean;
}

export default function App() {
  const [status, setStatus] = useState<Status>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<ScanError | null>(null);
  const [originalManifest, setOriginalManifest] = useState("");
  const [stage, setStage] = useState<ScanStage>("parsing");
  const [progressMeta, setProgressMeta] = useState<ProgressMeta>({
    packageCount: null,
    aiEnabled: false,
  });

  // Timers driving the staged progress display, and the abort controller for the
  // in-flight request. Refs so they survive re-renders and can be cleaned up.
  const timersRef = useRef<number[]>([]);
  const abortRef = useRef<AbortController | null>(null);
  const lastSubmissionRef = useRef<ScanSubmission | null>(null);

  const clearTimers = useCallback(() => {
    timersRef.current.forEach((t) => window.clearTimeout(t));
    timersRef.current = [];
  }, []);

  // Tidy up timers / requests on unmount.
  useEffect(() => {
    return () => {
      clearTimers();
      abortRef.current?.abort();
    };
  }, [clearTimers]);

  const runScan = useCallback(
    async (submission: ScanSubmission) => {
      lastSubmissionRef.current = submission;

      // Cancel any previous run and reset display state.
      abortRef.current?.abort();
      clearTimers();
      const controller = new AbortController();
      abortRef.current = controller;

      const ecosystem =
        submission.ecosystem ??
        detectEcosystem({ filename: submission.file?.name, content: submission.originalText });
      const packageCount = estimatePackageCount(submission.originalText, ecosystem);
      const aiEnabled = Boolean(submission.apiKey);

      setOriginalManifest(submission.originalText);
      setProgressMeta({ packageCount, aiEnabled });
      setError(null);
      setResult(null);
      setStatus("scanning");
      setStage("parsing");

      // Drive the staged progress to mirror the backend pipeline (parse -> OSV ->
      // optional AI). These are believable client-side timings; the request is a
      // single call, and the real result replaces this when it lands.
      timersRef.current.push(window.setTimeout(() => setStage("osv"), 500));
      if (aiEnabled) {
        timersRef.current.push(window.setTimeout(() => setStage("explaining"), 1600));
      }

      try {
        const scanResult = await scanManifest({
          file: submission.file,
          content: submission.content,
          ecosystem: submission.ecosystem,
          apiKey: submission.apiKey,
          signal: controller.signal,
        });
        clearTimers();
        setStage("done");
        setResult(scanResult);
        setStatus("success");
      } catch (err) {
        clearTimers();
        if (err instanceof ScanError) {
          if (err.kind === "aborted") return; // superseded by a newer scan
          setError(err);
        } else {
          setError(new ScanError("unknown", "An unexpected error occurred."));
        }
        setStatus("error");
      }
    },
    [clearTimers],
  );

  const handleRetry = useCallback(() => {
    if (lastSubmissionRef.current) void runScan(lastSubmissionRef.current);
  }, [runScan]);

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="mx-auto flex max-w-3xl items-center gap-2.5 px-4 py-4">
          <ShieldHalf className="size-6 text-primary" />
          <span className="text-lg font-semibold tracking-tight">Bastion</span>
          <span className="hidden text-sm text-muted-foreground sm:inline">
            · Dependency vulnerability scanner
          </span>
        </div>
      </header>

      <main className="mx-auto max-w-3xl space-y-6 px-4 py-8">
        <Card>
          <CardHeader>
            <CardTitle>Scan a dependency manifest</CardTitle>
          </CardHeader>
          <CardContent>
            <FileUpload onScan={runScan} isScanning={status === "scanning"} />
          </CardContent>
        </Card>

        {status === "scanning" && (
          <ScanProgress
            stage={stage}
            packageCount={progressMeta.packageCount}
            aiEnabled={progressMeta.aiEnabled}
          />
        )}

        {status === "error" && error && <ScanErrorState error={error} onRetry={handleRetry} />}

        {status === "success" && result && (
          <ScanReport result={result} originalManifest={originalManifest} />
        )}
      </main>

      <footer className="mx-auto max-w-3xl px-4 py-8 text-center text-xs text-muted-foreground">
        Bastion checks your dependencies against the{" "}
        <a
          href="https://osv.dev"
          target="_blank"
          rel="noopener noreferrer"
          className="underline underline-offset-2 hover:text-foreground"
        >
          OSV
        </a>{" "}
        database. Fix suggestions are a starting point — review before applying.
      </footer>
    </div>
  );
}
