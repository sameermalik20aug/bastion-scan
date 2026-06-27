import { CloudOff, FileWarning, Hourglass, RefreshCw, ServerCrash, WifiOff } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { ScanError, ScanErrorKind } from "@/lib/api";

interface ScanErrorStateProps {
  error: ScanError;
  onRetry: () => void;
}

interface ErrorCopy {
  icon: LucideIcon;
  title: string;
  body: string;
  /** Whether a retry is likely to help (transient failures). */
  retryable: boolean;
}

function copyFor(error: ScanError): ErrorCopy {
  const kind: ScanErrorKind = error.kind;
  switch (kind) {
    case "osv_unavailable":
      return {
        icon: CloudOff,
        title: "The OSV vulnerability database is unavailable",
        body: "Bastion couldn't reach OSV.dev to look up your packages. This is usually temporary — give it a moment and try the scan again.",
        retryable: true,
      };
    case "rate_limited":
      return {
        icon: Hourglass,
        title: "Too many scans, too fast",
        body:
          error.detail ??
          "You've hit the scan rate limit (10 per minute). Wait a minute, then run your scan again.",
        retryable: true,
      };
    case "unparseable":
      return {
        icon: FileWarning,
        title: "Couldn't read that manifest",
        body: `${
          error.detail ?? "The file didn't look like a valid package.json or requirements.txt."
        } Check the format, or pick the ecosystem manually from the dropdown, and try again.`,
        retryable: false,
      };
    case "too_large":
      return {
        icon: FileWarning,
        title: "That manifest is too large",
        body:
          error.detail ??
          "Bastion caps manifests at ~1 MB. Real package.json / requirements.txt files are far smaller — double-check you uploaded the right file.",
        retryable: false,
      };
    case "network":
      return {
        icon: WifiOff,
        title: "Couldn't reach the backend",
        body: "The scan request never made it to the Bastion API. Check your connection and that the backend is running, then try again.",
        retryable: true,
      };
    case "aborted":
      return {
        icon: RefreshCw,
        title: "Scan cancelled",
        body: "The scan was cancelled before it finished. Run it again whenever you're ready.",
        retryable: true,
      };
    case "unknown":
    default:
      return {
        icon: ServerCrash,
        title: "Something went wrong on the server",
        body:
          error.detail ??
          "The backend returned an unexpected error. Try again — if it keeps happening, the API may be down.",
        retryable: true,
      };
  }
}

export function ScanErrorState({ error, onRetry }: ScanErrorStateProps) {
  const { icon: Icon, title, body, retryable } = copyFor(error);

  return (
    <Card className="border-destructive/40 bg-destructive/5">
      <CardContent className="flex flex-col items-center gap-3 px-6 py-12 text-center">
        <div className="flex size-12 items-center justify-center rounded-full bg-destructive/15">
          <Icon className="size-6 text-destructive" />
        </div>
        <h2 className="text-lg font-semibold">{title}</h2>
        <p className="max-w-md text-sm text-muted-foreground">{body}</p>
        {retryable && (
          <Button variant="outline" onClick={onRetry} className="mt-1">
            <RefreshCw /> Try again
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
