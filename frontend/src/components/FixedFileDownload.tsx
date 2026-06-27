import { useState } from "react";
import ReactDiffViewer, { DiffMethod } from "react-diff-viewer-continued";
import { Check, Columns2, Copy, Download, Rows3 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { Ecosystem } from "@/types/scan";

interface FixedFileDownloadProps {
  ecosystem: Ecosystem;
  originalManifest: string;
  fixedManifest: string;
  /** The fixer's framing ("suggested safe versions, review before applying"). */
  fixNotice: string | null;
}

/** A sensible download filename for each ecosystem's manifest. */
const FILENAME_BY_ECOSYSTEM: Record<Ecosystem, string> = {
  npm: "package.json",
  PyPI: "requirements.txt",
  Maven: "pom.xml",
  RubyGems: "Gemfile",
};

export function FixedFileDownload({
  ecosystem,
  originalManifest,
  fixedManifest,
  fixNotice,
}: FixedFileDownloadProps) {
  const [splitView, setSplitView] = useState(true);
  const [copied, setCopied] = useState(false);

  const filename = FILENAME_BY_ECOSYSTEM[ecosystem];

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(fixedManifest);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard may be blocked (e.g. non-secure context); fail quietly.
    }
  }

  function handleDownload() {
    const blob = new Blob([fixedManifest], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2">
              Suggested fixes
              {fixNotice && (
                <Badge variant="outline" className="font-normal text-muted-foreground">
                  {fixNotice}
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              Review the changes below, then copy or download the updated {filename}.
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setSplitView((v) => !v)}
              title={splitView ? "Switch to inline diff" : "Switch to side-by-side diff"}
            >
              {splitView ? <Rows3 /> : <Columns2 />}
              {splitView ? "Inline" : "Side-by-side"}
            </Button>
            <Button variant="outline" size="sm" onClick={handleCopy}>
              {copied ? <Check /> : <Copy />}
              {copied ? "Copied" : "Copy fixed file"}
            </Button>
            <Button size="sm" onClick={handleDownload}>
              <Download />
              Download
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="overflow-hidden rounded-lg border text-sm">
          <ReactDiffViewer
            oldValue={originalManifest}
            newValue={fixedManifest}
            splitView={splitView}
            useDarkTheme
            compareMethod={DiffMethod.WORDS}
            leftTitle="Original"
            rightTitle="Suggested"
          />
        </div>
      </CardContent>
    </Card>
  );
}
