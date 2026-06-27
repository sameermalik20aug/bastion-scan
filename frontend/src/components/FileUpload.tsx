import { useRef, useState } from "react";
import { FileUp, KeyRound, Loader2, ShieldCheck, X } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { detectEcosystem } from "@/lib/manifest";
import { cn } from "@/lib/utils";
import type { Ecosystem } from "@/types/scan";

/** Manual override choices. "auto" maps to "omit the hint, let the backend decide". */
const ECOSYSTEM_OPTIONS: { value: "auto" | Ecosystem; label: string }[] = [
  { value: "auto", label: "Auto-detect" },
  { value: "npm", label: "npm (package.json)" },
  { value: "PyPI", label: "PyPI (requirements.txt)" },
];

export interface ScanSubmission {
  file?: File;
  content?: string;
  ecosystem?: Ecosystem;
  apiKey?: string;
  /** The original manifest text, kept purely so the result view can diff it. */
  originalText: string;
}

interface FileUploadProps {
  onScan: (submission: ScanSubmission) => void;
  isScanning: boolean;
}

export function FileUpload({ onScan, isScanning }: FileUploadProps) {
  const [file, setFile] = useState<File | null>(null);
  const [text, setText] = useState("");
  const [override, setOverride] = useState<"auto" | Ecosystem>("auto");
  const [apiKey, setApiKey] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // What we'd auto-detect right now, shown next to the dropdown when on "auto".
  const detected = detectEcosystem({
    filename: file?.name,
    content: file ? undefined : text,
  });

  const hasInput = file !== null || text.trim() !== "";

  function acceptFile(f: File) {
    setFile(f);
    setText(""); // a file and pasted text are mutually exclusive inputs
    // Read the file so we can show a count/preview and detect from content too.
    const reader = new FileReader();
    reader.onload = () => {
      const result = typeof reader.result === "string" ? reader.result : "";
      // Keep the text in state only for detection/preview; the File itself is
      // what we upload (multipart), so the backend gets the original bytes.
      setText(result);
    };
    reader.readAsText(f);
  }

  function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDragging(false);
    const dropped = e.dataTransfer.files?.[0];
    if (dropped) acceptFile(dropped);
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = e.target.files?.[0];
    if (selected) acceptFile(selected);
  }

  function clearFile() {
    setFile(null);
    setText("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  function handleSubmit() {
    if (!hasInput || isScanning) return;
    const ecosystem = override === "auto" ? undefined : override;
    const trimmedKey = apiKey.trim();
    if (file) {
      onScan({ file, ecosystem, apiKey: trimmedKey || undefined, originalText: text });
    } else {
      onScan({ content: text, ecosystem, apiKey: trimmedKey || undefined, originalText: text });
    }
  }

  return (
    <div className="space-y-5">
      {/* Drag & drop zone */}
      <div
        role="button"
        tabIndex={0}
        aria-label="Upload a manifest file"
        onClick={() => fileInputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            fileInputRef.current?.click();
          }
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={cn(
          "flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-8 text-center transition-colors",
          isDragging
            ? "border-primary bg-primary/5"
            : "border-input hover:border-primary/60 hover:bg-accent/40",
        )}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".json,.txt,application/json,text/plain"
          className="hidden"
          onChange={handleFileChange}
        />
        {file ? (
          <div className="flex items-center gap-2">
            <ShieldCheck className="size-5 text-primary" />
            <span className="font-medium">{file.name}</span>
            <Button
              variant="ghost"
              size="icon"
              className="size-6"
              aria-label="Remove file"
              onClick={(e) => {
                e.stopPropagation();
                clearFile();
              }}
            >
              <X />
            </Button>
          </div>
        ) : (
          <>
            <FileUp className="mb-2 size-6 text-muted-foreground" />
            <p className="text-sm font-medium">Drop a manifest here, or click to browse</p>
            <p className="mt-1 text-xs text-muted-foreground">
              package.json or requirements.txt
            </p>
          </>
        )}
      </div>

      {/* Paste-text alternative */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label htmlFor="manifest-text">…or paste your manifest</Label>
          {text && !file && (
            <button
              className="text-xs text-muted-foreground hover:text-foreground"
              onClick={() => setText("")}
            >
              Clear
            </button>
          )}
        </div>
        <Textarea
          id="manifest-text"
          placeholder={'{\n  "dependencies": {\n    "lodash": "4.17.20"\n  }\n}'}
          value={text}
          disabled={file !== null}
          onChange={(e) => setText(e.target.value)}
          rows={8}
          className="resize-y"
        />
        {file && (
          <p className="text-xs text-muted-foreground">
            Showing the uploaded file. Remove it to paste text instead.
          </p>
        )}
      </div>

      {/* Ecosystem override */}
      <div className="space-y-2">
        <Label htmlFor="ecosystem">Ecosystem</Label>
        <div className="flex items-center gap-3">
          <div className="w-56">
            <Select
              id="ecosystem"
              value={override}
              onChange={(e) => setOverride(e.target.value as "auto" | Ecosystem)}
            >
              {ECOSYSTEM_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </div>
          {override === "auto" && detected && (
            <Badge variant="outline" className="text-muted-foreground">
              detected: {detected}
            </Badge>
          )}
        </div>
      </div>

      {/* Optional API key (held in React state only — never persisted) */}
      <div className="space-y-2">
        <Label htmlFor="api-key" className="flex items-center gap-1.5">
          <KeyRound className="size-3.5" /> Anthropic API key{" "}
          <span className="font-normal text-muted-foreground">(optional)</span>
        </Label>
        <Input
          id="api-key"
          type="password"
          autoComplete="off"
          placeholder="sk-ant-…"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
        />
        <p className="text-xs leading-relaxed text-muted-foreground">
          Your key stays in your browser, is sent only with your scan request, and is never
          stored. Leave blank to skip AI explanations.
        </p>
      </div>

      <Button
        size="lg"
        className="w-full"
        disabled={!hasInput || isScanning}
        onClick={handleSubmit}
      >
        {isScanning ? (
          <>
            <Loader2 className="animate-spin" /> Scanning…
          </>
        ) : (
          <>
            <ShieldCheck /> Scan dependencies
          </>
        )}
      </Button>
    </div>
  );
}
