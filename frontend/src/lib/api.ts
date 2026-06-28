/**
 * Backend client for the Bastion scan API.
 *
 * Key handling: the user's Anthropic key is accepted as a plain argument and
 * attached ONLY as the `X-Anthropic-Key` request header, and only when present.
 * It is never written to storage, never put in the URL or query string, and
 * never logged. It lives in React state in the caller and is handed to this
 * function for the duration of one request.
 *
 * The base URL comes from the `VITE_API_BASE_URL` env var — localhost is never
 * hardcoded. An empty value means "same origin" (useful behind a reverse proxy).
 */
import type { Ecosystem, ScanResult } from "@/types/scan";

/** The header the backend reads the bring-your-own-key Anthropic key from. */
const ANTHROPIC_KEY_HEADER = "X-Anthropic-Key";

/** Trim a trailing slash so we can safely append the path. */
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");

const SCAN_PATH = "/api/v1/scan";

/** A coarse classification of failures, so the UI can show a specific message. */
export type ScanErrorKind =
  | "osv_unavailable" // 503
  | "rate_limited" // 429
  | "unparseable" // 400 / 422 / 415 — we couldn't read the manifest
  | "too_large" // 413
  | "network" // request never reached the server
  | "aborted" // caller cancelled
  | "unknown";

/** A typed error carrying enough for the UI to pick a human message. */
export class ScanError extends Error {
  readonly kind: ScanErrorKind;
  readonly status?: number;
  /** The backend's `detail` string, if any — useful context for "unparseable". */
  readonly detail?: string;

  constructor(kind: ScanErrorKind, message: string, opts?: { status?: number; detail?: string }) {
    super(message);
    this.name = "ScanError";
    this.kind = kind;
    this.status = opts?.status;
    this.detail = opts?.detail;
  }
}

export interface ScanRequest {
  /** Pasted manifest text. Provide this OR `file`. */
  content?: string;
  /** An uploaded manifest file. Provide this OR `content`. */
  file?: File;
  /** Manual ecosystem override. Omit for backend auto-detection. */
  ecosystem?: Ecosystem;
  /** The user's Anthropic key. Omit/empty to skip AI explanations. */
  apiKey?: string;
  /** Allows the caller to cancel an in-flight scan. */
  signal?: AbortSignal;
}

function mapStatusToKind(status: number): ScanErrorKind {
  switch (status) {
    case 503:
      return "osv_unavailable";
    case 429:
      return "rate_limited";
    case 400:
    case 415:
    case 422:
      return "unparseable";
    case 413:
      return "too_large";
    default:
      return "unknown";
  }
}

async function readDetail(response: Response): Promise<string | undefined> {
  try {
    const data = await response.json();
    if (data && typeof data.detail === "string") return data.detail;
  } catch {
    // Non-JSON error body — nothing useful to extract.
  }
  return undefined;
}

/**
 * Run a scan. Returns a {@link ScanResult} on success, or throws a
 * {@link ScanError} whose `kind` the UI maps to a specific message.
 */
export async function scanManifest(req: ScanRequest): Promise<ScanResult> {
  const url = `${API_BASE_URL}${SCAN_PATH}`;
  const headers: Record<string, string> = {};

  // The key is attached ONLY here, ONLY when truthy, ONLY as a header.
  if (req.apiKey && req.apiKey.trim() !== "") {
    headers[ANTHROPIC_KEY_HEADER] = req.apiKey.trim();
  }

  // A file upload goes as multipart (preserving the filename, which helps the
  // backend's ecosystem auto-detection); pasted text goes as JSON.
  let body: BodyInit;
  if (req.file) {
    const form = new FormData();
    form.append("file", req.file);
    if (req.ecosystem) form.append("ecosystem", req.ecosystem);
    body = form;
    // NB: do NOT set Content-Type — the browser adds the multipart boundary.
  } else {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify({
      content: req.content ?? "",
      ...(req.ecosystem ? { ecosystem: req.ecosystem } : {}),
    });
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers,
      body,
      signal: req.signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ScanError("aborted", "Scan cancelled.");
    }
    throw new ScanError(
      "network",
      "Couldn't reach the Bastion backend. Check that the API is running and reachable.",
    );
  }

  if (!response.ok) {
    const detail = await readDetail(response);
    const kind = mapStatusToKind(response.status);
    throw new ScanError(kind, detail ?? `Request failed (${response.status}).`, {
      status: response.status,
      detail,
    });
  }

  return (await response.json()) as ScanResult;
}
