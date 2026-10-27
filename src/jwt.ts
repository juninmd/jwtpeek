import { createHmac, timingSafeEqual } from "node:crypto";

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string; // base64url, as-is
  raw: { header: string; payload: string; signature: string };
}

function b64urlDecode(s: string): string {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64").toString("utf8");
}

function parseObject(s: string, what: string): Record<string, unknown> {
  let v: unknown;
  try {
    v = JSON.parse(b64urlDecode(s));
  } catch {
    throw new Error(`invalid ${what} (not base64url JSON)`);
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new Error(`invalid ${what} (expected a JSON object)`);
  }
  return v as Record<string, unknown>;
}

/** Decode a JWT without verifying. Throws on structural errors. */
export function decodeJwt(token: string): DecodedJwt {
  const parts = token.trim().split(".");
  if (parts.length !== 3) throw new Error("not a JWT (expected 3 dot-separated parts)");
  const [h, p, sig] = parts as [string, string, string];
  const header = parseObject(h, "header");
  const payload = parseObject(p, "payload");
  return { header, payload, signature: sig, raw: { header: h, payload: p, signature: sig } };
}

export type ExpiryState = "valid" | "expired" | "not-yet-valid" | "no-exp";

export interface ExpiryInfo {
  state: ExpiryState;
  exp?: number;
  nbf?: number;
  secondsRemaining?: number;
}

/** Interpret standard time claims relative to `now` (ms). */
export function checkExpiry(payload: Record<string, unknown>, now = Date.now()): ExpiryInfo {
  const nowSec = Math.floor(now / 1000);
  const exp = typeof payload.exp === "number" ? payload.exp : undefined;
  const nbf = typeof payload.nbf === "number" ? payload.nbf : undefined;
  if (nbf !== undefined && nowSec < nbf) return { state: "not-yet-valid", exp, nbf };
  if (exp === undefined) return { state: "no-exp", nbf };
  if (nowSec >= exp) return { state: "expired", exp, secondsRemaining: exp - nowSec };
  return { state: "valid", exp, secondsRemaining: exp - nowSec };
}

/** Verify an HS256/384/512 signature. Returns false for non-HMAC algs. */
export function verifyHs(token: string, secret: string): boolean {
  const parts = token.trim().split(".");
  if (parts.length !== 3) return false;
  const [h, p, sig] = parts as [string, string, string];
  let alg = "";
  try {
    alg = (JSON.parse(b64urlDecode(h)) as { alg?: string }).alg ?? "";
  } catch {
    return false;
  }
  const map: Record<string, string> = { HS256: "sha256", HS384: "sha384", HS512: "sha512" };
  const hash = map[alg];
  if (!hash) return false;
  const expected = createHmac(hash, secret)
    .update(`${h}.${p}`)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  if (expected.length !== sig.length) return false;
  return timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
}
