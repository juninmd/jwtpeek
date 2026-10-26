import { test, expect } from "bun:test";
import { createHmac } from "node:crypto";
import { decodeJwt, checkExpiry, verifyHs } from "../src/jwt";

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}
function makeHs256(payload: object, secret: string): string {
  const h = b64url({ alg: "HS256", typ: "JWT" });
  const p = b64url(payload);
  const sig = createHmac("sha256", secret).update(`${h}.${p}`).digest("base64url");
  return `${h}.${p}.${sig}`;
}

test("decodeJwt parses header and payload", () => {
  const t = makeHs256({ sub: "42", name: "juninho" }, "x");
  const d = decodeJwt(t);
  expect(d.header.alg).toBe("HS256");
  expect(d.payload.sub).toBe("42");
  expect(d.payload.name).toBe("juninho");
});

test("decodeJwt rejects malformed tokens", () => {
  expect(() => decodeJwt("a.b")).toThrow("3 dot-separated");
  expect(() => decodeJwt("!!!.###.$$$")).toThrow("invalid header");
});

test("checkExpiry: valid, expired, not-yet, no-exp", () => {
  const now = 1_700_000_000_000;
  const nowSec = now / 1000;
  expect(checkExpiry({ exp: nowSec + 100 }, now).state).toBe("valid");
  expect(checkExpiry({ exp: nowSec - 100 }, now).state).toBe("expired");
  expect(checkExpiry({ nbf: nowSec + 100 }, now).state).toBe("not-yet-valid");
  expect(checkExpiry({ sub: "x" }, now).state).toBe("no-exp");
});

test("verifyHs validates correct secret, rejects wrong", () => {
  const t = makeHs256({ sub: "1" }, "s3cret");
  expect(verifyHs(t, "s3cret")).toBe(true);
  expect(verifyHs(t, "wrong")).toBe(false);
});

test("verifyHs rejects non-HMAC alg", () => {
  const h = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
  const p = Buffer.from(JSON.stringify({ sub: "1" })).toString("base64url");
  expect(verifyHs(`${h}.${p}.`, "anything")).toBe(false);
});

test("rejects non-object header/payload JSON", () => {
  for (const v of [null, 1, "s", []]) {
    const ok = b64url({ alg: "HS256" });
    expect(() => decodeJwt(`${b64url(v)}.${ok}.x`)).toThrow("invalid header (expected a JSON object)");
    expect(() => decodeJwt(`${ok}.${b64url(v)}.x`)).toThrow("invalid payload (expected a JSON object)");
  }
});
