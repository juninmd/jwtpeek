#!/usr/bin/env node
import { decodeJwt, checkExpiry, verifyHs } from "./jwt";

const C = {
  b: (s: string) => `\x1b[1m${s}\x1b[0m`,
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
};

const HELP = `jwtpeek — decode & inspect a JWT

Usage:
  jwtpeek <token> [--verify <secret>] [--json]
  echo <token> | jwtpeek [--verify <secret>]

Options:
  --verify <secret>   check the HS256/384/512 signature
  --json              print decoded {header,payload} as JSON
  -h, --help`;

function fmtTime(sec?: number): string {
  return sec === undefined ? "—" : new Date(sec * 1000).toISOString();
}

async function readStdin(): Promise<string> {
  const chunks: Uint8Array[] = [];
  for await (const c of process.stdin) chunks.push(c as Uint8Array);
  return Buffer.concat(chunks).toString("utf8").trim();
}

async function main(argv: string[]): Promise<number> {
  if (argv.includes("-h") || argv.includes("--help")) {
    console.log(HELP);
    return 0;
  }
  const jsonOut = argv.includes("--json");
  const vIdx = argv.indexOf("--verify");
  const secret = vIdx > -1 ? argv[vIdx + 1] : undefined;

  const positional = argv.filter((a, i) => !a.startsWith("-") && i !== vIdx + 1);
  const token = positional[0] ?? (await readStdin());
  if (!token) {
    console.error(C.red("error: no token given"));
    return 2;
  }

  let decoded;
  try {
    decoded = decodeJwt(token);
  } catch (err) {
    console.error(C.red(`error: ${err instanceof Error ? err.message : err}`));
    return 1;
  }

  if (jsonOut) {
    console.log(JSON.stringify({ header: decoded.header, payload: decoded.payload }, null, 2));
    return 0;
  }

  const exp = checkExpiry(decoded.payload);
  console.log(C.b("\nHeader"));
  console.log(C.dim(JSON.stringify(decoded.header, null, 2)));
  console.log(C.b("\nPayload"));
  console.log(C.dim(JSON.stringify(decoded.payload, null, 2)));

  console.log(C.b("\nExpiry"));
  const label = {
    valid: C.green("valid"),
    expired: C.red("EXPIRED"),
    "not-yet-valid": C.yellow("not yet valid"),
    "no-exp": C.dim("no exp claim"),
  }[exp.state];
  console.log(`  status : ${label}`);
  if (exp.exp) console.log(`  exp    : ${fmtTime(exp.exp)}`);
  if (exp.nbf) console.log(`  nbf    : ${fmtTime(exp.nbf)}`);

  if (secret !== undefined) {
    const ok = verifyHs(token, secret);
    console.log(C.b("\nSignature"));
    console.log(`  HMAC   : ${ok ? C.green("VALID ✓") : C.red("INVALID ✗")}`);
    if (!ok) return 1;
  }
  console.log("");
  return exp.state === "expired" ? 1 : 0;
}

main(process.argv.slice(2)).then((code) => process.exit(code));
