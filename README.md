# 🔑 jwtpeek

Decode and inspect **JWTs** from the terminal — header, claims, **expiry status**, and optional **HMAC signature verification**. No network, no dependencies; the token never leaves your shell.

```bash
jwtpeek eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiJ9.xxxx
echo "$TOKEN" | jwtpeek --verify "$JWT_SECRET"
jwtpeek "$TOKEN" --json | jq .payload
```

## Output
- **Header** + **Payload** pretty-printed.
- **Expiry**: `valid` / `EXPIRED` / `not yet valid` / `no exp claim`, with `exp`/`nbf` as ISO timestamps.
- **Signature** (with `--verify <secret>`): HS256/384/512 checked in constant time.

Exit code is non-zero when the token is expired or signature verification fails — handy in scripts/CI.

## Dev
```bash
bun install
bun test
bun run build   # tsdown → dist/cli.js
```

Pure logic (decode, expiry, HMAC verify) is in `src/jwt.ts` and fully unit-tested.

MIT.
