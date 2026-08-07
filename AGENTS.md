# AGENTS.md

Guidance for AI agents and contributors working in this repo.

## What this is

`jwtpeek` — a zero-dependency CLI that decodes and inspects JWTs (header, claims, expiry, optional HMAC verify). Offline only; the token never leaves the shell.

## Stack & commands

- **Runtime:** [Bun](https://bun.sh) (never npm/node). **Bundler:** tsdown → `dist/`.

```bash
bun install
bun test                 # must stay green
bun run start "$TOKEN"   # run from source
bun run build            # bundle to dist/
```

## Conventions

- **No runtime dependencies**; no network calls — decoding/verification is fully local.
- HMAC verification must be constant-time-safe where it matters; don't weaken it.
- Keep stdout = data, stderr = diagnostics, so `jwtpeek "$T" --json | jq` stays clean.
- Stable exit codes; add a test for any behavior change before committing.

## Definition of done

`bun test` green, `bun run build` succeeds, README reflects any new flag.
