# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the
codebase. This repo is **single-context**, and its glossary and decisions live in another repository.

## Before exploring, read these

The spec, the glossary and the ADRs are in
[`toon-protocol/TOON_Network`](https://github.com/toon-protocol/TOON_Network), not here:

- **`CONTEXT.md`** there is the normative vocabulary this code uses (**Lease Interval**, **Warm
  Standby**, **Takeover** and so on). Terms only; decisions live in ADRs.
- **`docs/adr/`** there holds the decisions this code cites as "ADR 00NN". Read the ones that touch
  the area you are about to work in.
- **`docs/spec/toon-network-v1.md`** there is the protocol spec this code cites as "spec §N".

This repository has no `CONTEXT.md` and no `docs/adr/` of its own, so do not look for them in the
clone. If a `TOON_Network` checkout is not to hand, read the files on GitHub (`gh api` or
`gh browse`), or proceed from `README.md`, which restates what an operator needs.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a test name, a comment), use the term
as `TOON_Network`'s `CONTEXT.md` defines it, and don't drift to synonyms it avoids.

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0009 (a price change is a new listing version) — but worth reopening because…_
