# CLAUDE.md

`toon-provider` sells leases on workloads over the TOON Network. `README.md` is the operator's
guide, and it says where the spec, glossary and ADRs live (the `TOON_Network` repository, not
here). `docs/agents/` covers the issue tracker, the triage labels and the domain docs.

## Commands

```bash
cargo build --locked --bin toon-provider   # what the root Dockerfile ships

# The gate: the steps of .github/workflows/ci.yml's `checks` job, in this order.
cargo fmt --all -- --check
cargo test --locked --no-fail-fast
cargo clippy --locked --all-targets -- -D warnings
```

`cargo test` needs `envsubst` (`gettext-base`) and Node: `tests/deploy_bundle.rs` runs the real
`deploy/render.sh`, and several tests run the tools under `tools/`. The Docker integration tests
are `#[ignore]` and do not run in CI. `tests/fixtures/wire/` is checked byte-for-byte; regenerate
it with `make fixtures` only for an intended wire change.

There is deliberately no root `package.json`. The AFK factory's runner has its own under
`.sandcastle/`; `tools/*` each carry theirs.

## Rules

- Never weaken, skip or `#[ignore]` a test, and never loosen a lint, to get green.
- Never commit key material, a `.env` or a rendered `provider.toml` (it holds a private key).
- The repository-root `Dockerfile` and `publish-provider-image.yml` are the published image. Change
  them only when a ticket says so.
