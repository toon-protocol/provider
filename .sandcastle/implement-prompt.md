/mattpocock-skills:implement {{ISSUE_URL}}

You are running AFK in a sandbox, on branch `{{BRANCH}}`, which is already checked out.
Nobody will answer a question, so do not ask one. Treat the issue, its comments and its
parent spec (if it has one) as settled. Read them with `gh issue view {{ISSUE_NUMBER}} --comments`.

Commit to `{{BRANCH}}`, and reference `#{{ISSUE_NUMBER}}` in each commit message. Do not
push, open a PR or close the issue. The runner does all three once you finish.

## This repository

- A single Rust crate (`toon-provider`) plus a deploy bundle under `deploy/` and two small
  Node tools under `tools/`. `CLAUDE.md` has the commands and `README.md` is the operator's
  guide. There is no root `package.json`; the only Node manifest the runner uses is
  `.sandcastle/package.json`.
- Many tests run shell scripts and Node tools (`tests/deploy_bundle.rs` runs the real
  `deploy/render.sh`, which needs `envsubst`). They are in the image. The Docker
  integration tests are `#[ignore]`d: the sandbox has no Docker daemon, so do not try to run
  them or remove the attribute.
- The wire fixtures under `tests/fixtures/wire/` are verified byte-for-byte by
  `cargo test --test wire_fixtures`. Regenerate them with `make fixtures` only for an
  intended wire change, and say so in the commit message.
- After you finish, the runner runs CI's gate itself and won't open a PR while it is red:
  `cargo fmt --all -- --check`, `cargo test --locked --no-fail-fast` and
  `cargo clippy --locked --all-targets -- -D warnings`. Run them yourself before you
  commit. Never weaken, skip or `#[ignore]` a test, and never loosen a lint, to get green.
- Do not edit the repository-root `Dockerfile` (the published image) or
  `.github/workflows/publish-provider-image.yml` unless the issue asks for it.
- A ticket that needs a live box, a funded key or an on-chain write is not something you
  can do from here. Say so in a comment on the issue rather than guessing.

## When you cannot finish

Stop only when a genuinely new decision is needed, the action is irreversible, it touches
real funds, or it needs a credential that no workflow exposes. In that case, commit nothing
and explain what blocks you in a comment on the issue (`gh issue comment {{ISSUE_NUMBER}}`).
The runner moves an issue with no commits to `needs-triage`.

If your context is getting full (around 150k tokens) before you are done, commit what works,
write the remaining steps to `.sandcastle/logs/handoff-{{ISSUE_NUMBER}}.md`, commit it with
`git add -f`, and end your turn. A fresh session continues from your commits.

When the ticket is done and committed, output <promise>COMPLETE</promise>.
