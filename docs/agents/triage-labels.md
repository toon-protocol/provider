# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual
label strings used in this repo's issue tracker. This repo uses the canonical names unchanged.

| Label in mattpocock/skills | Label in our tracker | Meaning                                  |
| -------------------------- | -------------------- | ---------------------------------------- |
| `needs-triage`             | `needs-triage`       | Maintainer needs to evaluate this issue  |
| `needs-info`               | `needs-info`         | Waiting on reporter for more information |
| `ready-for-agent`          | `ready-for-agent`    | Fully specified, ready for an AFK agent  |
| `ready-for-human`          | `ready-for-human`    | Requires human implementation            |
| `wontfix`                  | `wontfix`            | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label
string from this table.

## These labels drive the AFK factory

There is no separate trigger label. `ready-for-agent` is the queue, as `to-spec`, `to-tickets`
and `triage` assume: `.github/workflows/agent-implement.yml` picks up every open
`ready-for-agent` issue whose blockers are closed, and turns it into a PR. The factory moves labels
like this:

- **`ready-for-agent`** on an issue: queued. Removed once the agent's PR is open. Put it back to
  retry.
- **`ready-for-human`** on a PR: the agent finished and the gate is green. A human merges.
- **`needs-triage`** on an issue: the AFK run failed. The issue has a comment linking the run.

A spec (an issue with sub-issues, or one written from the to-spec template) is never built
directly, even with `ready-for-agent` on it. Its tickets are.

The runner's gate is the commands of `ci.yml`'s `checks` job, run in the same order:
`cargo fmt --all -- --check`, `cargo test --locked --no-fail-fast`,
`cargo clippy --locked --all-targets -- -D warnings`. It never opens a PR while the gate is red.

## Creating the labels

The five labels must exist in the tracker before the factory can apply them. `wontfix` is GitHub's
stock label; the other four are created with `gh label create <name> -R toon-protocol/provider`.
