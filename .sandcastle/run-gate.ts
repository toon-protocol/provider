// The gate, run DETERMINISTICALLY by the runner, not asked of the agent.
//
// implement-prompt.md tells the agent to run the gate before it commits, but that is
// advisory prose the agent reports on itself. Verifying a build is plumbing, so the
// runner does it, and never opens a PR while it is red.
//
// The commands are the steps of ci.yml's `checks` job, in the same order and
// byte-identical to it. A gate that runs something similar to CI teaches the agent the
// wrong lesson. If ci.yml changes, change GATE_STEPS with it.
//
// There is a single gate and no
// path filter: `cargo test` here also runs the deploy-bundle, wire-fixture and Node
// tool tests, so a change outside src/ can still break it.

import type * as sandcastle from '@ai-hero/sandcastle';

type Sandbox = Awaited<ReturnType<typeof sandcastle.createSandbox>>;

export interface GateStep {
  readonly name: string;
  readonly command: string;
}

export interface GateFailure {
  readonly step: string;
  readonly command: string;
  readonly exitCode: number;
  /** Tail of combined output — enough for an agent to act on, bounded so it cannot blow a prompt. */
  readonly output: string;
}

export interface GateResult {
  readonly passed: boolean;
  readonly ran: readonly string[];
  readonly failure: GateFailure | null;
}

/** Keep fed-back output useful but bounded — a full cargo build log is megabytes. */
const MAX_OUTPUT_CHARS = 12_000;

/**
 * The steps of ci.yml's `checks` job, in order. `envsubst` (gettext-base) is in the
 * sandbox image, which is what the job's own install step guards for.
 *
 * `--all-targets` is deliberately absent from `cargo test`: it silently drops doc tests.
 * The Docker integration tests are `#[ignore]`, and this sandbox has no Docker daemon.
 */
export const GATE_STEPS: readonly GateStep[] = [
  { name: 'cargo fmt', command: 'cargo fmt --all -- --check' },
  { name: 'cargo test', command: 'cargo test --locked --no-fail-fast' },
  { name: 'cargo clippy', command: 'cargo clippy --locked --all-targets -- -D warnings' },
];

/**
 * Run `steps` in order, stopping at the first failure.
 *
 * Failure is returned, not thrown, so the caller can decide between a fix
 * iteration and failing the job.
 */
export async function runGate(sandbox: Sandbox, steps: readonly GateStep[]): Promise<GateResult> {
  const ran: string[] = [];

  for (const step of steps) {
    console.log(`  [gate] ${step.name}: ${step.command}`);
    const lines: string[] = [];
    const result = await sandbox.exec(step.command, {
      onLine: (line) => {
        lines.push(line);
        // Stream sparingly: full build output would bury the runner log.
        if (lines.length <= 40) console.log(`    | ${line}`);
      },
    });
    ran.push(step.name);

    if (result.exitCode !== 0) {
      const combined = [result.stdout, result.stderr].filter(Boolean).join('\n');
      const output =
        combined.length > MAX_OUTPUT_CHARS
          ? `...(truncated to the last ${MAX_OUTPUT_CHARS} chars)...\n` +
            combined.slice(-MAX_OUTPUT_CHARS)
          : combined;

      console.log(`  [gate] FAILED at ${step.name} (exit ${result.exitCode}).`);
      return {
        passed: false,
        ran,
        failure: { step: step.name, command: step.command, exitCode: result.exitCode, output },
      };
    }
  }

  console.log(`  [gate] PASSED (${ran.length} step(s): ${ran.join(', ')}).`);
  return { passed: true, ran, failure: null };
}

/** The prompt handed to a fix iteration. Concrete failure, no room to reinterpret the task. */
export function fixPrompt(failure: GateFailure, attempt: number, maxAttempts: number): string {
  return [
    `The repository gate is RED. This is fix attempt ${attempt} of ${maxAttempts}.`,
    '',
    `Failing step: ${failure.step}`,
    `Command:      ${failure.command}`,
    `Exit code:    ${failure.exitCode}`,
    '',
    'Output:',
    '```',
    failure.output,
    '```',
    '',
    'Fix the cause and commit. Rules:',
    `- Re-run \`${failure.command}\` yourself and confirm it passes before you finish.`,
    '- Fix the code. Do NOT weaken, skip, delete or #[ignore] a test, and do not',
    '  loosen a lint to make this pass — if the test is genuinely wrong, say so',
    '  explicitly in the commit message and explain why.',
    '- Change only what this failure requires. Do not refactor beyond it.',
    '- If you cannot fix it, commit nothing and explain what is blocking you.',
  ].join('\n');
}
