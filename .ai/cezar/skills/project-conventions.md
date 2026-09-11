# RGN Admin project conventions

## Git workflow

- `main` is the production branch. Never push directly to `main`.
- Never create or merge a pull request targeting `main`.
- `dev` is the integration branch.
- Every task must start from the current `origin/dev`.
- Task branches must use the `cez/*` namespace.
- Never push directly to `dev`.
- Push task branches to `origin`.
- Open pull requests only from `cez/*` into `dev`.
- During implementation and verification, do not push, create pull requests, or merge anything.
- GitHub publication is performed only by the dedicated `Publish` workflow step after local verification has passed; `Merge to dev` then proves required checks and the exact PR merge.
- Use squash merge.
- Enable auto-merge only after the pull request has been opened.
- Required GitHub status check: `test`.
- Do not bypass repository rules or required checks.

## Development

- Keep changes narrowly scoped to the requested task.
- Add or update tests for behaviour introduced or changed by the task.
- Do not modify repository rules, GitHub secrets, deployment credentials, or production configuration unless explicitly requested.
- Keep the lifecycle boundary explicit: `Implement` edits and reasons with cheap feedback; `Verify` performs reproducible authoritative validation.
- During `Implement`, use only cheap, local, dependency-free checks directly useful while editing, such as syntax or compile checks, `git diff --check`, formatting checks, and targeted static inspection.
- During `Implement`, run a targeted test only when its required environment already exists and the test is explicitly useful for the implementation step.
- During `Implement`, do not install dependencies or construct a project environment solely for authoritative verification.
- If a useful local check cannot run in the existing environment, continue implementing and delegate authoritative validation to `Verify`.
- The dedicated `Verify` step is authoritative. In a fresh task worktree it invokes exactly `make test`; it does not first run setup, install requirements, initialize submodules, select a project runtime, or perform any other hidden preparation.
- The repository's `make test` target must work from a clean worktree. It must initialize required submodules, install deterministic and pinned project dependencies, prepare any project-owned environment, and run the complete validation suite.
- RGN supplies the configured base worker toolchain and runtime. The repository declares its runtime constraints and owns reproducible project dependency installation and setup behind `make test`.
- When `Verify` fails and returns structured diagnostics to `Implement`, respond to those diagnostics without independently reconstructing the `Verify` environment.
- Do not weaken or remove tests merely to make verification or CI pass.

## Managed protocol

- Protocol v6 adds the explicit `Merge to dev` lifecycle step after `Publish`; Publish alone is not task completion.
- `Merge to dev` uses GitHub-native required-check classification, bounded polling, exact head/base identity, and retries the same workflow from `Implement` on failure.
- Terminal failure after publication preserves the PR, remote branch, and task worktree for investigation.

## Managed make contract

- Protocol v5 owns root `Makefile.rgn`; projects keep ownership of their selected conventional makefile and of the self-contained `test` target.
- GNU make selects `GNUmakefile`, `makefile`, then `Makefile`. RGN adds only a bounded marker block to that selected file, including `Makefile.rgn` and supplying missing `review` and `release` aliases.
- Existing project-owned `review` and `release` recipes are preserved. Ambiguous or malformed managed wiring is a conflict requiring manual reconciliation.
- After fast-forwarding a clean, pre-existing `dev` checkout, protocol v5 synchronizes every declared submodule to the exact gitlink recorded by the new superproject `HEAD`; matching checkouts are left untouched.
- `make review` establishes that managed synchronization invariant and then invokes exactly the project-owned `make test` contract.
- This managed synchronization complements rather than replaces the repository contract: project-owned `make test` must still initialize and check required submodules in a fresh Verify checkout.
- `make release` is human-only. It requires clean exact `dev`, runs `make test`, and creates or reuses the `dev` to `main` pull request with merge auto-merge gated by required `test`; it never pushes protected branches directly.
