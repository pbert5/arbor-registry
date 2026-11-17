# Arbor Registry agent guide

## CI/local test discrepancies

When GitHub Actions tests fail while comparable local tests pass, and there is
no obvious runner deficiency, use the isolated read-only
`ci-discrepancy-consultant` role (`gpt-6.1-sol`, medium effort). Obvious missing
tools, dependencies, services, or runner setup problems stay with the normal
owner. Confirm the exact failing SHA and local test comparability first.

Give the consultant the workflow/job links, relevant logs, local commands and
results, and known environment differences. It returns verified facts,
hypotheses, and a bounded fix/reproduction contract; the existing writer keeps
implementation and verification ownership. Reuse one consultant for the same
failure episode, not one per status poll. Its read-only instructions prohibit
repository, runner, credential, or runtime changes. They are behavioral limits,
not a separate security sandbox. This narrow escalation leaves other model
defaults and burn tiers unchanged.

## Worktree location

Create new worktrees under `<actual-main-checkout>/.worktrees/<task-slug>`.
Identify the actual main checkout with `git worktree list --porcelain`; do not
treat an existing linked worktree's `git rev-parse --show-toplevel` as the main
checkout or nest another `.worktrees/` inside it. Before creation, verify
`git -C "$MAIN_CHECKOUT" check-ignore -q .worktrees/probe` succeeds. Add
`/.worktrees/` to that main checkout's `.gitignore` if missing, then verify
again. One mutation owner per task, branch, and worktree.

This is the standard for new worktrees, not permission to relocate or delete
existing worktrees. Preserve active, dirty, and unpublished work in place;
migration or cleanup requires separate coordination.

