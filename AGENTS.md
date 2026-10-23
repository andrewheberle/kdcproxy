## Conventions

- **Commits** follow Conventional Commits (`feat:`, `fix:`, `chore:`, etc.).
- **Features** ship with tests covering the new behaviour.
- **Bug fixes** ship with a regression test that goes red with the bug present and green with the fix applied.
- **Dependencies**: ask the user for approval before adding, removing or upgrading any module in `go.mod`.
- **Done** means all three checks pass on the final change:
  1. `gofmt -l .` prints nothing (run `gofmt -w .` to fix)
  2. `golangci-lint run` reports no issues
  3. `go test ./...` passes

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues for `andrewheberle/kdcproxy`, using the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Uses the five default triage labels as-is (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
