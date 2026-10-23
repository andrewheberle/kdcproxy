## Conventions

- **Commits** follow Conventional Commits (`feat:`, `fix:`, `chore:`, etc.).
- **Features** ship with tests covering the new behaviour.
- **Bug fixes** ship with a regression test that goes red with the bug present and green with the fix applied.
- **Dependencies**: ask the user for approval before adding, removing or upgrading any module in `go.mod`.
- **Done** means all three checks pass on the final change:
  1. `gofmt -l .` prints nothing (run `gofmt -w .` to fix)
  2. `golangci-lint run` reports no issues
  3. `go test ./...` passes
