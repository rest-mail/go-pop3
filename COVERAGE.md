# Coverage exceptions

CI fails when statement coverage falls below 95%. Coverage is counted across
every package (`-coverpkg=./...`), because the RFC proofs in `internal/rfctest`
drive the library from outside it. These are the statements left uncovered,
each with the reason. Add an entry here whenever you leave a statement
uncovered.

| File | Function | Statements | Reason |
|------|----------|------------|--------|
| `server.go` | `acceptLoop` | `slog.Error(...)` and `continue` after an `Accept` error outside shutdown | Needs a listener whose `Accept` fails while the server is running. Not tested yet; a fake `net.Listener` would cover it. |
| `server.go` | `acceptLoop` | `s.limiter.Release(ip)`, `conn.Close()` and `return` when `trackConn` refuses | Happens only when `Shutdown` wins the race between `Accept` returning and `trackConn` taking the lock; a test cannot order that without a hook in the server. |
| `server.go` | `trackConn` | `return false` | The same shutdown race as above. |
| `internal/checklist/main.go` | `main` | `os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))` | Exiting the process cannot be tested in-process. All of the checker's logic is in `run`, which the tests cover; CI also runs the command itself. |
