// Command dev lands work in the shared main checkout and keeps it usable:
// land, gate-commit, status, protect and private worktrees. It imports only
// development tooling packages (see boundary_test.go), never product code, so
// it builds and rolls a landing back even while the shared tree holds applied
// sources that do not compile. The development fixture, signoff, generated
// documentation and disk collection are cmd/devenv's.
package main

import (
	"fmt"
	"os"
)

const usage = `Usage: go run ./cmd/dev <land|gate-commit|sync|status|protect|worktree> [options]

  land -from WORKTREE  Under the landing lock, apply a worktree's change to the
         shared tree, gate the touched files, roll back on failure; see land -h.
  gate-commit -m MSG  Under the landing lock, make check, then commit if green.
  sync   Under the landing lock, fast-forward the shared checkout to its
         upstream and protect it again; use it instead of git pull there.
  status  Shared checkout HEAD vs upstream, the landing in progress (marker
         .git/lindm-landing.current), landing/integration lock holders, and
         uncommitted files; re-protects tracked files it finds writable.
  protect  Make the shared checkout's tracked files read-only (a-w) unless a
         landing holds the lock; see protect -h.
  worktree add|list|audit|prune  Private worktrees in <main>.worktrees; see
         worktree help.

Every command acts on the shared main checkout of the repository containing
the working directory, so run them from your private worktree. The fixture,
signoff, pre-push, generate-docs and gc are go run ./cmd/devenv.
`

func run() error {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("a command is required")
	}
	switch verb, args := os.Args[1], os.Args[2:]; verb {
	case "help", "-h", "--help":
		_, err := fmt.Print(usage)
		return err
	case "worktree":
		return runWorktree(args)
	case "land":
		return runLand(args)
	case "status":
		return runStatus(args)
	case "gate-commit":
		return runGateCommit(args)
	case "protect":
		return runProtect(args)
	case "sync":
		return runSync(args)
	default:
		return fmt.Errorf("unknown command %q; use help (the fixture, signoff, pre-push, generate-docs and gc moved to go run ./cmd/devenv)", verb)
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dev:", err)
		os.Exit(1)
	}
}
