package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/daemon"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanhistory"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

const defaultStateRoot = "/data/aaa/state"

func daemonCommand(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workers := fs.Int("workers", 1, "number of concurrent scan workers")
	queueDepth := fs.Int("queue-depth", 32, "maximum number of queued scans")
	stateRoot := fs.String("state-root", stateRootFromEnv(), "persistent daemon state directory")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "daemon takes no positional arguments")
		os.Exit(2)
	}

	history, err := scanhistory.New(*stateRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan history failed: %v\n", err)
		os.Exit(1)
	}
	if _, err := history.LoadLatest(); err != nil {
		fmt.Fprintf(os.Stderr, "scan history replay failed: %v\n", err)
		os.Exit(1)
	}

	manager, err := daemon.NewWithRecorder(*workers, *queueDepth, scanner.ScanFile, history)
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon configuration failed: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "AAA daemon started workers=%d queue-depth=%d history=%s\n", *workers, *queueDepth, history.Path())
	if err := manager.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "AAA daemon failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "AAA daemon stopped")
}

func stateRootFromEnv() string {
	if root := os.Getenv("AAA_STATE_ROOT"); root != "" {
		return root
	}
	return defaultStateRoot
}
