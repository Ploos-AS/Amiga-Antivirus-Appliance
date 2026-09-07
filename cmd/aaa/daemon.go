package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/daemon"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

func daemonCommand(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workers := fs.Int("workers", 1, "number of concurrent scan workers")
	queueDepth := fs.Int("queue-depth", 32, "maximum number of queued scans")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "daemon takes no positional arguments")
		os.Exit(2)
	}

	manager, err := daemon.New(*workers, *queueDepth, scanner.ScanFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon configuration failed: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "AAA daemon started workers=%d queue-depth=%d\n", *workers, *queueDepth)
	manager.Run(ctx)
	fmt.Fprintln(os.Stderr, "AAA daemon stopped")
}
