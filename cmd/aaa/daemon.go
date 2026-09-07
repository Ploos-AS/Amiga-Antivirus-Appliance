package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	apihttp "github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/api"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/daemon"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/dropfolder"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanhistory"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/webui"
)

const (
	defaultStateRoot      = "/data/aaa/state"
	defaultIncomingRoot   = "/data/aaa/incoming"
	defaultDropRoot       = "/data/aaa/drop"
	defaultListen         = "127.0.0.1:8080"
	defaultMaxUploadBytes = int64(256 * 1024 * 1024)
	defaultDropPoll       = 2 * time.Second
	defaultDropStable     = 5 * time.Second
)

func daemonCommand(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workers := fs.Int("workers", 1, "number of concurrent scan workers")
	queueDepth := fs.Int("queue-depth", 32, "maximum number of queued scans")
	stateRoot := fs.String("state-root", stateRootFromEnv(), "persistent daemon state directory")
	incomingRoot := fs.String("incoming-root", incomingRootFromEnv(), "controlled scan upload directory")
	dropRoot := fs.String("drop-root", dropRootFromEnv(), "externally writable drop-folder directory")
	dropPoll := fs.Duration("drop-poll", defaultDropPoll, "drop-folder polling interval")
	dropStable := fs.Duration("drop-stable", defaultDropStable, "required unchanged time before drop-folder ingest")
	maxUploadBytes := fs.Int64("max-upload-bytes", defaultMaxUploadBytes, "maximum HTTP/drop scan input size in bytes")
	listen := fs.String("listen", listenFromEnv(), "HTTP API listen address")
	allowRemote := fs.Bool("allow-remote", false, "allow HTTP API to bind to a non-loopback address")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "daemon takes no positional arguments")
		os.Exit(2)
	}
	if *maxUploadBytes < 1 {
		fmt.Fprintln(os.Stderr, "max-upload-bytes must be at least 1")
		os.Exit(2)
	}
	if *dropPoll <= 0 || *dropStable <= 0 {
		fmt.Fprintln(os.Stderr, "drop-poll and drop-stable must be positive")
		os.Exit(2)
	}
	if *dropRoot == *incomingRoot {
		fmt.Fprintln(os.Stderr, "drop-root and incoming-root must differ")
		os.Exit(2)
	}
	if err := validateListenAddress(*listen, *allowRemote); err != nil {
		fmt.Fprintf(os.Stderr, "daemon listen configuration failed: %v\n", err)
		os.Exit(2)
	}

	history, err := scanhistory.New(*stateRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan history failed: %v\n", err)
		os.Exit(1)
	}
	if _, err := history.RecoverInterrupted(); err != nil {
		fmt.Fprintf(os.Stderr, "scan history replay failed: %v\n", err)
		os.Exit(1)
	}

	manager, err := daemon.NewWithRecorder(*workers, *queueDepth, func(path string) (scanner.Result, error) {
		return scanForDaemon(path)
	}, history)
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon configuration failed: %v\n", err)
		os.Exit(2)
	}

	dropReceiptPath := filepath.Join(*stateRoot, "drop-ingest.json")
	dropWatcher := dropfolder.Watcher{
		Root:         *dropRoot,
		IncomingRoot: *incomingRoot,
		ReceiptPath:  dropReceiptPath,
		PollInterval: *dropPoll,
		StableFor:    *dropStable,
		MaxBytes:     *maxUploadBytes,
		Submit: func(path string) error {
			_, err := manager.Submit(path)
			return err
		},
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	apiHandler := apihttp.NewHandlerWithSubmission(history, version, apihttp.SubmissionConfig{
		Submitter:      manager,
		IncomingRoot:   *incomingRoot,
		MaxUploadBytes: *maxUploadBytes,
	})
	server := &http.Server{
		Addr:              *listen,
		Handler:           webui.New(apiHandler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}

	managerDone := make(chan error, 1)
	go func() { managerDone <- manager.Run(ctx) }()
	dropDone := make(chan error, 1)
	go func() { dropDone <- dropWatcher.Run(ctx) }()
	serverDone := make(chan error, 1)
	go func() {
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serverDone <- err
	}()

	fmt.Fprintf(os.Stderr, "AAA daemon started workers=%d queue-depth=%d history=%s incoming=%s drop=%s drop-receipts=%s drop-poll=%s drop-stable=%s max-input-bytes=%d api=%s allow-remote=%t\n", *workers, *queueDepth, history.Path(), *incomingRoot, *dropRoot, dropReceiptPath, *dropPoll, *dropStable, *maxUploadBytes, *listen, *allowRemote)

	var runErr error
	managerFinished := false
	dropFinished := false
	select {
	case <-signalCtx.Done():
		cancel()
	case err := <-managerDone:
		managerFinished = true
		if err != nil {
			runErr = fmt.Errorf("scan manager: %w", err)
		}
		cancel()
	case err := <-dropDone:
		dropFinished = true
		if err != nil {
			runErr = fmt.Errorf("drop watcher: %w", err)
		}
		cancel()
	case err := <-serverDone:
		if err != nil {
			runErr = fmt.Errorf("HTTP API: %w", err)
		}
		cancel()
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := server.Shutdown(shutdownCtx); err != nil && runErr == nil {
		runErr = fmt.Errorf("HTTP API shutdown: %w", err)
	}
	shutdownCancel()

	if !managerFinished {
		if err := <-managerDone; err != nil && runErr == nil {
			runErr = fmt.Errorf("scan manager: %w", err)
		}
	}
	if !dropFinished {
		if err := <-dropDone; err != nil && runErr == nil {
			runErr = fmt.Errorf("drop watcher: %w", err)
		}
	}

	if runErr != nil {
		fmt.Fprintf(os.Stderr, "AAA daemon failed: %v\n", runErr)
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

func incomingRootFromEnv() string {
	if root := os.Getenv("AAA_INCOMING_ROOT"); root != "" {
		return root
	}
	return defaultIncomingRoot
}

func dropRootFromEnv() string {
	if root := os.Getenv("AAA_DROP_ROOT"); root != "" {
		return root
	}
	return defaultDropRoot
}

func listenFromEnv() string {
	if listen := os.Getenv("AAA_LISTEN"); listen != "" {
		return listen
	}
	return defaultListen
}
