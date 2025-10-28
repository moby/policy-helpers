package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	policy "github.com/moby/policy-helpers"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func main() {
	if err := run(); err != nil {
		log.Printf("error: %+v", err)
		os.Exit(1)
	}
}

func run() error {
	var stateDir string
	var requireOnline bool
	var debug bool
	flag.StringVar(&stateDir, "state-dir", "", "Path to state directory")
	flag.BoolVar(&requireOnline, "require-online", false, "Require online TUF roots update")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")

	flag.Parse()

	if debug {
		metadata.SetLogger(&tufLogger{l: slog.Default()})
	}

	cfg := policy.Config{
		StateDir:     stateDir,
		RquireOnline: requireOnline,
	}
	v, err := policy.NewVerifier(cfg)
	if err != nil {
		return err
	}

	_ = v // use the verifier as needed
	return nil
}

type tufLogger struct {
	l *slog.Logger
}

var _ metadata.Logger = (*tufLogger)(nil)

func (t *tufLogger) Error(err error, msg string, args ...any) {
	t.l.Error(fmt.Sprintf("%s: %v", msg, err), args...)
}

func (t *tufLogger) Info(msg string, args ...any) {
	t.l.Info(msg, args...)
}
