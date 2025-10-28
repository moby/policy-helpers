package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"

	policy "github.com/moby/policy-helpers"
	"github.com/moby/policy-helpers/githubapi"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func main() {
	if err := run(); err != nil {
		log.Printf("error: %+v", err)
		os.Exit(1)
	}
}

func run() error {
	var opts struct {
		stateDir      string
		requireOnline bool
		debug         bool
		bundle        string
		repo          string
	}
	flag.StringVar(&opts.stateDir, "state-dir", "", "Path to state directory")
	flag.BoolVar(&opts.requireOnline, "require-online", false, "Require online TUF roots update")
	flag.BoolVar(&opts.debug, "debug", false, "Enable debug logging")
	flag.StringVar(&opts.bundle, "bundle", "", "Path to attestation bundle file (if empty, will pull from GitHub)")
	flag.StringVar(&opts.repo, "repo", "", "GitHub repository to pull attestation from (owner/repo)")

	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		return errors.Errorf("no command specified")
	}

	if opts.debug {
		metadata.SetLogger(&tufLogger{l: slog.Default()})
	}

	cfg := policy.Config{
		StateDir:      opts.stateDir,
		RequireOnline: opts.requireOnline,
	}
	v, err := policy.NewVerifier(cfg)
	if err != nil {
		return err
	}

	ctx := context.TODO()

	switch args[0] {
	case "artifact":
		args := args[1:]
		if len(args) == 0 {
			return errors.Errorf("no artifact path specified")
		}
		return runArtifactCmd(ctx, v, args[0], opts.bundle, opts.repo)
	default:
		return errors.Errorf("unknown command: %s", args[0])
	}
}

func runArtifactCmd(ctx context.Context, v *policy.Verifier, artifactPath string, bundlePath, repo string) error {
	var rc io.ReadCloser
	if artifactPath == "-" {
		rc = io.NopCloser(os.Stdin)
	} else {
		f, err := os.Open(artifactPath)
		if err != nil {
			return errors.Wrapf(err, "opening artifact file %q", artifactPath)
		}
		rc = f
	}

	dgst, err := digest.FromReader(rc)
	if err != nil {
		rc.Close()
		return errors.Wrapf(err, "computing digest for artifact %q", artifactPath)
	}

	rc.Close()

	var bundleBytes []byte
	if bundlePath != "" {
		b, err := os.ReadFile(bundlePath)
		if err != nil {
			return errors.Wrapf(err, "reading bundle file %q", bundlePath)
		}
		bundleBytes = b
	} else if repo != "" {
		bundleBytes, err = githubapi.PullAttestation(ctx, nil, dgst, repo)
		if err != nil {
			return errors.Wrapf(err, "pulling attestation from repo %q", repo)
		}
	} else {
		return errors.Errorf("either bundle path or repo must be specified")
	}

	verified, err := v.VerifyArtifact(ctx, dgst, bundleBytes)
	if err != nil {
		return errors.Wrapf(err, "verifying artifact %q", artifactPath)
	}

	log.Printf("artifact %q verified: %+v", artifactPath, verified)
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
