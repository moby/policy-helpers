package verifier

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"time"

	"github.com/moby/policy-helpers/roots"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"golang.org/x/sync/singleflight"
)

type Config struct {
	UpdateInterval time.Duration
	RequireOnline  bool
	StateDir       string
}

type Verifier struct {
	cfg Config
	sf  singleflight.Group
	tp  *roots.TrustProvider // tp may be nil if initialization failed
}

type SignatureInfo struct {
	Signer     certificate.Summary                  `json:"signature"`
	Timestamps []verify.TimestampVerificationResult `json:"timestamps"`
}

func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.StateDir == "" {
		return nil, errors.Errorf("state directory must be provided")
	}
	v := &Verifier{cfg: cfg}

	v.loadTrustProvider() // initialization fails on expired root/timestamp

	return v, nil
}

func (v *Verifier) VerifyArtifact(ctx context.Context, dgst digest.Digest, bundleBytes []byte) (*SignatureInfo, error) {
	anyCert, err := anyCerificateIdentity()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	alg, rawDgst, err := rawDigest(dgst)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest(alg, rawDgst), anyCert)

	b, err := loadBundle(bundleBytes)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	tp, err := v.loadTrustProvider()
	if err != nil {
		return nil, errors.Wrap(err, "loading trust provider")
	}

	trustedRoot, _, err := tp.TrustedRoot(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "getting trusted root")
	}

	gv, err := verify.NewVerifier(trustedRoot, verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return nil, errors.Wrap(err, "creating verifier")
	}

	result, err := gv.Verify(b, policy)
	if err != nil {
		return nil, errors.Wrap(err, "verifying bundle")
	}

	if result.Signature == nil || result.Signature.Certificate == nil {
		return nil, errors.Errorf("no valid signatures found")
	}

	si := &SignatureInfo{}
	si.Signer = *result.Signature.Certificate
	si.Timestamps = result.VerifiedTimestamps

	return si, nil
}

func (v *Verifier) loadTrustProvider() (*roots.TrustProvider, error) {
	var tpCache *roots.TrustProvider
	_, err, _ := v.sf.Do("", func() (any, error) {
		if v.tp != nil {
			tpCache = v.tp
			return nil, nil
		}
		tp, err := roots.NewTrustProvider(roots.SigstoreRootsConfig{
			CachePath:      filepath.Join(v.cfg.StateDir, "tuf"),
			UpdateInterval: v.cfg.UpdateInterval,
			RequireOnline:  v.cfg.RequireOnline,
		})
		if err != nil {
			return nil, err
		}
		v.tp = tp
		tpCache = tp
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return tpCache, nil
}

func anyCerificateIdentity() (verify.PolicyOption, error) {
	sanMatcher, err := verify.NewSANMatcher("", ".*")
	if err != nil {

		return nil, err
	}

	issuerMatcher, err := verify.NewIssuerMatcher("", ".*")
	if err != nil {
		return nil, err
	}

	extensions := certificate.Extensions{
		RunnerEnvironment: "github-hosted",
	}

	certId, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, extensions)
	if err != nil {
		return nil, err
	}

	return verify.WithCertificateIdentity(certId), nil
}

func loadBundle(dt []byte) (*bundle.Bundle, error) {
	var bundle bundle.Bundle
	bundle.Bundle = new(protobundle.Bundle)

	err := bundle.UnmarshalJSON(dt)
	if err != nil {
		return nil, err
	}

	return &bundle, nil
}

func rawDigest(d digest.Digest) (string, []byte, error) {
	alg := d.Algorithm().String()
	b, err := hex.DecodeString(d.Encoded())
	if err != nil {
		return "", nil, errors.Wrapf(err, "decoding digest %s", d)
	}
	return alg, b, nil
}
