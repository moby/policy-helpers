package verifier

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/moby/policy-helpers/image"
	"github.com/moby/policy-helpers/roots"
	"github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
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
	Signer          certificate.Summary                  `json:"signature"`
	Timestamps      []verify.TimestampVerificationResult `json:"timestamps"`
	DockerReference string                               `json:"docker-reference,omitempty"`
	TrustRootStatus roots.Status                         `json:"trust-root-status,omitempty"`
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

	trustedRoot, st, err := tp.TrustedRoot(ctx)
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

	return &SignatureInfo{
		TrustRootStatus: st,
		Signer:          *result.Signature.Certificate,
		Timestamps:      result.VerifiedTimestamps,
	}, nil
}

func (v *Verifier) VerifyImage(ctx context.Context, provider image.ReferrersProvider, desc ocispecs.Descriptor, platform *ocispecs.Platform) (*SignatureInfo, error) {
	sc, err := image.ResolveSignatureChain(ctx, provider, desc, platform)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving signature chain for image %s", desc.Digest)
	}

	if sc.AttestationManifest == nil || sc.SignatureManifest == nil {
		return nil, errors.Errorf("no attestation or signature found for image %s", desc.Digest)
	}

	attestationBytes, err := sc.ManifestBytes(ctx, sc.AttestationManifest)
	if err != nil {
		return nil, errors.Wrapf(err, "reading attestation manifest %s", sc.AttestationManifest.Digest)
	}

	var attestation ocispecs.Manifest
	if err := json.Unmarshal(attestationBytes, &attestation); err != nil {
		return nil, errors.Wrapf(err, "unmarshaling attestation manifest %s", sc.AttestationManifest.Digest)
	}

	if attestation.Subject == nil {
		return nil, errors.Errorf("attestation manifest %s has no subject", sc.AttestationManifest.Digest)
	}
	if attestation.Subject.Digest != sc.ImageManifest.Digest {
		return nil, errors.Errorf("attestation manifest %s subject digest %s does not match image manifest digest %s", sc.AttestationManifest.Digest, attestation.Subject.Digest, sc.ImageManifest.Digest)
	}
	if attestation.Subject.MediaType != ocispecs.MediaTypeImageManifest && attestation.Subject.MediaType != ocispecs.MediaTypeImageIndex {
		return nil, errors.Errorf("attestation manifest %s subject media type %s is not an image manifest or index", sc.AttestationManifest.Digest, attestation.Subject.MediaType)
	}
	if attestation.Subject.Size != sc.ImageManifest.Size {
		return nil, errors.Errorf("attestation manifest %s subject size %d does not match image manifest size %d", sc.AttestationManifest.Digest, attestation.Subject.Size, sc.ImageManifest.Size)
	}

	anyCert, err := anyCerificateIdentity()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var artifactPolicy verify.ArtifactPolicyOption

	tp, err := v.loadTrustProvider()
	if err != nil {
		return nil, errors.Wrap(err, "loading trust provider")
	}

	trustedRoot, st, err := tp.TrustedRoot(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "getting trusted root")
	}

	gv, err := verify.NewVerifier(trustedRoot, verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return nil, errors.Wrap(err, "creating verifier")
	}

	sigBytes, err := sc.ManifestBytes(ctx, sc.SignatureManifest)
	if err != nil {
		return nil, errors.Wrapf(err, "reading signature manifest %s", sc.SignatureManifest.Digest)
	}

	var mfst ocispecs.Manifest
	if err := json.Unmarshal(sigBytes, &mfst); err != nil {
		return nil, errors.Wrapf(err, "unmarshaling signature manifest %s", sc.SignatureManifest.Digest)
	}

	// basic validations
	if mfst.Subject == nil {
		return nil, errors.Errorf("signature manifest %s has no subject", sc.SignatureManifest.Digest)
	}
	if mfst.Subject.Digest != sc.AttestationManifest.Digest {
		return nil, errors.Errorf("signature manifest %s subject digest %s does not match attestation manifest digest %s", sc.SignatureManifest.Digest, mfst.Subject.Digest, sc.AttestationManifest.Digest)
	}
	if mfst.Subject.MediaType != ocispecs.MediaTypeImageManifest && mfst.Subject.MediaType != ocispecs.MediaTypeImageIndex {
		return nil, errors.Errorf("signature manifest %s subject media type %s is not an image manifest or index", sc.SignatureManifest.Digest, mfst.Subject.MediaType)
	}
	if mfst.Subject.Size != sc.AttestationManifest.Size {
		return nil, errors.Errorf("signature manifest %s subject size %d does not match attestation manifest size %d", sc.SignatureManifest.Digest, mfst.Subject.Size, sc.AttestationManifest.Size)
	}

	if len(mfst.Layers) != 1 {
		return nil, errors.Errorf("signature manifest %s has %d layers, expected 1", sc.SignatureManifest.Digest, len(mfst.Layers))
	}
	layer := mfst.Layers[0]

	var dockerReference string

	var se verify.SignedEntity
	switch layer.MediaType {
	case image.ArtifactTypeSigstoreBundle:
		if mfst.ArtifactType != image.ArtifactTypeSigstoreBundle {
			return nil, errors.Errorf("signature manifest %s is not a bundle (artifact type %q)", sc.SignatureManifest.Digest, mfst.ArtifactType)
		}
		bundleBytes, err := image.ReadBlob(ctx, provider, layer)
		if err != nil {
			return nil, errors.Wrapf(err, "reading bundle layer %s from signature manifest %s", layer.Digest, sc.SignatureManifest.Digest)
		}
		b, err := loadBundle(bundleBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "loading signature bundle from manifest %s", sc.SignatureManifest.Digest)
		}
		se = b

		alg, rawDgst, err := rawDigest(sc.AttestationManifest.Digest)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		artifactPolicy = verify.WithArtifactDigest(alg, rawDgst)
	case image.MediaTypeCosignSimpleSigning:
		payloadBytes, err := image.ReadBlob(ctx, provider, layer)
		if err != nil {
			return nil, errors.Wrapf(err, "reading bundle layer %s from signature manifest %s", layer.Digest, sc.SignatureManifest.Digest)
		}
		var payload struct {
			Critical struct {
				Identity struct {
					DockerReference string `json:"docker-reference"`
				} `json:"identity"`
				Image struct {
					DockerManifestDigest string `json:"docker-manifest-digest"`
				} `json:"image"`
				Type string `json:"type"`
			} `json:"critical"`
			Optional map[string]any `json:"optional"`
		}
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			return nil, errors.Wrapf(err, "unmarshaling simple signing payload from manifest %s", sc.SignatureManifest.Digest)
		}
		if payload.Critical.Image.DockerManifestDigest != sc.AttestationManifest.Digest.String() {
			return nil, errors.Errorf("simple signing payload in manifest %s has docker-manifest-digest %s which does not match attestation manifest digest %s", sc.SignatureManifest.Digest, payload.Critical.Image.DockerManifestDigest, sc.AttestationManifest.Digest)
		}
		if payload.Critical.Type != "cosign container image signature" {
			return nil, errors.Errorf("simple signing payload in manifest %s has invalid type %q", sc.SignatureManifest.Digest, payload.Critical.Type)
		}
		dockerReference = payload.Critical.Identity.DockerReference
		// TODO: are more consistency checks needed for hashedrekord payload vs annotations?

		hrse, err := newHashedRecordSignedEntity(&mfst)
		if err != nil {
			return nil, errors.Wrapf(err, "loading hashed record signed entity from manifest %s", sc.SignatureManifest.Digest)
		}
		se = hrse
		alg, rawDgst, err := rawDigest(layer.Digest)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		artifactPolicy = verify.WithArtifactDigest(alg, rawDgst)
	default:
		return nil, errors.Errorf("signature manifest %s layer has invalid media type %s", sc.SignatureManifest.Digest, layer.MediaType)
	}

	policy := verify.NewPolicy(artifactPolicy, anyCert)

	result, err := gv.Verify(se, policy)
	if err != nil {
		return nil, errors.Wrap(err, "verifying bundle")
	}

	if result.Signature == nil || result.Signature.Certificate == nil {
		return nil, errors.Errorf("no valid signatures found")
	}

	return &SignatureInfo{
		TrustRootStatus: st,
		Signer:          *result.Signature.Certificate,
		Timestamps:      result.VerifiedTimestamps,
		DockerReference: dockerReference,
	}, nil
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
