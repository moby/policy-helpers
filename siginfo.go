package verifier

import (
	"fmt"

	"github.com/moby/policy-helpers/roots"
	digest "github.com/opencontainers/go-digest"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type NoSigChainError struct {
	Target         digest.Digest
	HasAttestation bool
}

var _ error = &NoSigChainError{}

func (e *NoSigChainError) Error() string {
	if e.HasAttestation {
		return fmt.Sprintf("no signature found for image %s", e.Target)
	}
	return fmt.Sprintf("no provenance attestation found for image %s", e.Target)
}

type SignatureInfo struct {
	Signer          *certificate.Summary                 `json:"signer,omitempty"`
	Timestamps      []verify.TimestampVerificationResult `json:"timestamps,omitempty"`
	DockerReference string                               `json:"dockerReference,omitempty"`
	TrustRootStatus roots.Status                         `json:"trustRootStatus,omitzero"`
	IsDHI           bool                                 `json:"isDHI,omitempty"`
}
