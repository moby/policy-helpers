package image

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	cerrdefs "github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

// memStore is an in-memory content.Provider backed by a digest→bytes map.
type memStore map[digest.Digest][]byte

func (s memStore) ReaderAt(_ context.Context, desc ocispecs.Descriptor) (content.ReaderAt, error) {
	data, ok := s[desc.Digest]
	if !ok {
		return nil, &notFoundError{desc.Digest}
	}
	return &bytesReaderAt{data: data}, nil
}

// notFoundError implements the unexported notFound interface from
// github.com/containerd/errdefs so cerrdefs.IsNotFound recognises it through
// pkg/errors wrapping.
type notFoundError struct{ d digest.Digest }

func (e *notFoundError) Error() string { return "not found: " + e.d.String() }
func (e *notFoundError) NotFound()     {}

type bytesReaderAt struct{ data []byte }

func (r *bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (r *bytesReaderAt) Size() int64  { return int64(len(r.data)) }
func (r *bytesReaderAt) Close() error { return nil }

// statementLayer describes one in-toto statement to embed in a test
// attestation manifest. When writeBlob is false the layer's bytes are NOT
// written to the store, simulating an unavailable blob.
type statementLayer struct {
	predicateType string
	payload       []byte
	writeBlob     bool
}

// buildChain constructs a SignatureChain whose AttestationManifest contains
// the given statement layers. All blobs that should be present (per
// statementLayer.writeBlob) are written to the returned in-memory provider.
func buildChain(t *testing.T, stmts []statementLayer) *SignatureChain {
	t.Helper()
	store := make(memStore)

	put := func(mt string, b []byte) ocispecs.Descriptor {
		dgst := digest.FromBytes(b)
		store[dgst] = b
		return ocispecs.Descriptor{MediaType: mt, Digest: dgst, Size: int64(len(b))}
	}
	putJSON := func(mt string, v any) ocispecs.Descriptor {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return put(mt, b)
	}

	var layerDescs []ocispecs.Descriptor
	for _, s := range stmts {
		var d ocispecs.Descriptor
		if s.writeBlob {
			d = put(ArtifactTypeInTotoJSON, s.payload)
		} else {
			d = ocispecs.Descriptor{
				MediaType: ArtifactTypeInTotoJSON,
				Digest:    digest.FromBytes(s.payload),
				Size:      int64(len(s.payload)),
			}
		}
		if s.predicateType != "" {
			d.Annotations = map[string]string{
				"in-toto.io/predicate-type": s.predicateType,
			}
		}
		layerDescs = append(layerDescs, d)
	}

	attMfstDesc := putJSON(ocispecs.MediaTypeImageManifest, ocispecs.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispecs.MediaTypeImageManifest,
		Config:    putJSON(ocispecs.MediaTypeImageConfig, struct{}{}),
		Layers:    layerDescs,
	})
	return &SignatureChain{
		AttestationManifest: &Manifest{Descriptor: attMfstDesc},
		Provider:            store,
	}
}

var (
	provenance = []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[],"predicate":{}}`)
	sbom       = []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document","subject":[],"predicate":{}}`)
)

func TestResolveAttestationStatements(t *testing.T) {
	ctx := context.Background()

	t.Run("nil_guards_return_nil", func(t *testing.T) {
		// Both forms of "no chain to walk" return (nil, nil) without error.
		blobs, err := ResolveAttestationStatements(ctx, nil, nil)
		require.NoError(t, err)
		require.Nil(t, blobs)

		blobs, err = ResolveAttestationStatements(ctx, &SignatureChain{Provider: make(memStore)}, nil)
		require.NoError(t, err)
		require.Nil(t, blobs)
	})

	t.Run("nil_filter_returns_all_annotated_layers", func(t *testing.T) {
		sc := buildChain(t, []statementLayer{
			{predicateType: SLSAProvenancePredicateType02, payload: provenance, writeBlob: true},
			{predicateType: "https://spdx.dev/Document", payload: sbom, writeBlob: true},
		})
		blobs, err := ResolveAttestationStatements(ctx, sc, nil)
		require.NoError(t, err)
		require.Len(t, blobs, 2)
	})

	t.Run("predicate_type_filter_selects_matching_layers", func(t *testing.T) {
		// Filter passes only layers whose annotation is in the requested set;
		// other annotated layers and unrelated annotations are excluded.
		sc := buildChain(t, []statementLayer{
			{predicateType: SLSAProvenancePredicateType02, payload: provenance, writeBlob: true},
			{predicateType: "https://spdx.dev/Document", payload: sbom, writeBlob: true},
			{predicateType: "https://example.com/other", payload: []byte(`{}`), writeBlob: true},
		})
		blobs, err := ResolveAttestationStatements(ctx, sc,
			[]string{SLSAProvenancePredicateType02, "https://spdx.dev/Document"})
		require.NoError(t, err)
		require.Len(t, blobs, 2)

		got := map[string]bool{}
		for _, b := range blobs {
			got[b.Descriptor.Annotations["in-toto.io/predicate-type"]] = true
		}
		require.True(t, got[SLSAProvenancePredicateType02])
		require.True(t, got["https://spdx.dev/Document"])
	})

	t.Run("unannotated_layers_are_skipped", func(t *testing.T) {
		// Layers without an in-toto.io/predicate-type annotation are not
		// statements; they must never be returned, even with no filter.
		sc := buildChain(t, []statementLayer{
			{predicateType: "", payload: []byte(`{"unannotated":"data"}`), writeBlob: true},
			{predicateType: SLSAProvenancePredicateType02, payload: provenance, writeBlob: true},
		})
		blobs, err := ResolveAttestationStatements(ctx, sc, nil)
		require.NoError(t, err)
		require.Len(t, blobs, 1)
		require.Equal(t, SLSAProvenancePredicateType02, blobs[0].Descriptor.Annotations["in-toto.io/predicate-type"])
	})

	t.Run("order_matches_manifest_layer_order", func(t *testing.T) {
		// OCI manifests define `layers` as an ordered list; the function must
		// preserve that order in its return value.
		v1 := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v1"}`)
		sc := buildChain(t, []statementLayer{
			{predicateType: SLSAProvenancePredicateType02, payload: provenance, writeBlob: true},
			{predicateType: SLSAProvenancePredicateType1, payload: v1, writeBlob: true},
		})
		blobs, err := ResolveAttestationStatements(ctx, sc, nil)
		require.NoError(t, err)
		require.Len(t, blobs, 2)
		require.Equal(t, SLSAProvenancePredicateType02, blobs[0].Descriptor.Annotations["in-toto.io/predicate-type"])
		require.Equal(t, SLSAProvenancePredicateType1, blobs[1].Descriptor.Annotations["in-toto.io/predicate-type"])
	})

	t.Run("missing_statement_blob_returns_not_found_error", func(t *testing.T) {
		// Fail fast and preserve NotFound semantics so callers (e.g. moby's
		// /images/{name}/attestations handler) can branch on it.
		sc := buildChain(t, []statementLayer{
			{predicateType: SLSAProvenancePredicateType02, payload: provenance, writeBlob: false},
		})
		blobs, err := ResolveAttestationStatements(ctx, sc, nil)
		require.Error(t, err)
		require.Nil(t, blobs)
		require.True(t, cerrdefs.IsNotFound(err),
			"error chain should preserve NotFound, got: %v", err)
	})

	t.Run("missing_statement_blob_is_ignored_when_filtered_out", func(t *testing.T) {
		// Key contract: we only fetch blobs we'd return. A missing layer that
		// doesn't match the filter must not cause an error.
		sc := buildChain(t, []statementLayer{
			{predicateType: SLSAProvenancePredicateType02, payload: provenance, writeBlob: true},
			{predicateType: "https://spdx.dev/Document", payload: sbom, writeBlob: false},
		})
		blobs, err := ResolveAttestationStatements(ctx, sc, []string{SLSAProvenancePredicateType02})
		require.NoError(t, err)
		require.Len(t, blobs, 1)
		require.Equal(t, SLSAProvenancePredicateType02, blobs[0].Descriptor.Annotations["in-toto.io/predicate-type"])
	})
}
