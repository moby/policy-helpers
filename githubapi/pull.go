package githubapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	cerrdefs "github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
)

func PullAttestation(ctx context.Context, client *http.Client, dgst digest.Digest, repo string) ([]byte, error) {
	// TODO: github token
	url := fmt.Sprintf("https://api.github.com/repos/%s/attestations/%s?predicate_type=%s", repo, dgst, "https://slsa.dev/provenance/v1")

	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "creating request to %s", url)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "making request to %s", url)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.Wrapf(cerrdefs.ErrNotFound, "attestation for digest %s in repo %s not found", dgst, repo)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected status code %d from %s", resp.StatusCode, url)
	}

	var result struct {
		Attestations []struct {
			Bundle *json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}

	rdr := io.LimitReader(resp.Body, 4*1024*1024)

	dec := json.NewDecoder(rdr)
	if err := dec.Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.Errorf("unexpected data after JSON bundle array")
	}

	if len(result.Attestations) == 0 {
		return nil, errors.Wrapf(cerrdefs.ErrNotFound, "no attestations found for digest %s in repo %s", dgst, repo)
	}

	return *result.Attestations[0].Bundle, nil
}
