package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/moby/policy-helpers/image"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// providerFromRef borrowed from buildkit/contentutil to avoid dependency
func providerFromRef(ref string) (ocispecs.Descriptor, image.ReferrersProvider, error) {
	headers := http.Header{}

	dro := docker.ResolverOptions{
		Headers: headers,
	}

	if creds, ok := os.LookupEnv("DOCKER_AUTH_CREDENTIALS"); ok {
		user, secret, ok := strings.Cut(creds, ":")
		if ok {
			dro.Hosts = docker.ConfigureDefaultRegistries(
				docker.WithAuthorizer(docker.NewDockerAuthorizer(docker.WithAuthCreds(func(host string) (string, string, error) {
					return user, secret, nil
				}))),
			)
		}
	}
	remote := docker.NewResolver(dro)

	name, desc, err := remote.Resolve(context.TODO(), ref)
	if err != nil {
		return ocispecs.Descriptor{}, nil, err
	}

	fetcher, err := remote.Fetcher(context.TODO(), name)
	if err != nil {
		return ocispecs.Descriptor{}, nil, err
	}

	refs, ok := fetcher.(remotes.ReferrersFetcher)
	if !ok {
		return ocispecs.Descriptor{}, nil, errors.Errorf("fetcher does not support referrers")
	}

	return desc, fromFetcher(fetcher, refs), nil
}

func fromFetcher(f remotes.Fetcher, refs remotes.ReferrersFetcher) image.ReferrersProvider {
	return &fetchedProvider{
		f:                f,
		ReferrersFetcher: refs,
	}
}

type fetchedProvider struct {
	f remotes.Fetcher
	remotes.ReferrersFetcher
}

func (p *fetchedProvider) ReaderAt(ctx context.Context, desc ocispecs.Descriptor) (content.ReaderAt, error) {
	rc, err := p.f.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}

	return &readerAt{Reader: rc, Closer: rc, size: desc.Size}, nil
}

type readerAt struct {
	io.Reader
	io.Closer
	size   int64
	offset int64
}

func (r *readerAt) ReadAt(b []byte, off int64) (int, error) {
	if ra, ok := r.Reader.(io.ReaderAt); ok {
		return ra.ReadAt(b, off)
	}

	if r.offset != off {
		if seeker, ok := r.Reader.(io.Seeker); ok {
			if _, err := seeker.Seek(off, io.SeekStart); err != nil {
				return 0, err
			}
			r.offset = off
		} else {
			return 0, errors.Errorf("unsupported offset")
		}
	}

	var totalN int
	for len(b) > 0 {
		n, err := r.Read(b)
		if errors.Is(err, io.EOF) && n == len(b) {
			err = nil
		}
		r.offset += int64(n)
		totalN += n
		b = b[n:]
		if err != nil {
			return totalN, err
		}
	}
	return totalN, nil
}

func (r *readerAt) Size() int64 {
	return r.size
}
