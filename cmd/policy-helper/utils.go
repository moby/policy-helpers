package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/distribution/reference"
	"github.com/moby/policy-helpers/image"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

const (
	hubRegistryDomain   = "docker.io"
	scoutRegistryDomain = "registry.scout.docker.com"
)

// providerFromRef borrowed from buildkit/contentutil to avoid dependency
func providerFromRef(ref reference.Named) (ocispecs.Descriptor, image.ReferrersProvider, error) {
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

	name, desc, err := remote.Resolve(context.TODO(), ref.String())
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

	return desc, fromFetcher(remote, fetcher, refs, ref.String(), reference.Domain(ref) == "docker.io"), nil
}

func fromFetcher(remote remotes.Resolver, f remotes.Fetcher, refs remotes.ReferrersFetcher, refName string, allowDHI bool) image.ReferrersProvider {
	return &fetchedProvider{
		remote:           remote,
		f:                f,
		ReferrersFetcher: refs,
		dhiAllowed:       allowDHI,
		refName:          refName,
	}
}

type fetchedProvider struct {
	remote remotes.Resolver
	f      remotes.Fetcher
	remotes.ReferrersFetcher
	refName string

	dhiAllowed          bool
	dhiInitMutex        sync.Mutex
	dhiReferrersFetcher image.ReferrersProvider
}

func (p *fetchedProvider) ReaderAt(ctx context.Context, desc ocispecs.Descriptor) (content.ReaderAt, error) {
	if p.dhiAllowed && image.IsDHI(ctx) {
		if desc.ArtifactType != "" || desc.MediaType == image.ArtifactTypeSigstoreBundle || desc.MediaType == image.MediaTypeCosignSimpleSigning {
			rp, err := p.dhiReferrersProvider(ctx)
			if err != nil {
				return nil, err
			}
			return rp.ReaderAt(ctx, desc)
		}
	}
	rc, err := p.f.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}

	return &readerAt{Reader: rc, Closer: rc, size: desc.Size}, nil
}

func (p *fetchedProvider) FetchReferrers(ctx context.Context, dgst digest.Digest, opts ...remotes.FetchReferrersOpt) ([]ocispecs.Descriptor, error) {
	if p.dhiAllowed && image.IsDHI(ctx) {
		rp, err := p.dhiReferrersProvider(ctx)
		if err != nil {
			return nil, err
		}
		return rp.FetchReferrers(ctx, dgst, opts...)
	}
	return p.ReferrersFetcher.FetchReferrers(ctx, dgst, opts...)
}

func (p *fetchedProvider) dhiReferrersProvider(ctx context.Context) (image.ReferrersProvider, error) {
	p.dhiInitMutex.Lock()
	defer p.dhiInitMutex.Unlock()

	if p.dhiReferrersFetcher != nil {
		return p.dhiReferrersFetcher, nil
	}
	name := p.refName
	if repo, found := strings.CutPrefix(name, hubRegistryDomain+"/"); found {
		name = scoutRegistryDomain + "/" + repo
	}

	fetcher, err := p.remote.Fetcher(ctx, name)
	if err != nil {
		return nil, err
	}
	refs, ok := fetcher.(remotes.ReferrersFetcher)
	if !ok {
		return nil, errors.Errorf("fetcher does not support referrers")
	}
	p.dhiReferrersFetcher = fromFetcher(p.remote, fetcher, refs, p.refName, false)
	return p.dhiReferrersFetcher, nil
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
