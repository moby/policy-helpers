package roots

import (
	"context"
	"embed"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"github.com/pkg/errors"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

type SigstoreRootsConfig struct {
	CachePath      string
	UpdateInterval time.Duration
	RequireOnline  bool
}

type TrustProvider struct {
	mu     sync.Mutex
	config SigstoreRootsConfig
	client *tuf.Client

	status Status
}

type Status struct {
	Error       error
	LastUpdated *time.Time
}

const (
	trustedRootFilename = "trusted_root.json"
)

func NewTrustProvider(cfg SigstoreRootsConfig) (*TrustProvider, error) {
	if cfg.CachePath == "" {
		return nil, errors.Errorf("cache path must be provided for trust provider")
	}

	def := tuf.DefaultOptions()
	def.CachePath = cfg.CachePath
	def.ForceCache = !cfg.RequireOnline

	cacheDir := filepath.Join(def.CachePath, tuf.URLToPath(def.RepositoryBaseURL))
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, errors.Wrap(err, "creating cache directory for trust provider")
	}

	tp := &TrustProvider{
		config: cfg,
	}

	unlock, err := tp.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	root, err := os.OpenRoot(cacheDir)
	if err != nil {
		return nil, errors.Wrap(err, "opening cache directory for trust provider")
	}
	defer root.Close()
	if _, err := root.Lstat("root.json"); err != nil {
		if !os.IsNotExist(err) {
			return nil, errors.Wrap(err, "statting root.json in cache directory for trust provider")
		}
		if err := copyEmbeddedRoot(EmbeddedTUF, root); err != nil {
			return nil, errors.Wrap(err, "initializing cache directory for trust provider with embedded root")
		}
	}

	agf := &airgappedFetcher{
		baseURL:       def.RepositoryBaseURL,
		cache:         root,
		onlineFetcher: fetcher.NewDefaultFetcher(),
		isOnline:      cfg.RequireOnline,
	}
	def.Fetcher = agf

	dt, err := root.ReadFile("root.json") // TODO(@tonistiigi): instead save all root chain to cache and load from embedded root
	if err != nil {
		return nil, err
	}
	def.Root = dt

	c, err := tuf.New(def)
	if err != nil {
		// this can still fail if the root has expired
		return nil, errors.WithStack(err)
	}
	tp.client = c
	agf.isOnline = true

	go tp.update()

	if cfg.UpdateInterval > 0 {
		go func() {
			ticker := time.NewTicker(cfg.UpdateInterval)
			defer ticker.Stop()
			for range ticker.C {
				tp.update()
			}
		}()
	}

	return tp, nil
}

func (tp *TrustProvider) update() error {
	unlock, err := tp.lock()
	if err != nil {
		tp.mu.Lock()
		tp.status = Status{Error: err}
		tp.mu.Unlock()
		return err
	}
	defer unlock()
	err = tp.client.Refresh()
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if err != nil {
		tp.status = Status{Error: err}
		return err
	}
	now := time.Now().UTC()
	tp.status = Status{LastUpdated: &now}
	return nil
}

func (tp *TrustProvider) wait(ctx context.Context) error {
	first := true
	errCh := make(chan error)
	for {
		tp.mu.Lock()
		status := tp.status
		tp.mu.Unlock()
		if status.LastUpdated != nil && status.Error == nil {
			return nil
		}
		if status.Error != nil && first {
			go func() {
				if err := tp.update(); err != nil {
					errCh <- err
				}
			}()
			first = false
		}
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (tp *TrustProvider) lock() (func() error, error) {
	lockPath := path.Join(tp.config.CachePath, ".lock")
	fileLock := flock.New(lockPath)
	if err := fileLock.Lock(); err != nil {
		return nil, errors.Wrap(err, "acquiring lock on trust provider cache")
	}
	return fileLock.Unlock, nil
}

func (tp *TrustProvider) TrustedRoot(ctx context.Context) (*root.TrustedRoot, Status, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var st Status
	if err := tp.wait(ctx); err != nil { // return indication of last refresh error? TODO(@tonistiigi) does this make GetTarget fail as well and separate instance of client is needed for optional refresh?
		st.Error = err
	}

	jsonBytes, err := tp.client.GetTarget(trustedRootFilename)
	if err != nil {
		return nil, st, err
	}
	tr, err := root.NewTrustedRootFromJSON(jsonBytes)
	return tr, st, err
}

type airgappedFetcher struct {
	baseURL       string
	cache         *os.Root
	onlineFetcher fetcher.Fetcher
	isOnline      bool
}

func (f *airgappedFetcher) DownloadFile(urlPath string, maxLength int64, dur time.Duration) ([]byte, error) {
	if f.isOnline {
		return f.onlineFetcher.DownloadFile(urlPath, maxLength, dur)
	}
	const timestampFilename = "timestamp.json"
	if urlPath == f.baseURL+"/"+timestampFilename {
		if dt, err := f.cache.ReadFile(timestampFilename); err == nil {
			return dt, nil
		}
	}
	return nil, &metadata.ErrDownloadHTTP{
		StatusCode: 404,
	}
}

func copyEmbeddedRoot(src embed.FS, dest *os.Root) error {
	subFS, err := fs.Sub(src, "tuf-root")
	if err != nil {
		return errors.WithStack(err)
	}
	return fs.WalkDir(subFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return dest.MkdirAll(p, 0o755)
		}
		in, err := subFS.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()

		if err := dest.MkdirAll(path.Dir(p), 0o755); err != nil {
			return err
		}
		out, err := dest.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}
