package verifier

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"github.com/moby/policy-helpers/roots"
	"github.com/pkg/errors"
	"golang.org/x/sync/singleflight"
)

type Config struct {
	UpdateInterval time.Duration
	RquireOnline   bool
	StateDir       string
}

type Verifier struct {
	cfg Config
	sf  singleflight.Group
	tp  *roots.TrustProvider // tp may be nil if initialization failed
}

func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.StateDir == "" {
		return nil, errors.Errorf("state directory must be provided")
	}
	v := &Verifier{cfg: cfg}

	tp, err := v.loadTrustProvider() // initialization fails on expired root/timestamp

	if err == nil {
		tm, st, err := tp.TrustedRoot(context.TODO())
		if err != nil {
			return nil, err
		}
		if st.Error != nil {
			log.Printf("trusted root warning: %+v", st.Error)
		}
		log.Printf("tm: %+v", tm)
	}
	return v, nil
}

func (v *Verifier) loadTrustProvider() (*roots.TrustProvider, error) {
	var tpCache *roots.TrustProvider
	_, err, _ := v.sf.Do("", func() (any, error) {
		if v.tp != nil {
			tpCache = v.tp
			return nil, nil
		}
		tpCache, err := roots.NewTrustProvider(roots.SigstoreRootsConfig{
			CachePath:      filepath.Join(v.cfg.StateDir, "tuf"),
			UpdateInterval: v.cfg.UpdateInterval,
			RequireOnline:  v.cfg.RquireOnline,
		})
		if err != nil {
			return nil, err
		}
		v.tp = tpCache
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return tpCache, nil
}
