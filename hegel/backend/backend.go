package backend

import (
	"context"
	"errors"
	"fmt"

	"github.com/jacobweinstock/tink-stack/hegel/backend/flatfile"
	"github.com/jacobweinstock/tink-stack/hegel/backend/kubernetes"
	"github.com/jacobweinstock/tink-stack/hegel/frontend/ec2"
	"github.com/jacobweinstock/tink-stack/hegel/frontend/hack"
	"github.com/jacobweinstock/tink-stack/hegel/healthcheck"
)

// ErrMissingBackendConfig indicates New was called without a backend configuration.
var ErrMissingBackendConfig = errors.New("no backend configuration specified in options")

// ErrMultipleBackends indicates the backend Options contains more than one backend configuration.
var ErrMultipleBackends = errors.New("only one backend option can be specified")

// Client is an abstraction for all frontend clients. Each backend implementation should satisfy
// this interface.
type Client interface {
	ec2.Client
	hack.Client
	healthcheck.Client
}

// New creates a backend instance for the configuration specified by opts. Consumers may only
// supply 1 backend configuration. If no backend configuration is supplied, it returns
// ErrMissingBackendConfig.
func New(ctx context.Context, opts Options) (Client, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	switch {
	case opts.Flatfile != nil:
		return flatfile.FromYAMLFile(opts.Flatfile.Path)

	case opts.Kubernetes != nil:
		kubeclient, err := kubernetes.NewBackend(ctx, kubernetes.Config{
			Kubeconfig:       opts.Kubernetes.Kubeconfig,
			APIServerAddress: opts.Kubernetes.APIServerAddress,
			Namespace:        opts.Kubernetes.Namespace,
		})
		if err != nil {
			return nil, fmt.Errorf("kubernetes client: %v", err)
		}
		if ok := kubeclient.WaitForCacheSync(ctx); !ok {
			return nil, errors.New("failed to sync kubernetes cache")
		}

		return kubeclient, nil

	default:
		return nil, ErrMissingBackendConfig
	}
}

// Options contains all options for all backend implementations. Only one backend option can be
// specified at a time.
type Options struct {
	Flatfile   *Flatfile
	Kubernetes *kubernetes.Config
}

func (o Options) validate() error {
	var count int

	if o.Flatfile != nil {
		count++
	}

	if o.Kubernetes != nil {
		count++
	}

	if count > 1 {
		return ErrMultipleBackends
	}

	return nil
}

// FlatFileOptions is the configuration for a flatfile backend.
type Flatfile struct {
	// Path is a path to a YAML file containing a list of flatfile instances.
	Path string
}
