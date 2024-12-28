package cmd

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/jacobweinstock/tink-stack/api/v1alpha1"
	"github.com/jacobweinstock/tink-stack/backend/file"
	"github.com/jacobweinstock/tink-stack/backend/kube"
	"github.com/jacobweinstock/tink-stack/backend/noop"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/scale/scheme"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
)

type Kube struct {
	// ConfigFilePath is the path to a kubernetes config file (kubeconfig).
	ConfigFilePath string
	// APIURL is the Kubernetes API URL.
	APIURL string
	// Namespace is an override for the Namespace the kubernetes client will watch.
	// The default is the Namespace the pod is running in.
	Namespace string
	Enabled   bool
}
type File struct {
	// FilePath is the path to a JSON FilePath containing hardware data.
	FilePath string
	Enabled  bool
}

type Noop struct {
	Enabled bool
}

func (n *Noop) backend() *noop.Backend {
	return &noop.Backend{}
}

func (k *Kube) getClient() (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = k.ConfigFilePath

	overrides := &clientcmd.ConfigOverrides{
		ClusterInfo: clientcmdapi.Cluster{
			Server: k.APIURL,
		},
		Context: clientcmdapi.Context{
			Namespace: k.Namespace,
		},
	}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)

	return loader.ClientConfig()
}

func (k *Kube) backend(ctx context.Context) (*kube.Backend, error) {
	config, err := k.getClient()
	if err != nil {
		return nil, err
	}

	rs := runtime.NewScheme()

	if err := scheme.AddToScheme(rs); err != nil {
		return nil, err
	}

	if err := v1alpha1.AddToScheme(rs); err != nil {
		return nil, err
	}

	conf := func(opts *cluster.Options) {
		opts.Scheme = rs
		if k.Namespace != "" {
			opts.Cache.DefaultNamespaces = map[string]cache.Config{k.Namespace: {}}
		}
	}

	kb, err := kube.NewBackend(config, conf)
	if err != nil {
		return nil, err
	}

	go func() {
		err = kb.Start(ctx)
		if err != nil {
			panic(err)
		}
	}()

	return kb, nil
}

func (s *File) backend(ctx context.Context, logger logr.Logger) (*file.Watcher, error) {
	f, err := file.NewWatcher(logger, s.FilePath)
	if err != nil {
		return nil, err
	}

	go f.Start(ctx)

	return f, nil
}
