package cmd

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	controller "github.com/jacobweinstock/tink-stack/internal/controller/tink"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

type TinkController struct {
	Logger               logr.Logger
	Kubeconfig           string
	EnableLeaderElection bool
	MetricsAddr          string
	ProbeAddr            string
}

func (t TinkController) Start(ctx context.Context) error {
	t.Logger.Info("Starting controller version ")

	ccfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: t.Kubeconfig},
		nil)
	//&clientcmd.ConfigOverrides{ClusterInfo: clientcmdapi.Cluster{Server: ""}})

	cfg, err := ccfg.ClientConfig()
	if err != nil {
		return err
	}

	namespace, _, err := ccfg.Namespace()
	if err != nil {
		return err
	}
	ctrl.SetLogger(t.Logger)
	klog.SetLogger(t.Logger)

	options := ctrl.Options{
		Logger:                  t.Logger,
		LeaderElection:          t.EnableLeaderElection,
		LeaderElectionID:        "tink.tinkerbell.org",
		LeaderElectionNamespace: namespace,
		Metrics: server.Options{
			BindAddress: t.MetricsAddr,
		},
		HealthProbeBindAddress: t.ProbeAddr,
	}

	mgr, err := controller.NewManager(cfg, options)
	if err != nil {
		return fmt.Errorf("controller manager: %w", err)
	}
	mgr.GetLogger().Info("Starting controller manager", "version", "v0.0.1")

	return mgr.Start(ctx)
}
