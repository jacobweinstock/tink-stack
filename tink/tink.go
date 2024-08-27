package tink

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/jacobweinstock/tink-stack/tink/controller"
	"github.com/jacobweinstock/tink-stack/tink/grpcserver"
	"github.com/jacobweinstock/tink-stack/tink/httpserver"
	tserver "github.com/jacobweinstock/tink-stack/tink/server"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

type Controller struct {
	Logger               logr.Logger
	Kubeconfig           string
	EnableLeaderElection bool
	MetricsAddr          string
	ProbeAddr            string
}

type Server struct {
	GRPCAuthority string
	HTTPAuthority string

	KubeconfigPath string
	KubeAPI        string
	KubeNamespace  string

	Logger logr.Logger
}

func (t Controller) Start(ctx context.Context) error {
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

func (t Server) Start(ctx context.Context) error {
	kube, err := tserver.NewKubeBackedServer(
		t.Logger,
		t.KubeconfigPath,
		t.KubeAPI,
		t.KubeNamespace,
	)
	if err != nil {
		return err
	}
	errCh := make(chan error, 2)
	// Start the gRPC server in the background
	addr, err := grpcserver.SetupGRPC(
		ctx,
		kube,
		t.GRPCAuthority,
		errCh,
	)
	if err != nil {
		return err
	}
	t.Logger.Info("started Tink Server listener", "address", addr)
	httpserver.SetupHTTP(ctx, t.Logger, t.HTTPAuthority, errCh)
	select {
	case err := <-errCh:
		t.Logger.Error(err, "tink server error")
	case <-ctx.Done():
		t.Logger.Info("signal received, stopping servers")
	}

	// wait for grpc server to shutdown
	err = <-errCh
	if err != nil {
		return err
	}
	err = <-errCh
	if err != nil {
		return err
	}
	return nil
}
