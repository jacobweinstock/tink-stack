package cmd

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/jacobweinstock/tink-stack/internal/tink/grpcserver"
	"github.com/jacobweinstock/tink-stack/internal/tink/httpserver"
	"github.com/jacobweinstock/tink-stack/internal/tink/server"
)

type TinkServer struct {
	GRPCAuthority string
	HTTPAuthority string

	KubeconfigPath string
	KubeAPI        string
	KubeNamespace  string

	Logger logr.Logger
}

func (t TinkServer) Start(ctx context.Context) error {
	kube, err := server.NewKubeBackedServer(
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
		t.Logger.Error(err, "")
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
