package hegel

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	"github.com/jacobweinstock/tink-stack/hegel/backend"
	"github.com/jacobweinstock/tink-stack/hegel/backend/kubernetes"
	"github.com/jacobweinstock/tink-stack/hegel/frontend/ec2"
	"github.com/jacobweinstock/tink-stack/hegel/frontend/hack"
	"github.com/jacobweinstock/tink-stack/hegel/healthcheck"
	hegelhttp "github.com/jacobweinstock/tink-stack/hegel/http"
	hegellogger "github.com/jacobweinstock/tink-stack/hegel/logger"
	"github.com/jacobweinstock/tink-stack/hegel/metrics"
	"github.com/jacobweinstock/tink-stack/hegel/xff"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

type Server struct {
	TrustedProxies       string
	HTTPAddr             string
	Backend              string
	KubernetesAPIServer  string
	KubernetesKubeconfig string
	KubernetesNamespace  string
	FlatfilePath         string
	Debug                bool
	Logger               logr.Logger

	// Hidden CLI flags.
	HegelAPI bool
}

func (h Server) Start(ctx context.Context) error {
	if h.Debug {
		gin.SetMode(gin.ReleaseMode)
	}
	be, err := backend.New(ctx, h.toBackendOptions())
	if err != nil {
		return errors.Errorf("initialize backend: %v", err)
	}
	xffmw, err := xff.MiddlewareFromUnparsed(h.TrustedProxies)
	if err != nil {
		return err
	}
	registry := prometheus.NewRegistry()

	router := gin.New()
	router.Use(
		metrics.InstrumentRequestCount(registry),
		metrics.InstrumentRequestDuration(registry),
		gin.Recovery(),
		hegellogger.Middleware(h.Logger),
		xffmw,
	)

	metrics.Configure(router, registry)
	healthcheck.Configure(router, be)

	// TODO(chrisdoherty4) Handle multiple frontends.
	fe := ec2.New(be)
	fe.Configure(router)

	hack.Configure(router, be)

	return hegelhttp.Serve(ctx, h.Logger, h.HTTPAddr, router)
}

func (h Server) toBackendOptions() backend.Options {
	var backndOpts backend.Options
	switch h.Backend {
	case "flatfile":
		backndOpts = backend.Options{
			Flatfile: &backend.Flatfile{
				Path: h.FlatfilePath,
			},
		}
	case "kubernetes":
		backndOpts = backend.Options{
			Kubernetes: &kubernetes.Config{},
		}
		if h.KubernetesAPIServer != "" {
			backndOpts.Kubernetes.APIServerAddress = "https://kubernetes.default.svc"
		}
		if h.KubernetesKubeconfig != "" {
			backndOpts.Kubernetes.Kubeconfig = h.KubernetesKubeconfig
		}
		if h.KubernetesNamespace != "" {
			backndOpts.Kubernetes.Namespace = h.KubernetesNamespace
		}
		backndOpts.Kubernetes.Logger = h.Logger
	}
	return backndOpts
}
