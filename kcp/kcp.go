package kcp

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	shared "github.com/jacobweinstock/plugin-shared"
	"github.com/jacobweinstock/plugin-shared/protobuf"
)

type Plugin struct {
	Context    context.Context
	DataDir    string
	PluginFile string
}

// pluginMap is the map of plugins we can dispense.
var pluginMap = map[string]plugin.Plugin{
	"kcp": &shared.KCPGRPCPlugin{},
}

func (k Plugin) Start(ctx context.Context) error {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "kcp plugin",
		Output: os.Stdout,
		Level:  hclog.Info,
	})
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  shared.HandshakeConfig,
		Plugins:          pluginMap,
		Cmd:              exec.Command("/home/tink/repos/jacobweinstock/kcp-plugin/kcp"),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Logger:           logger,
		Managed:          true,
		SyncStdout:       os.Stdout,
		SyncStderr:       os.Stderr,
		StartTimeout:     time.Minute,
	})
	defer client.Kill()

	// Connect via RPC
	rpcClient, err := client.Client()
	if err != nil {
		return err
	}

	// Request the plugin
	raw, err := rpcClient.Dispense("kcp")
	if err != nil {
		return err
	}

	// We should have a KV store now! This feels like a normal interface
	// implementation but is in fact over an RPC connection.
	kv, ok := raw.(*shared.GRPCClient)
	if !ok {
		return fmt.Errorf("unexpected type from plugin: %T", raw)
	}

	done := make(chan error, 1)
	go func() {
		_, err := kv.Start(ctx, &protobuf.Empty{})
		log.Println("in Do: error 5", err)
		done <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return fmt.Errorf("error with kcp: %w", err)
	}
}
