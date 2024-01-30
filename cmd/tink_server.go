package cmd

import (
	"context"
)

type TinkServer struct{}

func (t TinkServer) Start(ctx context.Context) error {
	return nil
}
