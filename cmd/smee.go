package cmd

import "context"

type Smee struct{}

func (s Smee) Start(ctx context.Context) error {
	return nil
}
