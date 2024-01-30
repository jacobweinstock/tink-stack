package cmd

import "context"

type Rufio struct{}

func (r Rufio) Start(ctx context.Context) error {
	return nil
}
