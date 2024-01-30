package flatfile

import (
	"context"
	"errors"

	"github.com/jacobweinstock/tink-stack/hegel/frontend/hack"
)

// GetHackInstance exists to satisfy the hack.Client interface. It is not implemented.
func (b *Backend) GetHackInstance(context.Context, string) (hack.Instance, error) {
	return hack.Instance{}, errors.New("unsupported")
}
