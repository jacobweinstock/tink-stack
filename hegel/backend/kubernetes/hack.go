package kubernetes

import (
	"context"
	"encoding/json"

	tinkv1 "github.com/jacobweinstock/tink-stack/api/v1alpha1"
	"github.com/jacobweinstock/tink-stack/hegel/frontend/hack"
)

func (b *Backend) GetHackInstance(ctx context.Context, ip string) (hack.Instance, error) {
	hw, err := b.retrieveByIP(ctx, ip)
	if err != nil {
		return hack.Instance{}, err
	}

	return toHackInstance(hw)
}

// toHackInstance converts a Tinkerbell Hardware resource to a hack.Instance by marshalling and
// unmarshalling. This works because the Hardware resource has historical roots that align with
// the hack.Instance struct that is derived from the rootio action. See the hack frontend for more
// details.
func toHackInstance(hw tinkv1.Hardware) (hack.Instance, error) {
	marshalled, err := json.Marshal(hw.Spec)
	if err != nil {
		return hack.Instance{}, err
	}

	var i hack.Instance
	if err := json.Unmarshal(marshalled, &i); err != nil {
		return hack.Instance{}, err
	}

	return i, nil
}
