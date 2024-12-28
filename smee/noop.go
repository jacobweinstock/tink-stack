package smee

import (
	"context"
	"errors"
	"net"

	"github.com/jacobweinstock/tink-stack/data"
)

var errAlways = errors.New("noop backend always returns an error")

type noop struct{}

func (n noop) GetByMac(context.Context, net.HardwareAddr) (*data.DHCP, *data.Netboot, error) {
	return nil, nil, errAlways
}

func (n noop) GetByIP(context.Context, net.IP) (*data.DHCP, *data.Netboot, error) {
	return nil, nil, errAlways
}
