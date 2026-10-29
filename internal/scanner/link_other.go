//go:build !linux

package scanner

import (
	"errors"
	"net"
	"runtime"
)

func openLink(net.Interface) (link, error) {
	return nil, errors.New("raw-socket discovery is only implemented on Linux (" + runtime.GOOS + " is not supported; use the Docker image or -demo)")
}
