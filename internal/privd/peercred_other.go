//go:build !linux

package privd

import (
	"errors"
	"net"
)

// peerCred is only implemented on Linux. Without it every connection is refused, so the
// helper fails closed elsewhere.
func peerCred(net.Conn) (*peer, error) {
	return nil, errors.New("peer credentials are only supported on Linux")
}
