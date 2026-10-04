//go:build !linux

package decisions

import (
	"fmt"
	"net"
)

func checkPeerUID(net.Conn, int) error {
	return fmt.Errorf("decision feed peer verification is supported only on Linux")
}
