//go:build linux

package decisions

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func checkPeerUID(conn net.Conn, expectedUID int) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("connection is not a unix socket")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return err
	}

	var ucred *unix.Ucred
	var sockErr error
	if ctrlErr := rawConn.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); ctrlErr != nil {
		return ctrlErr
	}
	if sockErr != nil {
		return sockErr
	}

	if int(ucred.Uid) != expectedUID {
		return fmt.Errorf("peer uid %d does not match configured scorer uid %d", ucred.Uid, expectedUID)
	}
	return nil
}
