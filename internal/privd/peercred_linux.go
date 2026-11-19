package privd

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerCred reads the connecting process's credentials from the kernel (SO_PEERCRED).
func peerCred(c net.Conn) (*peer, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a UNIX socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) //nolint:gosec // fd fits int
	}); err != nil {
		return nil, err
	}
	if credErr != nil {
		return nil, credErr
	}
	return &peer{uid: cred.Uid, pid: cred.Pid}, nil
}
