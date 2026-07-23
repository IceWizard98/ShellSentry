//go:build darwin

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process on the other end of a unix socket via
// LOCAL_PEERCRED (macOS/BSD equivalent of SO_PEERCRED), so otpd can bind a
// request to the connecting user's identity.
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var xu *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		xu, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return xu.Uid, nil
}
