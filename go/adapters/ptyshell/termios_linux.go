//go:build linux

package ptyshell

import "golang.org/x/sys/unix"

const (
	ioctlGetTermios = unix.TCGETS
	ioctlSetTermios = unix.TCSETS
)
