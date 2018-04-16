// +build !darwin

package main

import (
	"syscall"
)

func madviseSequential(b []byte) error {
	return syscall.Madvise(b, syscall.MADV_SEQUENTIAL)
}
