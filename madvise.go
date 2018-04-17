// +build !darwin

package pto3trace

import (
	"syscall"
)

func MadviseSequential(b []byte) error {
	return syscall.Madvise(b, syscall.MADV_SEQUENTIAL)
}
