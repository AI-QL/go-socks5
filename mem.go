package socks5

import (
	"context"
)

// MemAllocation is an interface for managing memory allocation and deallocation.
// It provides methods to allocate and free memory.
type MemAllocation interface {
	// Alloc allocates a slice of bytes of the specified size.
	// ctx can be used to control the allocation process, such as for timeouts or cancellations.
	Alloc(ctx context.Context, size int) []byte

	// Free deallocates the provided slice of bytes.
	// ctx can be used to control the deallocation process, such as for timeouts or cancellations.
	Free(ctx context.Context, bs []byte)
}

// MemMgr is an interface for managing memory allocators.
// It provides a method to create a new MemAllocation instance.
type MemMgr interface {
	// Create creates a new MemAllocation instance.
	// ctx can be used to control the creation process, such as for timeouts or cancellations.
	Create(ctx context.Context) MemAllocation
}

// Mem is a simple implementation of the MemAllocation interface.
// It uses the built-in `make` function to allocate memory and does nothing for deallocation.
type Mem struct{}

// Alloc allocates a slice of bytes of the specified size using the built-in `make` function.
// It does not perform any special handling for the context.
func (m *Mem) Alloc(ctx context.Context, size int) []byte {
	return make([]byte, size)
}

// Free is a no-op function for deallocating memory.
// It does not perform any actual deallocation and ignores the provided context.
func (m *Mem) Free(ctx context.Context, bs []byte) {
	// No-op
}