package util

import (
	"crypto/sha256"
	"fmt"
	"hash"
)

// A TruncatedHash is a truncated version of longer hashes.
// Used for testing purposes
type TruncatedHash struct {
	base hash.Hash
	size int
}

// Write adds more data to the running hash.
// It never returns an error.
func (sh *TruncatedHash) Write(p []byte) (n int, err error) {
	return sh.base.Write(p)
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (sh *TruncatedHash) Sum(b []byte) []byte {
	tmp := sh.base.Sum(nil)
	return append(b, tmp[:sh.size]...)
}

// Reset resets the Hash to its initial state.
func (sh *TruncatedHash) Reset() {
	sh.base.Reset()
}

// Size returns the number of bytes Sum will return.
func (sh *TruncatedHash) Size() int {
	return sh.size
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (sh *TruncatedHash) BlockSize() int {
	return sh.base.BlockSize()
}

// TruncateHash creates a new TruncatedHash from the base hash with the given size.
// After calling TruncateHash(base, size), base should no longer be used
// by external code.
func TruncateHash(base hash.Hash, size int) hash.Hash {
	if size > base.Size() {
		panic(fmt.Errorf("size too large: %d", size))
	}
	return &TruncatedHash{
		base: base,
		size: size,
	}
}

// NewTruncatedSHA256 creates a new TruncatedHash using sha256 as its base hash.
// Equivalent to calling TruncateHash(sha256.New(), size).
func NewTruncatedSHA256(size int) hash.Hash {
	return TruncateHash(sha256.New(), size)
}
