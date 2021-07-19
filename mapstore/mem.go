package mapstore

import (
	"bytes"
	"fmt"
	"sync"
)

// A MapStore imlpements lazyledger/smt.MapStore
type memMapStore struct {
	mem map[string][]byte

	m sync.RWMutex
}

// NewMem creates a new DDMapStore with the given hash size
func NewMem(hashSize int) Interface {
	return Wrap(hashSize, &memMapStore{
		mem: make(map[string][]byte),
	})
}

// Get gets the value for a key.
func (ms *memMapStore) Get(key []byte) ([]byte, error) {
	v, err := func() ([]byte, error) {
		ms.m.RLock()
		defer ms.m.RUnlock()

		v, ok := ms.mem[string(key)]
		if !ok {
			return nil, fmt.Errorf("no such key: %x", key)
		}
		return v, nil
	}()
	if err != nil {
		return nil, err
	}

	vCopy := make([]byte, len(v))
	copy(vCopy, v)
	return vCopy, nil
}

// Set updates the in-memory value for a key.
func (ms *memMapStore) Set(key []byte, value []byte) error {
	ms.m.Lock()
	defer ms.m.Unlock()
	ks := string(key)
	if oldVal, ok := ms.mem[ks]; ok {
		if bytes.Equal(value, oldVal) {
			return nil
		} else {
			return fmt.Errorf("Set operation on existing keys nto supported (key=%x)", key)
		}
	}
	ms.mem[ks] = value
	return nil
}

// Delete deletes a key.
func (ms *memMapStore) Delete(key []byte) error {
	return ErrDeleteNotSupported
}

// Size returns the number of nodes in this map store.
func (ms *memMapStore) Size() int {
	ms.m.RLock()
	defer ms.m.RUnlock()
	return len(ms.mem)
}

// ProcessKeys saves and/or deletes the listed keys
func (ms *memMapStore) ProcessKeys(keys []KeyInfo) error {
	ms.m.Lock()
	defer ms.m.Unlock()
	for _, ki := range keys {
		if !ki.ShouldSave {
			delete(ms.mem, string(ki.Key))
		}
	}
	return nil
}
