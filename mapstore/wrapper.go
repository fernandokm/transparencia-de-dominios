package mapstore

import (
	"bytes"
	"fmt"
	"sync"
)

const (
	leafPrefix byte = 0
	nodePrefix byte = 1
)

// KeyInfo stores information about a key
type KeyInfo struct {
	Key        []byte
	ShouldSave bool
}

// wrapper converts a lazyledger/smt.MapStore into a dt-compatible MapStore
type wrapper struct {
	base        Base
	hashSize    int
	placeholder []byte

	// locked by m
	newEntries    []KeyInfo
	newEntriesMap map[string]int

	m          sync.Mutex
	mTraversal sync.RWMutex
}

// Wrap creates a new mapstore.Interface from the specified lazyledger/smt.MapStore.
func Wrap(hashSize int, base Base) Interface {
	return &wrapper{
		base:     base,
		hashSize: hashSize,

		newEntries:    make([]KeyInfo, 0),
		newEntriesMap: make(map[string]int),

		placeholder: bytes.Repeat([]byte{0}, hashSize),
	}
}

// Get gets the value for a key.
func (ms *wrapper) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, ms.placeholder) {
		return []byte{}, nil
	}

	return ms.base.Get(key)
}

// Set updates the in-memory value for a key.
func (ms *wrapper) Set(key []byte, value []byte) error {
	if bytes.Equal(key, ms.placeholder) {
		return ErrCannotSetPlaceholder
	}

	if err := ms.base.Set(key, value); err != nil {
		return err
	}
	ks := string(key)

	ms.m.Lock()
	defer ms.m.Unlock()
	ms.newEntriesMap[ks] = len(ms.newEntries)
	ms.newEntries = append(ms.newEntries, KeyInfo{key, false})
	return nil
}

// Delete deletes a key.
func (ms *wrapper) Delete(key []byte) error {
	return ms.base.Delete(key)
}

// Size returns the number of nodes in this map store.
func (ms *wrapper) Size() int {
	return ms.base.Size()
}

// HashSize returns the hash size used in this map.
func (ms *wrapper) HashSize() int {
	return ms.hashSize
}

// SaveNodesForRoot saves all nodes for the specified root to disk
// and erases any nodes that were inserted prior to the root.
func (ms *wrapper) SaveNodesForRoot(root []byte) error {
	ms.m.Lock()
	defer ms.m.Unlock()
	if err := ms.markToSave(root); err != nil {
		return err
	}
	return ms.pruneUntil(root)
}

// TraverseNodes traverses the nodes starting from the root in DFS order.
//
// The handlers may return ErrSkipBranch in order to skip all descendants of the
// current node. See the documentation of ErrSkipBranch for more information.
//
// This function MAY error if the root or any of its children are pruned
// during the traversal.
func (ms *wrapper) TraverseNodes(root []byte, nodeFn NodeHandler, leafFn LeafHandler) error {
	ms.mTraversal.RLock()
	defer ms.mTraversal.RUnlock()

	data, err := ms.Get(root)
	if err != nil {
		return fmt.Errorf("no node for hash 0x%X", root)
	}

	if len(data) == 0 { // empty leaf
		if leafFn != nil {
			if err := leafFn(ms.placeholder, root, data); err != ErrSkipBranch {
				return err
			}
		}
		return nil
	}

	if data[0] == nodePrefix {
		if len(data) != 1+2*ms.hashSize {
			return fmt.Errorf("invalid node data: hash=%X, data=%X (expected length=1+2*hashSize=%d, got length=%d)", root, data, 1+2*ms.hashSize, len(data))
		}
		leftHash := data[1 : 1+ms.hashSize]
		rightHash := data[1+ms.hashSize:]
		if nodeFn != nil {
			if err := nodeFn(root, leftHash, rightHash); err == ErrSkipBranch {
				return nil
			} else if err != nil {
				return err
			}
		}
		if err := ms.TraverseNodes(leftHash, nodeFn, leafFn); err != nil {
			return err
		}
		if err := ms.TraverseNodes(rightHash, nodeFn, leafFn); err != nil {
			return err
		}
		return nil
	} else if data[0] == leafPrefix { // leaf
		if len(data) != 1+2*ms.hashSize {
			return fmt.Errorf("invalid leaf data: leafHash=%X, valueHash=%X (expected length=1+2*hashSize=%d, got length=%d)", root, data, 1+2*ms.hashSize, len(data))
		}
		if leafFn != nil {
			leafPath := data[1 : 1+ms.hashSize]
			valueHash := data[1+ms.hashSize:]
			if err := leafFn(leafPath, root, valueHash); err != ErrSkipBranch {
				return err
			}
			return nil // ignore ErrSkipBranch errors (no-ops in the leaf handler)
		}
		return nil
	}

	return fmt.Errorf("invalid node prefix: 0x%X for node 0x%X (expected 0x%X or 0x%X)", data[0], data, leafPrefix, nodePrefix)
}

func (ms *wrapper) markToSave(root []byte) error {
	mark := func(hash []byte) error {
		if len(hash) == 0 || bytes.Equal(hash, ms.placeholder) { // empty leaf value or hash
			return ErrSkipBranch // Shouldn't be needed, but also shouldn't matter
		}
		entry, ok := ms.newEntriesMap[string(hash)]
		if !ok {
			return ErrSkipBranch
		}
		ms.newEntries[entry].ShouldSave = true
		return nil
	}

	return ms.TraverseNodes(root, func(hash, left, right []byte) error { // nodeFn
		return mark(hash)
	}, func(leafPath, hash, valueHash []byte) error { // leafFn
		if err := mark(hash); err != nil {
			return err
		}
		return mark(valueHash)
	})
}

func (ms *wrapper) pruneUntil(root []byte) error {
	// Prevent node traversal during pruning.
	ms.mTraversal.Lock()
	defer ms.mTraversal.Unlock()

	rootIndex := len(ms.newEntries)
	for i, entry := range ms.newEntries {
		delete(ms.newEntriesMap, string(entry.Key))

		if bytes.Equal(entry.Key, root) {
			rootIndex = i
			break
		}
	}

	if rootIndex == len(ms.newEntries) {
		fmt.Printf("Warning: root not found in pruneUntil(). Pruning all nodes.\n")
		rootIndex--
	}

	toProcess := ms.newEntries[:rootIndex+1]
	newEntries := make([]KeyInfo, len(ms.newEntries)-rootIndex-1)
	copy(newEntries, ms.newEntries[rootIndex+1:])

	if err := ms.base.ProcessKeys(toProcess); err != nil {
		// rebuild map
		for i := 0; i < len(toProcess); i++ {
			entry := &toProcess[i]
			ms.newEntriesMap[string(entry.Key)] = i
		}

		return fmt.Errorf("ms.pruneUntil: %w", err)
	}

	ms.newEntries = newEntries
	// reindex
	for i, entry := range ms.newEntries {
		ms.newEntriesMap[string(entry.Key)] = i
	}
	return nil
}

func (ms *wrapper) Placeholder() []byte {
	cpy := make([]byte, len(ms.placeholder))
	copy(cpy, ms.placeholder)
	return cpy
}
