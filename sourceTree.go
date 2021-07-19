package dt

import (
	"fmt"
	"sync"

	"github.com/google/certificate-transparency-go/logid"
)

// A SourceTree lists the source logs tracked by a DomainMap.
type SourceTree struct {
	*merkleTree

	// locked by m
	leaves []logid.LogID

	m sync.RWMutex
}

// NewSourceTree creates a new source tree
func NewSourceTree() *SourceTree {
	return &SourceTree{
		merkleTree: newMerkleTree(),
	}
}

// GetEntries returns the entries in the specified interval, inclusive.
func (st *SourceTree) GetEntries(start, end uint64) ([]logid.LogID, error) {
	if start > end {
		return nil, fmt.Errorf("invalid interval: start (%d) > end (%d)", start, end)
	}

	st.m.RLock()
	defer st.m.RUnlock()

	if end >= uint64(len(st.leaves)) {
		return nil, fmt.Errorf("invalid interval: end (%d) >= tree size (%d)", end, len(st.leaves))
	}
	entries := st.leaves[start : end+1]
	cp := make([]logid.LogID, len(entries))
	copy(cp, entries)
	return cp, nil
}

// GetEntryAndProof returns the specified entry and its proof.
func (st *SourceTree) GetEntryAndProof(treeSize, leafIndex uint64) (logid.LogID, [][]byte, error) {
	// Note: we can technically be more efficient by getting the entries directly
	// This function clones the logID twice, once in st.GetEntries, and once on the final return statement
	entries, err := st.GetEntries(leafIndex, leafIndex)
	if err != nil {
		return logid.LogID{}, nil, err
	}

	proof, err := st.merkleTree.GetAuditProof(treeSize, leafIndex)
	if err != nil {
		return logid.LogID{}, nil, err
	}
	return entries[0], proof, nil
}

// AddEntry adds an entry to the tree and returns its current leaf count.
func (st *SourceTree) AddEntry(entry logid.LogID) uint64 {
	st.m.Lock()
	defer st.m.Unlock()

	st.merkleTree.addLeaf(entry[:])
	st.leaves = append(st.leaves, entry)
	return uint64(len(st.leaves))
}
