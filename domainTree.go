package dt

import (
	"fmt"
	"sort"
	"sync"

	"github.com/fernandokm/transparencia-de-dominios/util"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

// A DomainTreeRoot stores information about a domain tree.
type DomainTreeRoot struct {
	DomainTreeSize     uint64
	DomainTreeRootHash ct.SHA256Hash
}

// A DomainTreeEntry points to a certificate in a CT log.
// The LogIndex refers to the index of the CT log in the domain map's source tree.
type DomainTreeEntry struct {
	LogIndex         uint64
	CertificateIndex uint64
}

type certAndDTIndex struct {
	CertificateIndex uint64
	DomainTreeIndex  uint64
}

// A DomainTree stores certificates for a given domain,
// similarly to a CT log.
type DomainTree struct {
	DomainName string

	*merkleTree

	// locked by m
	leaves       []DomainTreeEntry
	leavesPerLog [][]certAndDTIndex

	m sync.RWMutex
}

// NewDomainTree creates a new domain tree
func NewDomainTree(domain string) (*DomainTree, error) {
	domain, err := util.NormalizeDomainName(domain)
	if err != nil {
		return nil, err
	}
	dtree := &DomainTree{
		DomainName: domain,
		merkleTree: newMerkleTree(),
	}
	return dtree, nil
}

// GetRoot retrieves the DomainTreeRoot with the specified size.
func (dtree *DomainTree) GetRoot(treeSize uint64) (*DomainTreeRoot, error) {
	rootHash, err := dtree.merkleTree.GetRoot(treeSize)
	if err != nil {
		return nil, err
	}

	var root DomainTreeRoot
	root.DomainTreeSize = treeSize
	copy(root.DomainTreeRootHash[:], rootHash[:])
	return &root, nil
}

// GetEntries returns the entries in the specified interval, inclusive.
func (dtree *DomainTree) GetEntries(start, end uint64) ([]DomainTreeEntry, error) {
	if start > end {
		return nil, fmt.Errorf("invalid interval: start (%d) > end (%d)", start, end)
	}

	dtree.m.RLock()
	defer dtree.m.RUnlock()

	if end >= uint64(len(dtree.leaves)) {
		return nil, fmt.Errorf("invalid interval: end (%d) >= tree size (%d)", end, len(dtree.leaves))
	}
	entries := dtree.leaves[start : end+1]
	cp := make([]DomainTreeEntry, len(entries))
	copy(cp, entries)
	return cp, nil
}

// GetEntryAndProof returns the specified entry and its proof.
func (dtree *DomainTree) GetEntryAndProof(treeSize, leafIndex uint64) (DomainTreeEntry, [][]byte, error) {
	entries, err := dtree.GetEntries(leafIndex, leafIndex)
	if err != nil {
		return DomainTreeEntry{}, nil, err
	}

	proof, err := dtree.GetAuditProof(treeSize, leafIndex)
	if err != nil {
		return DomainTreeEntry{}, nil, err
	}
	return entries[0], proof, nil
}

func (dtree *DomainTree) growLeavesPerLog(minSize uint64) {
	for uint64(len(dtree.leavesPerLog)) < minSize {
		dtree.leavesPerLog = append(dtree.leavesPerLog, nil)
	}
}

// AddEntry adds an entry to the tree and returns its current leaf count.
func (dtree *DomainTree) AddEntry(entry DomainTreeEntry) uint64 {
	leafData, err := tls.Marshal(entry)
	if err != nil {
		panic(fmt.Errorf("unexpected error marshaling entry: %w", err))
	}

	dtree.m.Lock()
	defer dtree.m.Unlock()

	dtree.tree.AddLeaf(leafData)
	dtree.leaves = append(dtree.leaves, entry)
	dtree.growLeavesPerLog(entry.LogIndex + 1)
	dtree.leavesPerLog[entry.LogIndex] = append(dtree.leavesPerLog[entry.LogIndex], certAndDTIndex{
		CertificateIndex: entry.CertificateIndex,
		DomainTreeIndex:  uint64(len(dtree.leaves)) - 1,
	})
	return uint64(len(dtree.leaves))
}

// EntryToDomainTreeIndex returns the index of a DomainTreeEntry in this domain tree.
//
// Returns an error if the specified entry could not be found in this domain tree.
func (dtree *DomainTree) EntryToDomainTreeIndex(entry DomainTreeEntry) (uint64, error) {
	dtree.m.RLock()
	defer dtree.m.RUnlock()

	dtree.growLeavesPerLog(entry.LogIndex + 1)
	leaves := dtree.leavesPerLog[entry.LogIndex]
	i := sort.Search(len(leaves), func(i int) bool { return leaves[i].CertificateIndex >= entry.CertificateIndex })
	if leaves[i].CertificateIndex != entry.CertificateIndex {
		return 0, fmt.Errorf("no entry with log index %d found", entry.LogIndex)
	}

	return leaves[i].DomainTreeIndex, nil
}
