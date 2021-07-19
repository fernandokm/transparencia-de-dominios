package dt

import (
	"fmt"
	"sync"

	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
)

var emptyDenseTreeRoot = rfc6962.DefaultHasher.EmptyRoot()

// merkleTree is a wrapper around merkle.InMemoryMerkleTree
// that ensures all operations are thread-safe and
// converts return values to the types used in this package
//
// Note: even though this type is unexported, its exported methods are part of
// the package's public interface, because merkleTree is embedded in the
// exported structs DomainTree and SourceTree.
type merkleTree struct {
	tree merkle.InMemoryMerkleTree

	// mTree can't be sync.RWMutex because any operations involving node hashes on the merkle tree
	// may mutate the tree (lazy hash evaluation)
	m sync.Mutex
}

func newMerkleTree() *merkleTree {
	return &merkleTree{
		tree: *merkle.NewInMemoryMerkleTree(rfc6962.DefaultHasher),
	}
}

// GetRoot returns the tree root at the specified size
func (t *merkleTree) GetRoot(treeSize uint64) ([]byte, error) {
	t.m.Lock()
	defer t.m.Unlock()

	latestTreeSize := uint64(t.tree.LeafCount())
	if treeSize > latestTreeSize {
		return nil, fmt.Errorf("invalid treeSize (%d): greater than latest tree size (%d)", treeSize, latestTreeSize)
	}

	return t.tree.RootAtSnapshot(int64(treeSize)).Hash(), nil
}

// getRawProof returns a raw version of the proof returned by GetProof.
// Used to limit how long the lock is held (GetProof does not lock outside of getRawProof).
func (t *merkleTree) getRawProof(treeSize, leafIndex uint64) ([]merkle.TreeEntryDescriptor, error) {
	if leafIndex >= treeSize {
		return nil, fmt.Errorf("leafIndex too large: leafIndex (%d) >= treeSize (%d)", leafIndex, treeSize)
	}

	t.m.Lock()
	defer t.m.Unlock()

	leafCount := uint64(t.tree.LeafCount())
	if leafCount < treeSize {
		return nil, fmt.Errorf("no such treeSize (%d): current tree size is %d", treeSize, leafCount)
	}

	return t.tree.PathToRootAtSnapshot(int64(leafIndex+1), int64(treeSize)), nil
}

// GetAuditProof returns a proof of containment for the specified index,
// for the given tree size.
func (t *merkleTree) GetAuditProof(treeSize, leafIndex uint64) ([][]byte, error) {
	raw, err := t.getRawProof(treeSize, leafIndex)
	if err != nil {
		return nil, err
	}

	proof := make([][]byte, len(raw))
	for i := range proof {
		proof[i] = raw[i].Value.Hash()
	}
	return proof, nil
}

// addLeaf adds a leaf with the specified data
func (t *merkleTree) addLeaf(leafData []byte) {
	t.m.Lock()
	defer t.m.Unlock()
	t.tree.AddLeaf(leafData)
}

// GetConsistencyProof returns a consistency proof
// between two trees identified by their sizes.
func (t *merkleTree) GetConsistencyProof(firstSize, secondSize uint64) [][]byte {
	raw := func() []merkle.TreeEntryDescriptor {
		t.m.Lock()
		defer t.m.Unlock()
		return t.tree.SnapshotConsistency(int64(firstSize), int64(secondSize))
	}()

	proof := make([][]byte, len(raw))
	for i := range proof {
		proof[i] = raw[i].Value.Hash()
	}
	return proof
}
