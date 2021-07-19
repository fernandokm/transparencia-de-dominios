package util

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/fernandokm/transparencia-de-dominios/mapstore"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
)

type merkleMapStore struct {
	nodes       [][]*merkle.TreeEntry
	leaves      []uint64
	hashToValue map[string][]byte
}

func (ms *merkleMapStore) Get(key []byte) ([]byte, error) {
	v, ok := ms.hashToValue[string(key)]
	if !ok {
		return nil, fmt.Errorf("non existent/not supported key")
	}
	return v, nil
}

func (ms *merkleMapStore) Set(key []byte, value []byte) error {
	return fmt.Errorf("not supported")
}

func (ms *merkleMapStore) Delete(key []byte) error {
	return fmt.Errorf("not supported")
}

func (ms *merkleMapStore) TraverseNodes(root []byte, nodeFn mapstore.NodeHandler, leafFn mapstore.LeafHandler) error {
	if !bytes.Equal(ms.nodes[0][0].Hash(), root) {
		return fmt.Errorf("not supported: root must be the actual tree root")
	}
	return ms.traverseNodes(0, 0, nodeFn, leafFn)
}

func (ms *merkleMapStore) traverseNodes(i, j int, nodeFn mapstore.NodeHandler, leafFn mapstore.LeafHandler) error {
	if i == len(ms.nodes)-1 || ms.nodes[i+1][2*j] == nil { // leaf (last layer or no children)
		var leafPath, value [8]byte
		binary.BigEndian.PutUint64(leafPath[:], uint64(j))
		binary.BigEndian.PutUint64(value[:], ms.leaves[j])
		return leafFn(leafPath[:], ms.nodes[i][j].Hash(), HashBytes(value[:]))
	}
	// node
	ri := i + 1
	rj := 2*j + 1
	for ms.nodes[ri][rj] == nil {
		ri++
		rj *= 2
	}
	nodeFn(ms.nodes[i][j].Hash(), ms.nodes[i+1][2*j].Hash(), ms.nodes[ri][rj].Hash())
	if err := ms.traverseNodes(i+1, 2*j, nodeFn, leafFn); err != nil {
		return err
	}
	if err := ms.traverseNodes(ri, rj, nodeFn, leafFn); err != nil {
		return err
	}

	return nil
}

// MapStoreFromLeaves creates a traversable map store from a slice of leaves.
// This MapStore is extremely limited an supports only traversal
// and Get(n) of leaf values.
//
// Returns the map store and the root node
func MapStoreFromLeaves(leaves []uint64) (TraversableMapStore, []byte) {
	tree := merkle.NewInMemoryMerkleTree(rfc6962.DefaultHasher)
	for _, leaf := range leaves {
		var leafData [8]byte
		binary.BigEndian.PutUint64(leafData[:], leaf)
		tree.AddLeaf(leafData[:])
	}

	nodes := make([][]*merkle.TreeEntry, tree.LevelCount())
	size := 1
	for i := range nodes {
		nodes[i] = make([]*merkle.TreeEntry, size)
		size *= 2
	}

	hashToValue := make(map[string][]byte)
	for leafIndex := range leaves {
		var val [8]byte
		binary.BigEndian.PutUint64(val[:], leaves[leafIndex])
		hashToValue[string(HashBytes(val[:]))] = val[:]

		proof := tree.PathToCurrentRoot(int64(leafIndex) + 1)
		path, err := merkle.CalcInclusionProofNodeAddresses(int64(len(leaves)), int64(leafIndex), int64(len(leaves)))
		if err != nil {
			panic(err)
		}
		for k, entry := range proof {
			e := entry
			id := path[k].ID
			nodes[uint(len(nodes))-id.Level-1][id.Index] = &e.Value
		}
	}
	root := tree.CurrentRoot()
	nodes[0][0] = &root

	return &merkleMapStore{nodes, leaves, hashToValue}, nodes[0][0].Hash()
}
