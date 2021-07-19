package dt

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/fernandokm/transparencia-de-dominios/mapstore"
	"github.com/fernandokm/transparencia-de-dominios/util"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/lazyledger/smt"
)

// Version is the Domain Transparency version
const Version = 1

var emptySMH = SignedMapHead{
	MapHead{
		Version:            Version,
		Timestamp:          0,
		MapSize:            0,
		MapRootHash:        [32]byte{},
		SourceTreeRootHash: [32]byte{},
		SourceLogRevisions: []LogRevision{},
	},
	nil,
}

// A DomainProof proves the (non-)containment of a node.
type DomainProof struct {
	Proof    [][]byte
	LeafHash []byte
}

// LogRevision is used in MapHead to identify a source log revision
type LogRevision struct {
	TreeSize uint64        `json:"tree_size"`
	RootHash ct.SHA256Hash `json:"root_hash"`
}

// MapHead is the structure which is signed to produce the SignedMapHead.
type MapHead struct {
	Version   ct.Version `json:"-" tls:"maxval:255"`
	Timestamp uint64     `json:"timestamp"`
	MapSize   uint64     `json:"map_size"`

	MapRootHash        ct.SHA256Hash `json:"map_root_hash"`
	SourceTreeRootHash ct.SHA256Hash `json:"source_tree_root_hash"`

	SourceLogRevisions []LogRevision `json:"source_log_revisions" tls:"minlen:40,maxlen:16777215"` // 40 = size(LogRevision), 16777215=2^24-1 (419k elements)
}

// An SignedMapHead (SMH) certifies the root of a domain map.
type SignedMapHead struct {
	MapHead
	MapHeadSignature []byte `json:"map_head_signature"`
}

// A DomainMap maps domains to CT certificates.
type DomainMap struct {
	// locked by m
	smhs       map[uint64]*SignedMapHead
	smh        *SignedMapHead
	sparseTree *smt.SparseMerkleTree
	subtrees   map[string]*DomainTree

	// const, internally thread-safe
	sparseStore mapstore.Interface
	sourceTree  *SourceTree
	signer      crypto.Signer

	// mPublishSMH ensures only one call to CheckAndPublishSMH is running at any time.
	// It should only be locked by CheckAndPublishSMH.
	mPublishSMH sync.Mutex
	m           sync.RWMutex
}

// NewDomainMap creates a new DomainMap.
// The domain map starts with unsigned an empty SMH.
func NewDomainMap(signer crypto.Signer) *DomainMap {
	ms := mapstore.NewMem(sha256.Size)
	return &DomainMap{
		smhs:        make(map[uint64]*SignedMapHead),
		smh:         &emptySMH,
		sparseStore: ms,
		sparseTree:  smt.NewSparseMerkleTree(ms, sha256.New()),
		sourceTree:  NewSourceTree(),
		subtrees:    make(map[string]*DomainTree),
		signer:      signer,
	}
}

// PublicKey returns this map's public key.
func (dm *DomainMap) PublicKey() crypto.PublicKey {
	return dm.signer.Public()
}

func (dm *DomainMap) getDomain(root []byte, domain string, failIfEmpty bool) ([]byte, error) {
	normalizedDomain, err := util.NormalizeDomainName(domain)
	if err != nil {
		return nil, err
	}

	dm.m.RLock()
	defer dm.m.RUnlock()
	data, err := dm.sparseTree.GetForRoot([]byte(normalizedDomain), root[:])
	if err != nil {
		panic(fmt.Errorf("unexpected error fetching domain in DomainMap: %v", err))
	}
	if failIfEmpty && len(data) == 0 {
		return nil, fmt.Errorf("no such domain name %q (after normalization: %q)", domain, normalizedDomain)
	}
	return data, nil
}

// CheckAndPublishSMH checks the specified rootand publishes a new SMH.
func (dm *DomainMap) CheckAndPublishSMH(root []byte, mapSize uint64, sourceRevisions []LogRevision) error {
	if len(root) != 32 {
		return fmt.Errorf("invalid map root hash: length=%d, expected 32", len(root))
	}
	for i, rev := range sourceRevisions {
		if len(rev.RootHash) != 32 {
			return fmt.Errorf("invalid source log root hash (log %d): length=%d, expected 32", i, len(rev.RootHash))
		}
	}

	dm.mPublishSMH.Lock()
	defer dm.mPublishSMH.Unlock()
	// Note: to avoid deadlocks, do not call dm.m.Lock() before this point

	currentSMH := dm.GetLatestSMH()
	isRepublish := bytes.Equal(root, currentSMH.MapRootHash[:])

	// Check mapSize
	if isRepublish && mapSize != currentSMH.MapSize {
		return fmt.Errorf("invalid map size for republish: new map size (%d) != current map size (%d)", mapSize, currentSMH.MapSize)
	} else if !isRepublish && mapSize <= currentSMH.MapSize {
		return fmt.Errorf("invalid map size for new map root: new map size (%d) <= current map size (%d)", mapSize, currentSMH.MapSize)
	}
	// Check len(sourceRevisions)
	if isRepublish && len(sourceRevisions) != len(currentSMH.SourceLogRevisions) {
		return fmt.Errorf("invalid source logs for republish: new source log count (%d) != current source log count (%d)", len(sourceRevisions), len(currentSMH.SourceLogRevisions))
	} else if !isRepublish && len(sourceRevisions) < len(currentSMH.SourceLogRevisions) {
		return fmt.Errorf("invalid source logs: new source log count (%d) < current source log count (%d)", len(sourceRevisions), len(currentSMH.SourceLogRevisions))
	}
	// Check sourceRevisions
	for i, currentRev := range currentSMH.SourceLogRevisions {
		newRev := sourceRevisions[i]
		if isRepublish && newRev.TreeSize != currentRev.TreeSize {
			return fmt.Errorf("invalid source log size for republish (log %d): new size (%d) != current size (%d)", i, newRev.TreeSize, currentRev.TreeSize)
		} else if !isRepublish && newRev.TreeSize < currentRev.TreeSize {
			return fmt.Errorf("invalid source log size (log %d): new size (%d) < current size (%d)", i, newRev.TreeSize, currentRev.TreeSize)
		}
	}

	var head MapHead
	if isRepublish {
		head = currentSMH.MapHead
		head.Timestamp = uint64(time.Now().UTC().Unix())
	} else {
		head = MapHead{
			Version:            Version,
			Timestamp:          uint64(time.Now().UTC().Unix()),
			MapSize:            mapSize,
			SourceLogRevisions: make([]LogRevision, len(sourceRevisions)),
		}
		copy(head.SourceLogRevisions, sourceRevisions)
		copy(head.MapRootHash[:], root)

		var sourceRoot []byte
		var err error
		if len(sourceRevisions) == len(currentSMH.SourceLogRevisions) {
			sourceRoot = currentSMH.SourceTreeRootHash[:]
		} else if sourceRoot, err = dm.sourceTree.GetRoot(uint64(len(sourceRevisions))); err != nil {
			return err
		}
		copy(head.SourceTreeRootHash[:], sourceRoot)
	}

	tlsEncodedHead, err := tls.Marshal(head)
	if err != nil {
		return fmt.Errorf("error marshaling MapHead: %w", err)
	}

	sig, err := dm.signer.Sign(rand.New(rand.NewSource(42)), util.HashBytes(tlsEncodedHead), nil)
	if err != nil {
		return fmt.Errorf("error signing MapHead: %w", err)
	}
	smh := &SignedMapHead{head, sig}

	// Delete "orphan" nodes at the last possible moment, to ensure
	// that the MapStore is only modified if the SMH update is successful.
	if !isRepublish {
		if err := dm.sparseStore.SaveNodesForRoot(root); err != nil {
			return err
		}
	}

	dm.m.Lock()
	defer dm.m.Unlock()

	dm.smh = smh
	dm.smhs[smh.MapSize] = smh
	return nil
}

// HasDomain checks if this map has the specified key.
func (dm *DomainMap) HasDomain(root []byte, domain string) (bool, error) {
	data, err := dm.getDomain(root, domain, false)
	if err != nil {
		return false, err
	}
	return len(data) > 0, nil
}

// UpdateDomainTreeRoot updates the DomainTreeRoot for the
// specified domain and returns the new map root.
func (dm *DomainMap) UpdateDomainTreeRoot(root []byte, domain string, treeSize uint64) ([]byte, error) {
	normalizedDomain, err := util.NormalizeDomainName(domain)
	if err != nil {
		return nil, err
	}
	dm.m.RLock()
	dtree, ok := dm.subtrees[normalizedDomain]
	dm.m.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no domain tree for %q (normalized: %q)", domain, normalizedDomain)
	}

	treeRoot, err := dtree.GetRoot(treeSize)
	if err != nil {
		return nil, err
	}

	if oldTreeRoot, err := dm.GetDomainTreeRoot(root, normalizedDomain); err == nil { // Not the first tree root for the domain
		if oldTreeRoot.DomainTreeSize >= treeSize {
			return nil, fmt.Errorf("invalid domain tree root update: cannot go back in time (current size: %d, proposed size: %d)", oldTreeRoot.DomainTreeSize, treeSize)
		}
	}

	value, err := tls.Marshal(*treeRoot)
	if err != nil {
		return nil, err
	}

	dm.m.Lock()
	defer dm.m.Unlock()
	newRoot, err := dm.sparseTree.UpdateForRoot([]byte(normalizedDomain), value, root)
	if err != nil {
		return nil, err
	}
	return newRoot, nil
}

// AddDomainTree adds a new domain tree to this domain map.
// This means only that the tree can be found through dm.GetDomainTree().
// In order to get this domain tree included in the sparse merkle tree,
// call dm.UpdateDomainTreeRoot().
func (dm *DomainMap) AddDomainTree(tree *DomainTree) error {
	normalizedDomain, err := util.NormalizeDomainName(tree.DomainName)
	if err != nil {
		return err
	}
	if normalizedDomain != tree.DomainName {
		return fmt.Errorf("invalid DomainTree: tree.DomainName is not normalized")
	}

	dm.m.Lock()
	defer dm.m.Unlock()
	if _, ok := dm.subtrees[normalizedDomain]; ok {
		return fmt.Errorf("domain tree already exists for %q", tree.DomainName)
	}
	dm.subtrees[normalizedDomain] = tree
	return nil
}

// GetLatestSMH returns the latest SMH, or nil if the tree is empty.
func (dm *DomainMap) GetLatestSMH() *SignedMapHead {
	dm.m.RLock()
	defer dm.m.RUnlock()
	return dm.smh
}

// GetSMH returns the specified SMH, or nil if the specified SMH does not exist.
func (dm *DomainMap) GetSMH(treeSize uint64) *SignedMapHead {
	dm.m.RLock()
	defer dm.m.RUnlock()
	return dm.smhs[treeSize]
}

// GetDomainTreeRoot returns the STH for the specified domain tree at the specified map head,
// after domain name normalization.
func (dm *DomainMap) GetDomainTreeRoot(root []byte, domain string) (*DomainTreeRoot, error) {
	data, err := dm.getDomain(root, domain, false)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		dtr := DomainTreeRoot{DomainTreeSize: 0}
		copy(dtr.DomainTreeRootHash[:], emptyDenseTreeRoot)
		return &dtr, nil
	}

	var tree DomainTreeRoot
	bs, err := tls.Unmarshal(data, &tree)
	if err != nil {
		panic(fmt.Errorf("unexpected error unmarshalling data from map store: %v", err))
	}
	if len(bs) != 0 {
		panic(fmt.Errorf("invalid data in map store: %d bytes leftover after unmarshalling SubtreeRoot", len(bs)))
	}
	return &tree, nil
}

// GetDomainTree returns the domain tree associated with the specified
// domain, after domain name normalization.
func (dm *DomainMap) GetDomainTree(domain string) (*DomainTree, error) {
	normalizedDomain, err := util.NormalizeDomainName(domain)
	if err != nil {
		return nil, err
	}

	dm.m.RLock()
	defer dm.m.RUnlock()
	st, ok := dm.subtrees[normalizedDomain]
	if !ok {
		return nil, fmt.Errorf("no such domain name %q (after normalization: %q)", domain, normalizedDomain)
	}
	return st, nil
}

// GetProofForDomain returns a (non-)containment proof for the specified domain.
func (dm *DomainMap) GetProofForDomain(root []byte, domain string) (DomainProof, error) {
	normalizedDomain, err := util.NormalizeDomainName(domain)
	if err != nil {
		return DomainProof{}, err
	}

	dm.m.RLock()
	defer dm.m.RUnlock()
	proof, err := dm.sparseTree.ProveForRoot([]byte(normalizedDomain), root[:])
	if err != nil {
		return DomainProof{}, err
	}

	leafHash := proof.NonMembershipLeafData
	if leafHash == nil {
		leafHash = dm.sparseStore.Placeholder()
	}

	rev := make([][]byte, len(proof.SideNodes))
	for i := range rev {
		rev[i] = proof.SideNodes[len(rev)-i-1]
	}

	return DomainProof{
		Proof:    rev,
		LeafHash: leafHash,
	}, nil
}

// EntryToDomainTreeIndex returns the index of a DomainTreeEntry in the domain tree
// for the specified domain (after domain name normalization).
//
// Returns an error if the domain tree does not exist or if the specified
// certificate could not be found in the domain tree.
// has no such certificate.
func (dm *DomainMap) EntryToDomainTreeIndex(entry DomainTreeEntry, domain string) (uint64, error) {
	tree, err := dm.GetDomainTree(domain)
	if err != nil {
		return 0, err
	}
	return tree.EntryToDomainTreeIndex(entry)
}

// GetSourceTree returns this map's SourceTree
func (dm *DomainMap) GetSourceTree() *SourceTree {
	return dm.sourceTree
}
