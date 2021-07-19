package mapstore

import "errors"

// ErrDeleteNotSupported is the error returned when Interface.Delete is not implemented.
var ErrDeleteNotSupported = errors.New("mapstore.Interface: ms.Delete not implemented")

// ErrCannotSetPlaceholder is the error returned when Interface.Set is called with the placeholder key.
var ErrCannotSetPlaceholder = errors.New("mapstore.Interface: ms.Set: cannot set the value of the placeholder ([]byte{0,0,0...})")

// ErrSkipBranch is returned by NodeHandler to indicate that children of the current node do not need to be traversed.
// This error will be ignored if returned by LeafHandler.
var ErrSkipBranch = errors.New("<ErrSkipBranch>")

// NodeHandler is used in TraverseNodes.
type NodeHandler func(hash, left, right []byte) error

// LeafHandler is used in TraverseNodes.
type LeafHandler func(leafPath, hash, valueHash []byte) error

// Base is a simplified MapStore.
// It implements lazyledger/smt.MapStore and can be converted into a
// dt-compatible MapStore with Wrap().
// Base.Delete does not need to be implemented (it may return ErrDeleteNotImplemented).
type Base interface {
	Get(key []byte) ([]byte, error)
	Set(key, value []byte) error
	Delete(key []byte) error
	Size() int

	ProcessKeys(keys []KeyInfo) error
}

// Interface is the interface implemented by all dt-compatible MapStores.
// It is an extension of Base.
type Interface interface {
	Get(key []byte) ([]byte, error)
	Set(key, value []byte) error
	Delete(key []byte) error
	Size() int

	HashSize() int
	Placeholder() []byte
	TraverseNodes(root []byte, nodeFn NodeHandler, leafFn LeafHandler) error
	SaveNodesForRoot(root []byte) error
}
