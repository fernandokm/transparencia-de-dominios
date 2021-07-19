package util

import (
	"encoding/base64"
	"fmt"

	"github.com/fernandokm/transparencia-de-dominios/mapstore"
	"github.com/goccy/go-graphviz"
	"github.com/goccy/go-graphviz/cgraph"
	"github.com/lazyledger/smt"
)

// A TraversableMapStore is a map store which can be traversed.
type TraversableMapStore interface {
	smt.MapStore
	TraverseNodes(root []byte, nodeFn mapstore.NodeHandler, leafFn mapstore.LeafHandler) error
}

// DrawTree draws a graphviz tree starting at the given root.
func DrawTree(ms TraversableMapStore, root []byte, options DrawTreeOptions) (*graphviz.Graphviz, *cgraph.Graph, error) {
	g := graphviz.New()
	graph, err := g.Graph()
	if err != nil {
		return nil, nil, err
	}

	td := &treeDrawer{
		g:         g,
		graph:     graph,
		nodeStack: make([]*cgraph.Node, 0),
		ms:        ms,
		options:   options,
	}

	err = ms.TraverseNodes(root, td.processNode, td.processLeaf)
	if err != nil {
		return nil, nil, err
	}
	return g, graph, nil
}

// DrawTreeOptions is used to specify options to DrawTree
type DrawTreeOptions struct {
	MaxHashLength     int
	FormatHashesAsHex bool
	ValueFormatter    func(leafPath, leafHash, valueHash, value []byte) string
}

type treeDrawer struct {
	g         *graphviz.Graphviz
	graph     *cgraph.Graph
	nodeStack []*cgraph.Node
	ms        TraversableMapStore
	options   DrawTreeOptions
}

func (td *treeDrawer) hash2str(hash []byte) string {
	var s string
	if td.options.FormatHashesAsHex {
		s = fmt.Sprintf("%X", hash)
	} else {
		s = base64.StdEncoding.EncodeToString(hash)
	}
	if td.options.MaxHashLength > 0 && len(s) > td.options.MaxHashLength {
		return s[:td.options.MaxHashLength]
	}
	return s
}

func (td *treeDrawer) popNode() (*cgraph.Node, string) {
	n := td.nodeStack[len(td.nodeStack)-1]
	td.nodeStack = td.nodeStack[:len(td.nodeStack)-1]
	if len(td.nodeStack) > 0 && n == td.nodeStack[len(td.nodeStack)-1] {
		return n, "L"
	}
	return n, "R"
}

func (td *treeDrawer) processNode(hash, left, right []byte) error {
	node, err := td.graph.CreateNode(RandomBase64String(30))
	if err != nil {
		return err
	}
	node.SetLabel(td.hash2str(hash))

	if len(td.nodeStack) == 0 { // root
		node.SetLabel("ROOT\n" + td.hash2str(hash))
	} else { //not root
		parent, edgeName := td.popNode()
		edge, err := td.graph.CreateEdge("e", parent, node)
		if err != nil {
			return err
		}
		edge.SetLabel(edgeName)
	}

	td.nodeStack = append(td.nodeStack, node, node)

	return nil
}

func (td *treeDrawer) processLeaf(leafPath, leafHash, valueHash []byte) error {
	var value []byte
	var err error
	if len(valueHash) == 0 {
		value = []byte("{Placeholder}")
	} else if value, err = td.ms.Get(valueHash); err != nil {
		return err
	}

	leaf, err := td.graph.CreateNode(RandomBase64String(30))
	if err != nil {
		return err
	}

	leaf.SetShape(cgraph.RectangleShape)
	if len(valueHash) == 0 {
		leaf.SetLabel(td.hash2str(leafHash) + "\n(placeholder)")
	} else {
		label := td.hash2str(leafHash) + "\nvalHash=" + td.hash2str(valueHash)
		if td.options.ValueFormatter == nil {
			label += fmt.Sprintf("\nvalue=%q", value)
		} else {
			label += "\n" + td.options.ValueFormatter(leafPath, leafHash, valueHash, value)
		}
		leaf.SetLabel(label)
		leaf.SetColor("red")
		leaf.SetFontColor("red")
	}

	if len(td.nodeStack) == 0 {
		return nil // Tree has a single node
	}

	parent, edgeName := td.popNode()
	edge, err := td.graph.CreateEdge(RandomBase64String(30), parent, leaf)
	if err != nil {
		return err
	}
	edge.SetLabel(edgeName)

	return nil
}
