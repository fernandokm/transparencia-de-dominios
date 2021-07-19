package mapstore

import (
	"testing"
)

type testCase struct {
	key        string
	prefix     byte
	val1, val2 string
}

func set(t *testing.T, ms Interface, key string, prefix byte, val1, val2 string) {
	val := append([]byte{prefix}, []byte(val1+val2)...)
	if err := ms.Set([]byte(key), val); err != nil {
		t.Errorf("ms.Set: %v\n", err)
		t.FailNow()
	}
}

func get(t *testing.T, ms Interface, key string) (byte, string, string) {
	val, err := ms.Get([]byte(key))
	if err != nil {
		t.Errorf("ms.Get: %v\n", err)
		t.FailNow()
	}
	hashSize := len(val) / 2
	return val[0], string(val[1 : hashSize+1]), string(val[hashSize+1:])
}

func expect(t *testing.T, ok bool, errf string, a ...interface{}) {
	if !ok {
		t.Errorf(errf, a...)
		t.FailNow()
	}
}

func TestBasic(t *testing.T) {
	// Get, set, size
	cases := []testCase{
		{"abcd", nodePrefix, "efgh", "eeri"},
		{"efgh", nodePrefix, "1e04", "r2er"},
		{"eeri", leafPrefix, "1e05", "r3er"},
		{"pift", leafPrefix, "asrg", "4ysa"}, // orphan
		{"1e04", leafPrefix, "tyui", "asdf"},
		{"r2er", leafPrefix, "cvbf", "345h"},
		{"adht", nodePrefix, "asxc", "04ip"}, // orphan
	}

	ms := NewMem(4)
	for i, c := range cases {
		set(t, ms, c.key, c.prefix, c.val1, c.val2)
		size := ms.Size()
		expect(t, size == i+1, "ms.Size: wrong map size: expected %d, got %d", i+1, size)
	}

	for _, c := range cases {
		p, v1, v2 := get(t, ms, c.key)
		expect(t, p == c.prefix && v1 == c.val1 && v2 == c.val2,
			"ms.Get: wrong value: expected (%d, %s, %s), got (%d, %s, %s)", c.prefix, c.val1, c.val2, p, v1, v2)
	}
}

func TestPlaceholder(t *testing.T) {
	ms := NewMem(4)
	if err := ms.Set(ms.Placeholder(), []byte{0, 1, 2, 3, 4, 1, 2, 3, 4}); err != ErrCannotSetPlaceholder {
		t.Errorf("ms.Set: expected ErrCannotSetPlaceholder when trying to setting placeholder, got %v", err)
	}
	if v, err := ms.Get(ms.Placeholder()); err != nil {
		t.Errorf("ms.Get: %v", err)
	} else if len(v) != 0 {
		t.Errorf("ms.Get: got non-empty value for placeholder key: ms.Get(placeholder) == %v", v)
	}
}

func TestTraverseNodes(t *testing.T) {
	cases := []testCase{
		{"abcd", nodePrefix, "efgh", "eeri"},
		{"efgh", nodePrefix, "1e04", "r2er"},
		{"eeri", leafPrefix, "1e05", "r3er"},
		{"pift", leafPrefix, "asrg", "4ysa"}, // orphan
		{"1e04", leafPrefix, "tyui", "asdf"},
		{"r2er", leafPrefix, "cvbf", "345h"},
		{"adht", nodePrefix, "asxc", "04ip"}, // orphan
	}

	ms := NewMem(4)
	for _, c := range cases {
		set(t, ms, c.key, c.prefix, c.val1, c.val2)
	}

	traversalOrder := []testCase{cases[0], cases[1], cases[4], cases[5], cases[2]}
	i := 0

	checkNode := func(prefix byte, hash, val1, val2 []byte) {
		c := traversalOrder[i]
		i++
		expect(t, prefix == c.prefix && string(hash) == c.key && string(val1) == c.val1 && string(val2) == c.val2,
			"ms.TraverseNodes: wrong node: expected (%s : %d, %s, %s), got (%s : %d, %s, %s)",
			c.key, c.prefix, c.val1, c.val2, hash, prefix, val1, val2)
	}

	err := ms.TraverseNodes([]byte("abcd"), func(hash, left, right []byte) error {
		checkNode(nodePrefix, hash, left, right)
		return nil
	}, func(leafPath, hash, valueHash []byte) error {
		checkNode(leafPrefix, hash, leafPath, valueHash)
		return nil
	})

	if err != nil {
		t.Errorf("ms.TraverseNodes: %v", err)
		t.FailNow()
	}
}

func TestSaveNodesForRoot(t *testing.T) {
	cases := []testCase{
		{"abcd", nodePrefix, "efgh", "eeri"},
		{"efgh", nodePrefix, "1e04", "r2er"},
		{"eeri", leafPrefix, "1e05", "r3er"},
		{"pift", leafPrefix, "asrg", "4ysa"}, // orphan
		{"1e04", leafPrefix, "tyui", "asdf"},
		{"r2er", leafPrefix, "cvbf", "345h"},
		{"adht", nodePrefix, "asxc", "04ip"}, // orphan
	}

	ms := NewMem(4)
	for i := range cases {
		c := cases[len(cases)-i-1] // reverse to ensure root is added last (ms.SaveNodesForRoot prunes until the root)
		set(t, ms, c.key, c.prefix, c.val1, c.val2)
	}

	err := ms.SaveNodesForRoot([]byte(cases[0].key))
	if err != nil {
		t.Errorf("ms.SaveNodesForRoot: %v", err)
		t.FailNow()
	}

	orphans := map[int]struct{}{
		3: {},
		6: {},
	}
	for i, c := range cases {
		_, err := ms.Get([]byte(c.key))
		_, isOrphan := orphans[i]
		if isOrphan && err == nil {
			t.Errorf("ms.SaveNodesForRoot: found orphan node %q after pruning", c.key)
		} else if !isOrphan && err != nil {
			t.Errorf("ms.SaveNodesForRoot: did not find rooted node %q after pruning", c.key)
		}
	}
}
