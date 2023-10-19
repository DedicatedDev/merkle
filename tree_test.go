package merkle

import "testing"

func TestNewMerkleTree(t *testing.T) {
	data := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
	}

	tree := NewMerkleTree(data)
	if tree == nil {
		t.Fatal("Failed to create new Merkle tree")
	}

	if len(tree.Leaves) != 3 {
		t.Fatalf("Expected 3 leaves, got %d", len(tree.Leaves))
	}
}

func TestAddLeaf(t *testing.T) {
	data := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
	}

	tree := NewMerkleTree(data)
	if tree == nil {
		t.Fatal("Failed to create new Merkle tree")
	}

	// Initial checks
	if len(tree.Leaves) != 2 {
		t.Fatalf("Expected 2 leaves, got %d", len(tree.Leaves))
	}

	// Add a new leaf
	tree.AddLeaf([]byte("data3"))
	if len(tree.Leaves) != 3 {
		t.Fatalf("Expected 3 leaves after adding one, got %d", len(tree.Leaves))
	}

	// Check the root hash to ensure tree integrity
	rootHashBefore := tree.Root.Hash
	tree.AddLeaf([]byte("data4"))
	rootHashAfter := tree.Root.Hash

	if rootHashBefore == rootHashAfter {
		t.Fatal("Root hash didn't change after adding a new leaf")
	}
}

func TestComputeHash(t *testing.T) {
	data := []byte("test")
	hash := ComputeHashAsString(data)
	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

	if hash != expected {
		t.Fatalf("Expected %s, got %s", expected, hash)
	}
}

func TestBuildTree(t *testing.T) {
	data := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
		[]byte("data4"),
	}

	nodes := make([]*MerkleNode, len(data))
	for i, datum := range data {
		nodes[i] = NewMerkleNode(nil, nil, datum)
	}

	root := buildTree(nodes)
	if root == nil {
		t.Fatal("Failed to build the tree")
	}
}
