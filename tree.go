package merkle

import (
	"crypto/sha256"
	"encoding/hex"
)

type MerkleNode struct {
	Hash  string
	Left  *MerkleNode
	Right *MerkleNode
}

type MerkleTree struct {
	Root   *MerkleNode
	Leaves []*MerkleNode
}

func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	node := &MerkleNode{
		Left:  left,
		Right: right,
	}

	if left == nil && right == nil {
		node.Hash = ComputeHashAsString(data)
	} else {
		prevHashes := append([]byte(left.Hash), []byte(right.Hash)...)
		node.Hash = ComputeHashAsString(prevHashes)
	}

	return node
}

func NewMerkleTree(data [][]byte) *MerkleTree {
	var leaves []*MerkleNode

	for _, datum := range data {
		node := NewMerkleNode(nil, nil, datum)
		leaves = append(leaves, node)
	}

	root := buildTree(leaves)
	return &MerkleTree{Root: root, Leaves: leaves}
}

func buildTree(nodes []*MerkleNode) *MerkleNode {
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	var nextLevel []*MerkleNode
	for i := 0; i < len(nodes); i += 2 {
		if i+1 < len(nodes) {
			node := NewMerkleNode(nodes[i], nodes[i+1], nil)
			nextLevel = append(nextLevel, node)
		} else {
			nextLevel = append(nextLevel, nodes[i])
		}
	}

	return buildTree(nextLevel)
}

func (mt *MerkleTree) AddLeaf(data []byte) {
	// Create a new leaf node
	newLeaf := NewMerkleNode(nil, nil, data)

	// Add the new leaf to the list of leaves
	mt.Leaves = append(mt.Leaves, newLeaf)

	// Rebuild the tree with the new list of leaves
	mt.Root = buildTree(mt.Leaves)
}

func ComputeHash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func ComputeHashAsString(data []byte) string {
	return hex.EncodeToString(ComputeHash(data))
}
