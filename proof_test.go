package merkle

import (
	"testing"
)

func TestMerkleProof(t *testing.T) {
	// Create a new Merkle Tree from some sample data
	data := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
		[]byte("data4"),
	}
	tree := NewMerkleTree(data)

	// Ensure the tree has been constructed
	if tree.Root == nil {
		t.Error("Merkle Tree root should not be nil")
	}

	// Generate a proof for one of the leaf nodes
	hash := ComputeHashAsString([]byte("data3"))
	proof, ok := tree.GenerateProof(hash)

	if !ok {
		t.Error("Failed to generate Merkle proof")
	}

	// Validate the proof
	if !proof.Validate(tree.Root.Hash) {
		t.Error("Failed to validate Merkle proof")
	}

	// Generate an incorrect proof to ensure validation fails
	wrongProof := Proof{
		Hashes: []string{ComputeHashAsString([]byte("wrongdata"))},
		IsLeft: []bool{true},
		Target: ComputeHashAsString([]byte("data3")),
	}

	if wrongProof.Validate(tree.Root.Hash) {
		t.Error("Merkle proof should not validate with incorrect data")
	}
}

func TestProofValidationWithInvalidRoot(t *testing.T) {
	// Sample data
	data := [][]byte{
		[]byte("block1"),
		[]byte("block2"),
		[]byte("block3"),
		[]byte("block4"),
	}

	// Create a Merkle tree
	tree := NewMerkleTree(data)

	// Generate a proof for the third block
	targetHash := ComputeHashAsString(data[2])
	proof, ok := tree.GenerateProof(targetHash)

	if !ok {
		t.Fatal("Failed to generate the Merkle proof")
	}

	// Create an invalid root hash by slightly modifying the actual root hash
	invalidRootHash := tree.Root.Hash[:len(tree.Root.Hash)-1] + "a"

	// Validate the proof with invalid root hash
	if proof.Validate(invalidRootHash) {
		t.Fatal("Proof validation passed with an invalid root hash")
	}
}

func TestProofGenerationWithInvalidData(t *testing.T) {
	// Sample data
	data := [][]byte{
		[]byte("block1"),
		[]byte("block2"),
		[]byte("block3"),
		[]byte("block4"),
	}

	// Create a Merkle tree
	tree := NewMerkleTree(data)

	// Try to generate a proof for data that's not in the tree
	targetHash := ComputeHashAsString([]byte("invalidBlock"))
	_, ok := tree.GenerateProof(targetHash)

	if ok {
		t.Fatal("Successfully generated a proof for invalid data")
	}
}
