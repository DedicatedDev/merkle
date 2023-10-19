package merkle

type Proof struct {
	Hashes []string
	IsLeft []bool
	Target string
}

func (t *MerkleTree) GenerateProof(targetHash string) (Proof, bool) {
	var proof Proof
	proof.Target = targetHash

	var buildProof func(node *MerkleNode) bool
	buildProof = func(node *MerkleNode) bool {
		if node == nil {
			return false
		}

		if node.Hash == targetHash {
			return true
		}

		if buildProof(node.Left) {
			proof.IsLeft = append(proof.IsLeft, false)
			proof.Hashes = append(proof.Hashes, node.Right.Hash)
			return true
		}

		if buildProof(node.Right) {
			proof.IsLeft = append(proof.IsLeft, true)
			proof.Hashes = append(proof.Hashes, node.Left.Hash)
			return true
		}

		return false
	}

	return proof, buildProof(t.Root)
}

func (p *Proof) Validate(rootHash string) bool {
	currentHash := p.Target
	for i := 0; i < len(p.Hashes); i++ {
		var combinedHash []byte
		if p.IsLeft[i] {
			combinedHash = append([]byte(p.Hashes[i]), []byte(currentHash)...)
		} else {
			combinedHash = append([]byte(currentHash), []byte(p.Hashes[i])...)
		}
		currentHash = ComputeHashAsString(combinedHash)
	}
	return currentHash == rootHash
}
