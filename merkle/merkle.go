package merkle

import "errors"

// HashFn represents a generic hash function type
// This is like a intterface for a hash function that take a []byte and return a []byte
// In merkle tree you can depend on this generic HashFn and this can be passed as a parameter to the MerkleTree implementation
type HashFn func(data []byte) []byte

type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Hash  []byte
}

type DefaultMerkleTree struct {
	hashFn HashFn
	leaves [][]byte
	root   *MerkleNode
}

func NewDefaultMerkleTree(hashFn HashFn) *DefaultMerkleTree {
	return &DefaultMerkleTree{
		hashFn: hashFn,
	}
}

// AddLeaf adds a new data element to the Merkle tree as a leaf node
func (t *DefaultMerkleTree) AddLeaf(data []byte) error {
	t.leaves = append(t.leaves, data)
	t.buildTree()
	return nil
}

// Root returns the Merkle root hash representing the entire tree
func (t *DefaultMerkleTree) Root() []byte {
	if t.root == nil {
		return nil
	}
	return t.root.Hash
}

// MerkleTree defines the core interface
//
// Notes:
// - Merkle proofs do NOT include the root hash. The verifier must already have the expected root.
// - A Merkle proof is a min number of hashes needed to recompute the root from a given leaf.
// - Root verification  = recompute the path from the leaf using the proof and comparing it to the expected root.
func (t *DefaultMerkleTree) buildTree() {
	var nodes []*MerkleNode
	for _, data := range t.leaves {
		hashed := t.hashFn(data)
		nodes = append(nodes, &MerkleNode{Hash: hashed})
	}

	if len(nodes) == 0 {
		t.root = nil
		return
	}

	for len(nodes) > 1 {
		var level []*MerkleNode

		if len(nodes)%2 != 0 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}

		for i := 0; i < len(nodes); i += 2 {
			combined := append(nodes[i].Hash, nodes[i+1].Hash...)
			parentHash := t.hashFn(combined)
			parent := &MerkleNode{
				Left:  nodes[i],
				Right: nodes[i+1],
				Hash:  parentHash,
			}
			level = append(level, parent)
		}

		nodes = level
	}

	t.root = nodes[0]
}

// GenerateProof generates a Merkle proof for the leaf at the given index
// The proof consists of sibling hashes needed to compute the root.
func (t *DefaultMerkleTree) GenerateProof(index int) ([][]byte, error) {
	if index < 0 || index >= len(t.leaves) {
		return nil, errors.New("index out of bounds")
	}

	var proof [][]byte
	numLeaves := len(t.leaves)

	var level []*MerkleNode
	for _, data := range t.leaves {
		level = append(level, &MerkleNode{Hash: t.hashFn(data)})
	}

	for numLeaves > 1 {
		if len(level)%2 != 0 {
			level = append(level, level[len(level)-1])
		}

		siblingIndex := index ^ 1
		proof = append(proof, level[siblingIndex].Hash)

		var nextLevel []*MerkleNode
		for i := 0; i < len(level); i += 2 {
			combined := append(level[i].Hash, level[i+1].Hash...)
			parent := &MerkleNode{
				Hash: t.hashFn(combined),
			}
			nextLevel = append(nextLevel, parent)
		}

		level = nextLevel
		numLeaves = len(level)
		index = index / 2
	}

	return proof, nil
}

// VerifyProof verifies a Merkle proof for a given leaf and index against the provided root hash
// Recomputes the root from the leaf and proof, and compares it with the provided root.
func (t *DefaultMerkleTree) VerifyProof(leaf []byte, index int, proof [][]byte, root []byte) bool {
	hash := t.hashFn(leaf)

	for _, sibling := range proof {
		var combined []byte
		if index%2 == 0 {
			combined = append(hash, sibling...)
		} else {
			combined = append(sibling, hash...)
		}
		hash = t.hashFn(combined)
		index = index / 2
	}

	return string(hash) == string(root)
}
