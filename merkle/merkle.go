package merkle

// HashFn represents a generic hash function type
// This is like a intterface for a hash function that take a []byte and return a []byte
// In merkle tree you can depend on this generic HashFn and this can be passed as a parameter to the MerkleTree implementation
type HashFn func(data []byte) []byte

// MerkleTree defines the core interface
//
// Notes:
// - Merkle proofs do NOT include the root hash. The verifier must already have the expected root.
// - A Merkle proof is a min number of hashes needed to recompute the root from a given leaf.
// - Root verification  = recompute the path from the leaf using the proof and comparing it to the expected root.

type MerkleTree interface {
	// AddLeaf adds a new data element to the Merkle tree as a leaf node
	AddLeaf(data []byte) error

	// Root returns the Merkle root hash representing the entire tree
	Root() []byte

	// GenerateProof generates a Merkle proof for the leaf at the given index
	// The proof consists of sibling hashes needed to compute the root.
	GenerateProof(index int) ([][]byte, error)

	// VerifyProof verifies a Merkle proof for a given leaf and index against the provided root hash
	// Recomputes the root from the leaf and proof, and compares it with the provided root.
	VerifyProof(leaf []byte, index int, proof [][]byte, root []byte) bool
}
