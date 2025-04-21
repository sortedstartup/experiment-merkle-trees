package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"sortedstartup/merkletree/merkle"
)

func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func main() {
	tree := merkle.NewDefaultMerkleTree(sha256Hash)

	data := [][]byte{
		[]byte("tx1: Alice pays Bob 10 BTC"),
		[]byte("tx2: Bob pays Charlie 5 BTC"),
		[]byte("tx3: Charlie pays Dave 2 BTC"),
		[]byte("tx4: Dave pays Eve 1 BTC"),
		[]byte("tx5: sanskar pays vishu 1 BTC"),
	}

	for _, d := range data {
		tree.AddLeaf(d)
	}

	root := tree.Root()
	fmt.Printf("Merkle Root: %s\n", hex.EncodeToString(root))

	// Proof for tx3
	index := 2
	proof, _ := tree.GenerateProof(index)
	fmt.Printf("Proof for leaf %d:\n", index)
	for i, p := range proof {
		fmt.Printf("  [%d] %s\n", i, hex.EncodeToString(p))
	}

	valid := tree.VerifyProof(data[index], index, proof, root)
	fmt.Printf("Proof valid? %v\n", valid)
}
