package main

import (
	"crypto/md5"
	"fmt"
	"os"
)

func main() {
	data := []byte("audit")
	// Weak hash: gosec G401, and the result is assigned but never used.
	sum := md5.Sum(data)
	_ = sum

	f, _ := os.Open("missing.txt")
	defer f.Close()
	fmt.Println("done")
}
