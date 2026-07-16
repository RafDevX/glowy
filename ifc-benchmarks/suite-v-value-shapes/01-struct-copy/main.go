package main

import "fmt"

// glowy::label::{high}
const secret = 7

type Pair struct {
	left  int
	right int
}

func main() {
	var original = Pair{left: 1, right: 1}

	var copied = original
	copied.left = secret

	// glowy::assert::{}
	fmt.Println(original.left)

	// glowy::assert::{high}
	fmt.Println(copied.left)
}
