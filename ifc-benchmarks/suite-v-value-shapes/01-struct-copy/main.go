package main

import "fmt"

// glowy::label::{high}
const secret = 7

type Pair struct {
	left  int
	right int
}

func copyArray(values [2]int) [2]int {
	values[1] = secret

	return values
}

func main() {
	var original = Pair{left: 1, right: 1}

	var copied = original
	copied.left = secret

	// glowy::assert::{}
	fmt.Println(original.left)

	// glowy::assert::{high}
	fmt.Println(copied.left)

	arrayOriginal := [2]int{secret, 0}
	arrayAssigned := arrayOriginal
	assignedLabel := arrayAssigned[0]
	arrayAssigned[0] = 0

	arrayReturned := copyArray(arrayOriginal)
	returnedLabel := arrayReturned[0]
	arrayReturned[0] = 0

	// glowy::assert::{high}
	fmt.Println(arrayOriginal[0], assignedLabel, returnedLabel, arrayReturned[1])
	// glowy::assert::{}
	fmt.Println(arrayAssigned[0], arrayOriginal[1], arrayReturned[0])
}
