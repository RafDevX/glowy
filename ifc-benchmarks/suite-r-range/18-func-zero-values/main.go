package main

import "fmt"

func main() {
	x := false

	for range iter0 {
		x = true
	}

	// glowy::assert::{iter0}
	fmt.Println(x)
}

func iter0(yield func() bool) {
	// glowy::label::{iter0}
	var high = true

	if high {
		yield()
	}
}
