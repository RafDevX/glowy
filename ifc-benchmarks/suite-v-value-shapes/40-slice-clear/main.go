package main

import "fmt"

func main() {
	// glowy::label::{visible}
	visibleSecret := 1
	// glowy::label::{spare}
	spareSecret := 2

	backing := []int{visibleSecret, spareSecret}

	visible := backing[:1]
	alias := visible

	clear(alias)

	recovered := visible[:2][1]

	// glowy::assert::{}
	fmt.Println(backing[0], visible[0], alias[0])

	// glowy::assert::{spare}
	fmt.Println(backing[1], recovered)
}
