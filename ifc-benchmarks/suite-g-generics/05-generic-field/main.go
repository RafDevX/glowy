package main

import "fmt"

type Box[T any] struct {
	value T
}

func main() {
	// glowy::label::{secret}
	const secret = "hidden"

	box := Box[string]{value: secret}

	// glowy::assert::{secret}
	fmt.Println(box.value)
}
