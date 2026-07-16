package main

import "fmt"

type Box[T any] struct {
	value T
}

func wrap[T any](v T) T {
	return v
}

func main() {
	// glowy::label::{secret}
	tainted := Box[int]{value: 1}

	out := wrap[Box[int]](tainted)

	// glowy::assert::{secret}
	fmt.Println(out)
}
