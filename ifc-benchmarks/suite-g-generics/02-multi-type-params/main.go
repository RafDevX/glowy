package main

import "fmt"

func keyOf[K any, V any](key K, value V) K {
	return key
}

func main() {
	// glowy::label::{secret}
	tainted := "secret"

	// glowy::label::{high}
	other := 2

	out := keyOf[string, int](tainted, other)

	// glowy::assert::{secret}
	fmt.Println(out)
}
