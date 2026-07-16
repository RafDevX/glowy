package main

import "fmt"

func keep[T any](xs T) T {
	return xs
}

func main() {
	// glowy::label::{secret}
	tainted := []string{"private"}

	out := keep[[]string](tainted)

	// glowy::assert::{secret}
	fmt.Println(out)
}
