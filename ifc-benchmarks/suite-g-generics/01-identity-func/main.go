package main

import "fmt"

func Echo[T any](x T) T {
	return x
}

func main() {
	// glowy::label::{secret}
	tainted := "secret"

	out := Echo[string](tainted)

	// glowy::assert::{secret}
	fmt.Println(out)
}
