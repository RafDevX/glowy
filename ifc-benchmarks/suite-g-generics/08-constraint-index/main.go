package main

import "fmt"

func first[S ~[]E, E any](values S) E {
	return values[0]
}

func main() {
	// glowy::label::{secret}
	const secret = "hidden"

	value := first[[]string, string]([]string{secret})

	// glowy::assert::{secret}
	fmt.Println(value)
}
