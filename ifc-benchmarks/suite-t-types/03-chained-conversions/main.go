package main

import "fmt"

type A int
type B int

func main() {
	// glowy::label::{high}
	const secret = 42

	x := int(B(A(secret)))

	// glowy::assert::{high}
	fmt.Println(x)
}
