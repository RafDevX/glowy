package main

import "fmt"

type S struct {
	A int
	B int
}

// glowy::label::{red}
const red = 1

func main() {
	s := S{}

	mutate := func() {
		s.A = red
	}

	mutate()

	s.B = 7

	// glowy::assert::{red}
	fmt.Println(s.A)

	// glowy::assert::{}
	fmt.Println(s.B)
}
