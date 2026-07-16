package main

import "fmt"

func main() {
	// glowy::label::{high}
	const secret = 7

	s := make([]int, 3)

	closure := func() {
		s[1] = secret
	}

	closure()

	s[2] = 3

	// glowy::assert::{high}
	fmt.Println(s[1])

	// glowy::assert::{}
	fmt.Println(s[2])
}
