package main

import "fmt"

// glowy::label::{private}
const private = 0

type Tokens []string

func main() {
	// glowy::label::{high}
	const secret = "alpha"

	s := make(Tokens, private)
	s = append(s, secret)

	// glowy::assert::{high}
	fmt.Println(s[0])
}
