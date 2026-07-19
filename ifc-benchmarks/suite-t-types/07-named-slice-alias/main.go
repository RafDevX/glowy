package main

import "fmt"

type Tokens []string

func main() {
	raw := []string{"public"}
	converted := Tokens(raw)

	// glowy::label::{secret}
	const secret = "hidden"
	converted[0] = secret

	// glowy::assert::{secret}
	fmt.Println(raw[0])
}
