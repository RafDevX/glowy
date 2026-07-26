package main

import "fmt"

type Tokens []string

func main() {
	// glowy::label::{high}
	const secret = "alpha"

	t := Tokens{secret, "public"}
	t = append(t, "extra")

	// glowy::assert::{high}
	fmt.Println(t[0])

	// glowy::assert::{}
	fmt.Println(t[1:])
}
