package main

import "fmt"

type Inner struct {
	Token string `glowy:"high"`
}

type Outer struct {
	Inner
}

func main() {
	var outer Outer

	token := outer.Token

	// glowy::assert::{high}
	fmt.Println(token)
}
