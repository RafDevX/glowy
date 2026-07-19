package main

import "fmt"

type Inner struct {
	Token string `glowy:"high"`
}

type Mid struct {
	Inner
}

type Outer struct {
	Mid
}

func main() {
	var outer Outer

	token := outer.Token

	// glowy::assert::{high}
	fmt.Println(token)
}
