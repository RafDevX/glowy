package main

import "fmt"

type State struct {
	background int
	foreground int
}

func main() {
	// glowy::label::{high}
	const secret = 7

	state := State{}
	p := &state

	(*p).background = secret
	(*p).foreground = 0

	// glowy::assert::{high}
	fmt.Println((*p).background, p.background)

	// glowy::assert::{}
	fmt.Println((*p).foreground)
}
