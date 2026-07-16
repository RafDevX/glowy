package main

import "fmt"

type State struct {
	background int
	foreground int
}

func main() {
	// glowy::label::{high}
	const secret = 7

	var cond bool
	var state State

	if cond {
		state = State{background: secret, foreground: 0}
	} else {
		state = State{background: 0, foreground: 0}
	}

	state.foreground = 1

	// glowy::assert::{high}
	fmt.Println(state.background)

	// glowy::assert::{}
	fmt.Println(state.foreground)
}
