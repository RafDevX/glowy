package main

import "fmt"

type Token struct{ value string }

func (t Token) Reveal() string { return t.value }

type Revealer interface {
	Reveal() string
}

func reveal[T Revealer](value T) string { return value.Reveal() }

func main() {
	// glowy::label::{secret}
	const secret = "hidden"

	result := reveal[Token](Token{value: secret})

	// glowy::assert::{secret}
	fmt.Println(result)
}
