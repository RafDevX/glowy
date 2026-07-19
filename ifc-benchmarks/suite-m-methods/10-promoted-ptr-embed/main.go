package main

import "fmt"

// glowy::label::{private}
const tag = "wrapped"

type Inner struct{}

func (Inner) Wrap(msg string) string {
	return tag + ": <" + msg + ">"
}

type Outer struct {
	*Inner
}

func main() {
	outer := Outer{Inner: &Inner{}}

	// glowy::label::{high}
	const secret = "hidden"

	wrapped := outer.Wrap(secret)

	// glowy::assert::{high, private}
	fmt.Println(wrapped)
}
