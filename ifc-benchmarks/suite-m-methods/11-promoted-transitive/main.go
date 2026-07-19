package main

import "fmt"

// glowy::label::{private}
const tag = "wrapped"

type Inner struct{}

func (Inner) Wrap(msg string) string {
	return tag + ": {" + msg + "}"
}

type Mid struct {
	Inner
}

type Outer struct {
	Mid
}

func main() {
	var outer Outer

	// glowy::label::{high}
	const secret = "hidden"

	wrapped := outer.Wrap(secret)

	// glowy::assert::{high, private}
	fmt.Println(wrapped)
}
