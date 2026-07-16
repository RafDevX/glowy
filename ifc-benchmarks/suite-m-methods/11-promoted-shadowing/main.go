package main

import "fmt"

type Inner struct{}

func (Inner) Wrap(msg string) string {
	return "from-inner:" + msg
}

type Outer struct {
	Inner
}

func (Outer) Wrap(_ string) string {
	return "shadow"
}

func main() {
	var outer Outer

	// glowy::label::{high}
	const secret = "hidden"

	wrapped := outer.Wrap(secret)

	// glowy::assert::{}
	fmt.Println(wrapped)
}
