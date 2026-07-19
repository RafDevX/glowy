package main

import "fmt"

type Inner struct {
	prefix string
}

func (i Inner) Mark(msg string) string {
	return i.prefix + ": " + msg
}

type Outer struct {
	inner Inner
}

func main() {
	// glowy::label::{high}
	const secret = "secret"

	// glowy::label::{private}
	const tag = "tag"

	outer := Outer{inner: Inner{prefix: tag}}

	marked := outer.inner.Mark(secret)

	// glowy::assert::{high, private}
	fmt.Println(marked)
}
