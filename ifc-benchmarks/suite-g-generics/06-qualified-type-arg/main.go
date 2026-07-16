package main

import (
	"bytes"
	"fmt"
)

func Hold[T any](v T) T {
	return v
}

func main() {
	// glowy::label::{secret}
	tainted := bytes.Buffer{}

	out := Hold[bytes.Buffer](tainted)

	// glowy::assert::{secret}
	fmt.Println(out)
}
