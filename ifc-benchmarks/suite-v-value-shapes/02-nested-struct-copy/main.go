package main

import "fmt"

func main() {
	// glowy::label::{high}
	var original = struct{ inner struct{ value int } }{
		inner: struct{ value int }{value: 7},
	}

	var copied = original
	copied.inner.value = 0

	// glowy::assert::{high}
	fmt.Println(original.inner.value)

	// glowy::assert::{}
	fmt.Println(copied.inner.value)
}
