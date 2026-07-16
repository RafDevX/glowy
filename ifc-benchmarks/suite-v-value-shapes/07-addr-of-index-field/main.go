package main

import "fmt"

type Span struct {
	offsets [2]int
}

func main() {
	// glowy::label::{high}
	const secret = 7

	spans := []Span{{}, {}}

	(&spans[1]).offsets[1] = secret

	// glowy::assert::{high}
	fmt.Println(spans[1].offsets[1])

	// glowy::assert::{}
	fmt.Println(spans[0].offsets[0], spans[1].offsets[0])
}
