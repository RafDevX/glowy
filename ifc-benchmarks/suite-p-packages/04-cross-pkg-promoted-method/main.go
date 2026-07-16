package main

import (
	"fmt"

	"cross-pkg-promoted-method/upper"
)

func main() {
	var server = upper.New()

	// glowy::label::{high}
	const secret = "hidden"

	annotated := server.Annotate(secret)

	// glowy::assert::{high, private}
	fmt.Println(annotated)
}
