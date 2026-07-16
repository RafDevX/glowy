package main

import (
	"fmt"

	"cross-pkg-method/sub"
)

func main() {
	var formatter = sub.New()

	// glowy::label::{high}
	const secret = "hidden"

	wrapped := formatter.Wrap(secret)

	// glowy::assert::{high, private}
	fmt.Println(wrapped)
}
