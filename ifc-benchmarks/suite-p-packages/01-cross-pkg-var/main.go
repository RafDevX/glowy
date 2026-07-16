package main

import (
	"fmt"

	"cross-pkg-var/store"
)

func main() {
	// glowy::label::{high}
	const secret = "hidden"

	store.Value = secret

	wrapped := store.Value

	// glowy::assert::{high}
	fmt.Println(wrapped)
}
