package main

import (
	"fmt"

	"cross-pkg-var/store"
)

func main() {
	// glowy::label::{high}
	const secret = "hidden"

	store.Value = secret
	store.Save(secret)

	wrapped := store.Value
	loaded := store.Load()

	// glowy::assert::{high}
	fmt.Println(wrapped, loaded)
}
