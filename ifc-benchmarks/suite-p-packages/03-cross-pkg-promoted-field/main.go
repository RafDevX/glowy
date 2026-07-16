package main

import (
	"fmt"

	"cross-pkg-promoted-field/upper"
)

func main() {
	var server = upper.New()

	token := server.Token

	// glowy::assert::{remote}
	fmt.Println(token)
}
