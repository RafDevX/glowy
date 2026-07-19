package main

import (
	"fmt"

	"initialization-deps/relay"
)

var observed = relay.Delivered

func main() {
	// glowy::assert::{secret}
	fmt.Println(observed)
}
