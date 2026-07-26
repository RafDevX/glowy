package main

import "fmt"

// glowy::label::{red}
var message = "internal"

var _ = message
var _ = len(message)

func main() {
	var message = message

	// glowy::assert::{red}
	fmt.Println(message)
}
