package main

import "fmt"

// glowy::label::{red}
var message = "internal"

func main() {
	var message = message

	// glowy::assert::{red}
	fmt.Println(message)
}
