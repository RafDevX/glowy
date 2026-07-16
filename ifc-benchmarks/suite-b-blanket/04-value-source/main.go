package main

import "fmt"

var Global int

type Box struct{ Value int }

func main() {
	box := Box{}

	// glowy::assert::{global}
	fmt.Println(Global)

	// glowy::assert::{field}
	fmt.Println(box.Value)
}
