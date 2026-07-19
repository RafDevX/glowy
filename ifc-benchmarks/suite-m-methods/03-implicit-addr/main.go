package main

import "fmt"

type Box struct{ value string }

func (b *Box) Read() string { return b.value }

func main() {
	// glowy::label::{secret}
	const secret = "hidden"

	box := Box{value: secret}
	result := box.Read()

	// glowy::assert::{secret}
	fmt.Println(result)
}
