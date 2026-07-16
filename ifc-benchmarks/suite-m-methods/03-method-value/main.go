package main

import "fmt"

type Box struct {
	value string
}

func (b *Box) Get() string {
	return b.value
}

func main() {
	// glowy::label::{high}
	const secret = "secret"

	box := &Box{value: secret}

	f := box.Get
	value := f()

	// glowy::assert::{high}
	fmt.Println(value)
}
