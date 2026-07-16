package main

import "fmt"

type Wrapper struct {
	value string
}

func (w *Wrapper) Read() string {
	return w.value
}

func main() {
	// glowy::label::{high}
	const secret = "secret"

	wrapper := &Wrapper{value: secret}

	output := wrapper.Read()

	// glowy::assert::{high}
	fmt.Println(output)
}
