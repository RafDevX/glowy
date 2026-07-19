package main

import "fmt"

// glowy::label::{secret}
const secret = 1

func main() {
	// glowy::label::{delivery}
	hasPayload := true

	sensitive := make(chan int, 1)
	public := make(chan int, 1)

	if hasPayload {
		sensitive <- secret
	}

	close(sensitive)
	public <- 0

	var value int
	var ok bool

	select {
	case value, ok = <-sensitive:
	case value, ok = <-public:
	}

	// glowy::assert::{secret, delivery}
	fmt.Println(value)

	// glowy::assert::{delivery}
	fmt.Println(ok)
}
