package main

import "fmt"

// glowy::label::{secret}
const secret = 42

func main() {
	// glowy::label::{delivery}
	hasPayload := true
	ch := make(chan int, 1)
	if hasPayload {
		ch <- secret
	}
	close(ch)

	v, ok := <-ch

	// glowy::assert::{secret, delivery}
	fmt.Println(v)
	// glowy::assert::{delivery}
	fmt.Println(ok)
}
