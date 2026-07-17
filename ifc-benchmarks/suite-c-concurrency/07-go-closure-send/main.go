package main

import "fmt"

// glowy::label::{initial}
const initial = 0

// glowy::label::{secret}
const secret = 1

func main() {
	value := initial
	ch := make(chan int, 1)
	send := func() {
		ch <- value
	}

	value = secret
	go send()
	received := <-ch

	// glowy::assert::{secret}
	fmt.Println(received)
}
