package main

import "fmt"

// glowy::label::{secret}
const secret = 1

func makePair() (chan int, chan int) {
	ch := make(chan int, 1)
	alias := ch

	// These descriptors alias each other, while descriptors returned by a
	// different call must refer to a fresh channel.
	return ch, alias
}

func main() {
	ch, alias := makePair()
	ch <- secret

	value := <-alias

	// glowy::assert::{secret}
	fmt.Println(value)

	other, otherAlias := makePair()
	other <- 0

	otherValue := <-otherAlias

	// glowy::assert::{}
	fmt.Println(otherValue)
}
