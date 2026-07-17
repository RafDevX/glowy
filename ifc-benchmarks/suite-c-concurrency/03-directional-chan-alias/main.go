package main

import "fmt"

// glowy::label::{secret}
const secret = 42

func main() {
	ch := make(chan int, 1)
	var sendOnly chan<- int = ch
	var receiveOnly <-chan int = ch

	sendOnly <- secret
	v := <-receiveOnly

	// glowy::assert::{secret}
	fmt.Println(v)
}
