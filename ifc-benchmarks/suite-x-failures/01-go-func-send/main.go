package main

import "fmt"

// glowy::label::{secret}
const secret = 1

func sender(ch chan int) {
	ch <- secret
}

func main() {
	ch := make(chan int, 1)

	go sender(ch)

	x := <-ch

	// glowy::assert::{secret}
	fmt.Println(x)
}
