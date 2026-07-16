package main

import "fmt"

// glowy::label::{secret}
const secret = 1

func main() {
	ch := make(chan int, 1)

	go func() { ch <- secret }()

	v := <-ch

	// glowy::assert::{secret}
	fmt.Println(v)
}
