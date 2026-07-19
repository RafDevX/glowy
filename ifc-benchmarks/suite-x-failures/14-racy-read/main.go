package main

import "fmt"

// glowy::label::{red}
const initial = 0

// glowy::label::{blue}
const updated = 1

func main() {
	shared := initial
	observations := make(chan int)

	go func() {
		observations <- shared
	}()

	shared = updated
	observed := <-observations

	// glowy::assert::{red, blue}
	fmt.Println(observed)
}
