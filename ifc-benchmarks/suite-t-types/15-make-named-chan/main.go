package main

import "fmt"

type Stream chan string

func main() {
	// glowy::label::{secret}
	const tag = "hidden"

	ch := make(Stream, 1)
	ch <- tag
	close(ch)

	for item := range ch {
		// glowy::assert::{secret}
		fmt.Println(item)
	}
}
