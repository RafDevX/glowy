package main

import "fmt"

// glowy::label::{secret}
const secret = "hidden"

func main() {
	ch := make(chan string, 1)
	ch <- secret
	close(ch)

	for item := range ch {
		// glowy::assert::{secret}
		fmt.Println(item)
	}
}
