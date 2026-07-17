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

	// glowy::label::{schedule}
	sendCount := 2
	public := make(chan int, 2)
	for range sendCount {
		public <- 0
	}
	close(public)

	visits := 0
	for range public {
		visits++
	}

	// glowy::assert::{schedule}
	fmt.Println(visits)
}
