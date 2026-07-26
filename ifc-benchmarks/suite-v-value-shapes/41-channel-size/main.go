package main

import "fmt"

func main() {
	// glowy::label::{channel-capacity}
	capacity := 1
	messages := make(chan string, capacity)

	// glowy::label::{occupancy}
	enqueue := true

	if enqueue {
		messages <- "public"
	}

	// glowy::assert::{occupancy}
	fmt.Println(len(messages))
	// glowy::assert::{channel-capacity}
	fmt.Println(cap(messages))
}
