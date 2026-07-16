package main

import "fmt"

type Events map[int]any

func main() {
	// glowy::label::{high}
	const secret = "topsecret"

	events := make(Events)
	events[1] = secret

	// glowy::assert::{high}
	fmt.Println(events[1])

	// glowy::assert::{}
	fmt.Println(events[2])
}
