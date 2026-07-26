package main

import "fmt"

// glowy::label::{secret}
const secret = true

var published int

func publish() {
	if secret {
		return
	}

	published = 1
}

func main() {
	publish()

	// glowy::assert::{secret}
	fmt.Println(published)
}
