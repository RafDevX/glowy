package main

import "fmt"

// glowy::label::{secret}
var secret = 3

func main() {
	if secret > 0 {
		first()
	}
}

func first() {
	second()
}

func second() {
	observe()
}

func observe() {
	// glowy::assert::{secret}
	fmt.Println(0)
}
