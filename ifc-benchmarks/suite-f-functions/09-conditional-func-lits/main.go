package main

import "fmt"

// glowy::label::{secret}
var secret = 3

// glowy::label::{high}
var high = 4

func main() {
	emit := func() {
		// glowy::assert::{secret, high}
		fmt.Println(0)
	}

	if secret > 0 {
		emit = func() {
			// glowy::assert::{secret, high}
			fmt.Println(1)
		}
	}

	if high > 0 {
		emit()
	}
}
