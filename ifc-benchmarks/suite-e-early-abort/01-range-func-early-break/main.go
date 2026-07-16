package main

import "fmt"

// glowy::label::{private}
var private = false

// glowy::label::{high}
var high = false

func main() {
	x := 0

	for value := range selectedValues {
		x += value

		if private {
			break
		}

		if high {
			break
		}
	}

	// glowy::assert::{alice, bob, secret}
	fmt.Println(x)
}

// glowy::label::{alice}
const alice = 2

// glowy::label::{bob}
const bob = 3

var arr = [...]int{1, alice, bob, 4}

func selectedValues(yield func(int) bool) {
	for _, value := range arr {
		if should(value) {
			if !yield(value) {
				// glowy::assert::{private, high}
				fmt.Println(0)
			}
		}
	}
}

// glowy::label::{secret}
const secret = 2

func should(n int) bool {
	return n%secret == 0
}
