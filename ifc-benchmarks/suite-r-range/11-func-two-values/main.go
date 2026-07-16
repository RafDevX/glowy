package main

import "fmt"

func main() {
	x := 0

	for k, v := range iter2 {
		// glowy::assert::{alice, bob, secret}
		fmt.Println(k)

		x += v
	}

	// glowy::assert::{alice, bob, secret}
	fmt.Println(x)
}

// glowy::label::{alice}
const alice = 2

// glowy::label::{bob}
const bob = 3

var m = map[string]int{"one": 1, "two": alice, "three": bob, "four": 4}

func iter2(yield func(string, int) bool) {
	for k, v := range m {
		if should(v) {
			yield(k, v)
		}
	}
}

// glowy::label::{secret}
const secret = 2

func should(n int) bool {
	return n%secret == 0
}
