package main

import "fmt"

// glowy::label::{secret}
const secret = 42

func main() {
	m := map[int]int{}

	stash := func(v int) {
		m[1] = v
	}

	stash(secret)

	// glowy::assert::{secret}
	fmt.Println(m[1])
}
