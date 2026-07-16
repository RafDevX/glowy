package main

import "fmt"

func main() {
	// glowy::label::{high}
	const secret = 7

	cache := map[int]int{}

	closure := func() {
		cache[2] = secret
		delete(cache, 2)
	}

	closure()

	// glowy::assert::{}
	fmt.Println(cache[2])
}
