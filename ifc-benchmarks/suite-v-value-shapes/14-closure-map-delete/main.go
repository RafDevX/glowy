package main

import "fmt"

func main() {
	// glowy::label::{high}
	const secret = 7

	cache := map[int]int{2: secret}

	closure := func() {
		delete(cache, 2)
	}

	closure()

	// glowy::assert::{}
	fmt.Println(cache[2])
}
