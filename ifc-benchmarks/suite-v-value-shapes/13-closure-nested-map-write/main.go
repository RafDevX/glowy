package main

import "fmt"

func main() {
	// glowy::label::{high}
	const secret = 42

	outer := map[int]map[int]int{}
	outer[0] = map[int]int{}

	writeInner := func() {
		outer[0][1] = secret
	}

	writeInner()

	// glowy::assert::{high}
	fmt.Println(outer[0][1])
}
