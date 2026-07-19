package main

import "fmt"

// glowy::label::{secret}
const secret = 7

var selectedTarget int

func targetIndex(index int) int {
	selectedTarget = index

	return index
}

func main() {
	// glowy::label::{route}
	useMars := true

	mars := make(chan int, 1)
	venus := make(chan int, 1)

	if useMars {
		mars <- secret
	} else {
		venus <- 0
	}

	values := [2]int{}
	select {
	case values[targetIndex(0)] = <-mars:
	case values[targetIndex(1)] = <-venus:
	}

	// glowy::assert::{route}
	fmt.Println(selectedTarget)

	// glowy::assert::{secret}
	fmt.Println(values[0])

	// glowy::assert::{}
	fmt.Println(values[1])
}
