package main

import "fmt"

func source() int {
	return 3
}

func main() {
	x := source() + 1

	// glowy::assert::{high}
	fmt.Println(x)
}
