package main

import "fmt"

// glowy::label::{secret}
const secret = 1

func main() {
	for index := range [...]int{secret, 2} {
		// glowy::assert::{}
		fmt.Println(index)
	}
}
