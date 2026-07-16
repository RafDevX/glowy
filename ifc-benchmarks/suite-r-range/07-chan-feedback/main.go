package main

import "fmt"

// glowy::label::{secret}
const secret = 5

func main() {
	ch := make(chan int, 10)

	ch <- 0

	for x := range ch {
		if x == 0 {
			ch <- secret
		} else {
			// glowy::assert::{secret}
			fmt.Println(x)
			close(ch)
		}
	}
}
