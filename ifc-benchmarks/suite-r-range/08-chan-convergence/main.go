package main

import "fmt"

// glowy::label::{secret}
const secret = 5

func main() {
	ch := make(chan int, 1)

	ch <- 0

	ret := 0
	f := func() int { return ret }
	g := func() int { return f() }
	h := func() int { return g() }

	for x := range ch {
		if x == 0 {
			ret = secret
			ch <- h()
		} else {
			// glowy::assert::{secret}
			fmt.Println(x)
			close(ch)
		}
	}

}
