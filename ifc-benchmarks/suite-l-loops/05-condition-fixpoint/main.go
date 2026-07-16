package main

import "fmt"

func main() {
	// glowy::label::{confidential}
	conf := 5

	ret := 3
	f := func() int { return ret }
	g := func() int { return f() }
	h := func() int { return g() }

	k := 0
	for k < h() {
		// glowy::assert::{confidential}
		fmt.Println(0)

		ret = conf
		k += 1
	}

	// glowy::assert::{confidential}
	var _ = k
}
