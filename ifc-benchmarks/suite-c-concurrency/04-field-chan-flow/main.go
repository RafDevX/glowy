package main

import "fmt"

type Mailbox struct {
	values chan int
}

// glowy::label::{secret}
const secret = 42

func main() {
	mailbox := Mailbox{values: make(chan int, 1)}

	mailbox.values <- secret

	v := <-mailbox.values

	// glowy::assert::{secret}
	fmt.Println(v)
}
