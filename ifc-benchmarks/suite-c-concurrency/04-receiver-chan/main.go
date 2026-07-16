package main

import "fmt"

// glowy::label::{secret}
const secret = 42

type Container struct {
	values chan int
}

func (c *Container) run() {
	v := <-c.values

	// glowy::assert::{secret}
	fmt.Println(v)
}

func main() {
	c := &Container{values: make(chan int, 1)}

	c.values <- secret

	c.run()
}
