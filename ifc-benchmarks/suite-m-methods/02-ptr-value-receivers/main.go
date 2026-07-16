package main

import "fmt"

type Counter struct {
	value string
}

func (c *Counter) Label() string {
	return c.value
}

type Tag struct {
	value string
}

func (t Tag) Label() string {
	return t.value
}

func main() {
	// glowy::label::{secret}
	const secret = "red"

	// glowy::label::{private}
	const private = "gold"

	c := &Counter{value: secret}
	t := Tag{value: private}

	counter := c.Label()
	tag := t.Label()

	// glowy::assert::{secret}
	fmt.Println(counter)

	// glowy::assert::{private}
	fmt.Println(tag)
}
