package main

import "fmt"

type Contents struct {
	direct  string
	items   []string
	entries map[string]string
}

func (c Contents) WriteReferences(value string) string {
	c.direct = value
	c.items[0] = value
	c.entries["color"] = value
	return c.direct
}

func (c *Contents) WriteDirect(value string) {
	c.direct = value
}

func main() {
	// glowy::label::{secret}
	const secret = "red"

	// glowy::label::{private}
	const private = "gold"

	contents := Contents{
		items:   []string{""},
		entries: map[string]string{"color": ""},
	}

	copiedDirect := contents.WriteReferences(secret)

	// glowy::assert::{}
	fmt.Println(contents.direct)
	// glowy::assert::{secret}
	fmt.Println(copiedDirect, contents.items[0], contents.entries["color"])

	contents.WriteDirect(private)

	// glowy::assert::{private}
	fmt.Println(contents.direct)
}
