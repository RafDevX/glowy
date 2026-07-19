package main

import "fmt"

type Cache struct {
	values map[string]int
}

func (c *Cache) drop(key string) {
	delete(c.values, key)
}

func main() {
	// glowy::label::{high}
	const secret = 1

	c := &Cache{values: map[string]int{"red": secret, "blue": 2}}

	c.drop("red")

	// glowy::assert::{}
	fmt.Println(c.values["red"])

	// glowy::assert::{}
	fmt.Println(c.values["blue"])
}
