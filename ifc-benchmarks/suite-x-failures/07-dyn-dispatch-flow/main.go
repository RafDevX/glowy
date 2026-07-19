package main

import "fmt"

// glowy::label::{alice}
const alice = 1

// glowy::label::{bob}
const bob = 2

type source interface{ read() int }
type first struct{}
type second struct{}

func (first) read() int  { return alice }
func (second) read() int { return bob }

func main() {
	var first source = first{}
	var second source = second{}

	// glowy::assert::{alice}
	fmt.Println(first.read())

	// glowy::assert::{bob}
	fmt.Println(second.read())
}
