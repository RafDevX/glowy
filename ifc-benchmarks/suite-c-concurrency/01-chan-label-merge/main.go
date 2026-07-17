package main

import "fmt"

// glowy::label::{alpha}
const alpha = 1

// glowy::label::{beta}
const beta = 2

func main() {
	ch := make(chan int, 2)
	go func() {
		ch <- alpha
	}()
	go func() {
		ch <- beta
	}()

	v := <-ch

	// glowy::assert::{alpha, beta}
	fmt.Println(v)
}
