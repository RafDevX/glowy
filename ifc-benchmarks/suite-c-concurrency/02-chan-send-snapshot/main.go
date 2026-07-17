package main

import "fmt"

// glowy::label::{alpha}
const alpha = 1

// glowy::label::{beta}
const beta = 2

func main() {
	payload := alpha
	fmt.Println(payload)

	buffered := make(chan int, 1)
	buffered <- payload

	payload = beta
	fmt.Println(payload)

	bufferedValue := <-buffered

	unbuffered := make(chan int)
	done := make(chan struct{})
	go func() {
		value := alpha
		unbuffered <- value

		value = beta
		fmt.Println(value)

		close(done)
	}()
	unbufferedValue := <-unbuffered
	<-done

	// glowy::assert::{alpha}
	fmt.Println(bufferedValue, unbufferedValue)
}
