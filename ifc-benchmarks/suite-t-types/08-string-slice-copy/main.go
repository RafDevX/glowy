package main

import "fmt"

func main() {
	// glowy::label::{secret}
	const secret = "🪐 Mars"

	bytes := []byte(secret)
	byteCopy := []byte(secret)

	runes := []rune(secret)
	runeCopy := []rune(secret)

	bytes[0] = 'x'
	runes[1] = 'y'

	// glowy::assert::{secret}
	fmt.Println(secret, byteCopy[0], runeCopy[1], bytes[1], runes[0])

	// glowy::assert::{}
	fmt.Println(bytes[0], runes[1])
}
