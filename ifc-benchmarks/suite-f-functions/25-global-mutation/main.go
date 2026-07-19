package main

import "fmt"

var argumentValue int
var conditionalCall int
var neverWritten int

func storeArgument(value int) {
	argumentValue = value
}

func storeConditionally() {
	conditionalCall = 0
}

func relayArgument(value int) {
	storeArgument(value)
}

func relayConditionalCall() {
	storeConditionally()
}

func NeverCalled(value int) {
	neverWritten = value
}

func main() {
	// glowy::label::{high}
	var high = 1

	relayArgument(high)

	// glowy::assert::{high}
	fmt.Println(argumentValue)

	if high > 0 {
		relayConditionalCall()
	}

	// glowy::assert::{high}
	fmt.Println(conditionalCall)

	// glowy::assert::{}
	fmt.Println(neverWritten)
}
