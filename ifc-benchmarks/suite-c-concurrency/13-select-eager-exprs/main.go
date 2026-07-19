package main

import "fmt"

// glowy::label::{red}
const red = 1

// glowy::label::{blue}
const blue = 2

var channelSideEffectExactlyOnce, valueSideEffectExactlyOnce int

func channelExpr(channel chan int) chan int {
	// glowy::assert::{}
	fmt.Println(channelSideEffectExactlyOnce)

	channelSideEffectExactlyOnce = red

	return channel
}

func sendExpr() int {
	// glowy::assert::{red}
	fmt.Println(channelSideEffectExactlyOnce)

	// glowy::assert::{}
	fmt.Println(valueSideEffectExactlyOnce)

	valueSideEffectExactlyOnce = blue

	return 0
}

func main() {
	var blocked chan int

	select {
	case channelExpr(blocked) <- sendExpr():
	default:
	}

	// glowy::assert::{red}
	fmt.Println(channelSideEffectExactlyOnce)

	// glowy::assert::{blue}
	fmt.Println(valueSideEffectExactlyOnce)
}
