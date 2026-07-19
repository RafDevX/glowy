package main

import "fmt"

func main() {
	// glowy::label::{red}
	secretRed := 1
	// glowy::label::{blue}
	secretBlue := 2
	// glowy::label::{green}
	secretGreen := 3

	redValues := []int{secretRed}
	blueValues := []int{secretBlue}

	selected := redValues

	var chooseBlue = true
	if chooseBlue {
		selected = blueValues
	}

	selected[0] = secretGreen

	// glowy::assert::{red, green}
	fmt.Println(redValues[0])

	// glowy::assert::{blue, green}
	fmt.Println(blueValues[0])
}
