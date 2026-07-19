package main

var active chan int
var privateMessages chan int

func selectPrivate() int {
	active = privateMessages

	return 0
}

func selected() chan int { return active }

func main() {
	// glowy::label::{red}
	redMessage := 1
	// glowy::label::{blue}
	blueMessage := 2

	publicMessages := make(chan int, 1)
	privateMessages = make(chan int, 1)

	publicMessages <- redMessage
	privateMessages <- blueMessage

	active = publicMessages

	_, received := selectPrivate(), <-selected()

	// glowy::assert::{blue}
	var _ = received
}
