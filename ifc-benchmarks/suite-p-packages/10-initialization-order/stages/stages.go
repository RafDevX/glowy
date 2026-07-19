package stages

import "initialization-order/origin"

var imported = origin.Published
var staged string
var Result string

func init() {
	staged = imported
}

func init() {
	Result = staged
}
