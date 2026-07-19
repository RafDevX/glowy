package installer

import "blank-import/registry"

// glowy::label::{private}
const secret = "hidden"

var Registered = register()

func register() bool {
	registry.Value = secret

	return true
}
