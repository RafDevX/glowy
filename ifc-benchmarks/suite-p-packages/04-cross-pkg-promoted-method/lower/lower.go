package lower

// glowy::label::{private}
const tag = "wrapped"

type Base struct{}

func (Base) Annotate(msg string) string {
	return tag + ": <<" + msg + ">>"
}
